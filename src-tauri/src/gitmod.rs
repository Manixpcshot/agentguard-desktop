//! Git integration built on `git2` (vendored libgit2).
//!
//! AgentGuard is strictly read-only with respect to the user's repository: this
//! module never writes, stages, commits or checks out anything. It only reads
//! refs, status and diffs.

use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::util;
use git2::{BranchType, Delta, DiffFlags, DiffOptions, FileMode, Repository, Sort, StatusOptions};
use std::path::Path;

/// Opens the repository that contains `path` (searching parent directories).
pub fn open(path: &str) -> AppResult<Repository> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(AppError::User(format!("path does not exist: {path}")));
    }
    Repository::discover(p).map_err(|e| AppError::NotARepo(format!("{path}: {e}")))
}

fn norm(p: Option<&Path>) -> Option<String> {
    p.map(|x| x.to_string_lossy().replace('\\', "/"))
}

/// Snapshot of repository metadata for the project picker.
pub fn repo_info(repo: &Repository, fallback_path: &str) -> RepoInfo {
    let workdir = repo
        .workdir()
        .map(|w| {
            w.to_string_lossy()
                .trim_end_matches(['\\', '/'])
                .to_string()
        })
        .unwrap_or_else(|| fallback_path.to_string());

    let mut info = RepoInfo {
        path: workdir,
        is_repo: true,
        branch: None,
        head_sha: None,
        head_subject: None,
        commit_count: 0,
        dirty_files: 0,
        untracked_files: 0,
        branches: Vec::new(),
        remotes: Vec::new(),
        error: None,
    };

    match repo.head() {
        Ok(head) => {
            info.branch = head.shorthand().ok().map(|s| s.to_string());
            if let Ok(commit) = head.peel_to_commit() {
                info.head_sha = Some(commit.id().to_string());
                info.head_subject = commit.summary().ok().flatten().map(|s| s.to_string());
            }
        }
        Err(e) => info.error = Some(format!("no HEAD yet: {e}")),
    }

    if let Ok(mut walk) = repo.revwalk() {
        if walk.push_head().is_ok() {
            let _ = walk.set_sorting(Sort::TIME);
            info.commit_count = walk.take(5000).count() as u32;
        }
    }

    let mut sopts = StatusOptions::new();
    sopts.include_untracked(true).recurse_untracked_dirs(true);
    if let Ok(statuses) = repo.statuses(Some(&mut sopts)) {
        for entry in statuses.iter() {
            let s = entry.status();
            if s.contains(git2::Status::WT_NEW) || s.contains(git2::Status::INDEX_NEW) {
                info.untracked_files += 1;
            } else {
                info.dirty_files += 1;
            }
        }
    }

    if let Ok(branches) = repo.branches(None) {
        for item in branches.flatten() {
            let (branch, kind) = item;
            if let Ok(Some(name)) = branch.name() {
                info.branches.push(BranchInfo {
                    name: name.to_string(),
                    is_head: branch.is_head(),
                    is_remote: kind == BranchType::Remote,
                });
            }
        }
    }

    if let Ok(remotes) = repo.remotes() {
        info.remotes = remotes.iter().filter_map(|r| r.ok().map(|s| s.to_string())).collect();
    }

    info
}

/// Recent commits on a ref (or HEAD).
pub fn list_commits(repo: &Repository, refname: Option<&str>, limit: usize) -> AppResult<Vec<CommitInfo>> {
    let mut walk = repo.revwalk()?;
    match refname {
        Some(r) => {
            let obj = repo.revparse_single(r)?;
            walk.push(obj.id())?;
        }
        None => walk.push_head()?,
    }
    walk.set_sorting(Sort::TIME)?;
    let mut out = Vec::new();
    for oid in walk.take(limit) {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let sha = oid.to_string();
        let short = sha.chars().take(8).collect::<String>();
        out.push(CommitInfo {
            sha,
            short_sha: short,
            subject: commit.summary().ok().flatten().unwrap_or_default().to_string(),
            author: commit.author().name().unwrap_or_default().to_string(),
            timestamp: commit.author().when().seconds(),
        });
    }
    Ok(out)
}

/// Builds the list of changed files (with unified-diff hunks) for a scan base.
pub fn build_changes(
    repo: &Repository,
    base: &ScanBase,
    include_untracked: bool,
    context_lines: u32,
    max_file_bytes: u64,
    pathspec: Option<&str>,
) -> AppResult<Vec<FileChange>> {
    let mut opts = DiffOptions::new();
    opts.context_lines(context_lines);
    opts.interhunk_lines(0);
    if include_untracked {
        opts.include_untracked(true);
        opts.recurse_untracked_dirs(true);
        opts.show_untracked_content(true);
    }
    if let Some(p) = pathspec {
        opts.pathspec(p);
    }

    let diff = match base {
        ScanBase::WorkingTree => match repo.head() {
            Ok(head) => {
                let tree = head.peel_to_tree()?;
                repo.diff_tree_to_workdir_with_index(Some(&tree), Some(&mut opts))?
            }
            // Unborn branch: everything in the workdir is new.
            Err(_) => repo.diff_tree_to_workdir_with_index(None, Some(&mut opts))?,
        },
        ScanBase::Staged => {
            // index vs HEAD tree (unborn HEAD -> everything staged is new)
            let head_tree = repo.head().ok().and_then(|h| h.peel_to_tree().ok());
            repo.diff_tree_to_index(head_tree.as_ref(), None, Some(&mut opts))?
        }
        ScanBase::Branch(b) => {
            let head_oid = repo
                .head()?
                .target()
                .ok_or_else(|| AppError::User("repository has no HEAD commit".into()))?;
            let branch_obj = repo.revparse_single(b).map_err(|e| {
                AppError::User(format!("cannot resolve branch {b:?}: {e}"))
            })?;
            let base_oid = repo
                .merge_base(head_oid, branch_obj.id())
                .unwrap_or(branch_obj.id());
            let tree = repo.find_commit(base_oid)?.tree()?;
            repo.diff_tree_to_workdir_with_index(Some(&tree), Some(&mut opts))?
        }
        ScanBase::Commit(c) => {
            let commit = repo
                .revparse_single(c)
                .map_err(|e| AppError::User(format!("cannot resolve commit {c:?}: {e}")))?
                .peel_to_commit()?;
            let new_tree = commit.tree()?;
            let old_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());
            repo.diff_tree_to_tree(old_tree.as_ref(), Some(&new_tree), Some(&mut opts))?
        }
        ScanBase::Range { from, to } => {
            let a = repo
                .revparse_single(from)
                .map_err(|e| AppError::User(format!("cannot resolve {from:?}: {e}")))?
                .peel_to_tree()?;
            let b = repo
                .revparse_single(to)
                .map_err(|e| AppError::User(format!("cannot resolve {to:?}: {e}")))?
                .peel_to_tree()?;
            repo.diff_tree_to_tree(Some(&a), Some(&b), Some(&mut opts))?
        }
        ScanBase::LastCommits(n) => {
            let head = repo.head()?.peel_to_commit()?;
            let mut cursor = head;
            for _ in 0..*n {
                match cursor.parent(0) {
                    Ok(parent) => cursor = parent,
                    Err(_) => break,
                }
            }
            let tree = cursor.tree()?;
            repo.diff_tree_to_workdir_with_index(Some(&tree), Some(&mut opts))?
        }
    };

    collect_changes(&diff, max_file_bytes)
}

fn collect_changes(diff: &git2::Diff<'_>, max_file_bytes: u64) -> AppResult<Vec<FileChange>> {
    let deltas: Vec<git2::DiffDelta<'_>> = diff.deltas().collect();
    let mut out = Vec::with_capacity(deltas.len());

    for (idx, delta) in deltas.iter().enumerate() {
        let status = match delta.status() {
            Delta::Added => ChangeStatus::Added,
            Delta::Untracked => ChangeStatus::Untracked,
            Delta::Deleted => ChangeStatus::Deleted,
            Delta::Modified => ChangeStatus::Modified,
            Delta::Renamed => ChangeStatus::Renamed,
            Delta::Copied => ChangeStatus::Copied,
            _ => ChangeStatus::Typechange,
        };
        let new_path = norm(delta.new_file().path());
        let old_path = norm(delta.old_file().path());
        let path = new_path.clone().or_else(|| old_path.clone()).unwrap_or_default();
        if path.is_empty() {
            continue;
        }
        let is_binary = delta.flags().contains(DiffFlags::BINARY);
        let too_large = delta.new_file().size() > max_file_bytes;
        let old_exec = delta.old_file().mode() == FileMode::BlobExecutable;
        let new_exec = delta.new_file().mode() == FileMode::BlobExecutable;

        let mut hunks: Vec<DiffHunk> = Vec::new();
        let mut additions = 0u32;
        let mut deletions = 0u32;

        if !is_binary && !too_large {
            if let Ok(Some(patch)) = git2::Patch::from_diff(diff, idx) {
                let hunk_count = patch.num_hunks();
                for h in 0..hunk_count {
                    let (hunk, hunk_lines) = match patch.hunk(h) {
                        Ok(x) => x,
                        Err(_) => continue,
                    };
                    let header = String::from_utf8_lossy(hunk.header()).trim_end().to_string();
                    let mut lines: Vec<DiffLine> = Vec::new();
                    let line_count = patch.num_lines_in_hunk(h).unwrap_or(hunk_lines);
                    for l in 0..line_count {
                        let line = match patch.line_in_hunk(h, l) {
                            Ok(x) => x,
                            Err(_) => continue,
                        };
                        let kind = match line.origin() {
                            '+' => {
                                additions += 1;
                                LineKind::Added
                            }
                            '-' => {
                                deletions += 1;
                                LineKind::Removed
                            }
                            _ => LineKind::Context,
                        };
                        lines.push(DiffLine {
                            kind,
                            old_no: line.old_lineno(),
                            new_no: line.new_lineno(),
                            text: util::clean_line(&String::from_utf8_lossy(line.content())),
                        });
                    }
                    if !lines.is_empty() {
                        hunks.push(DiffHunk { header, lines });
                    }
                }
            }
        } else {
            // For binary/too-large files still surface +/- counts via the delta.
            additions = 0;
            deletions = 0;
        }

        out.push(FileChange {
            path,
            old_path: if old_path != new_path { old_path } else { None },
            status,
            is_binary,
            too_large,
            additions,
            deletions,
            old_exec,
            new_exec,
            hunks,
        });
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Content of the file as it exists in the working directory (lossy UTF-8).
pub fn read_workdir_file(repo: &Repository, rel: &str) -> Option<String> {
    let workdir = repo.workdir()?;
    let full = workdir.join(rel);
    let bytes = std::fs::read(full).ok()?;
    if util::is_likely_binary(&bytes) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Content of the file before the change (from the old blob), for deletions.
pub fn read_old_content(repo: &Repository, fc: &FileChange) -> Option<String> {
    // Deleted files: locate the blob via revparse of HEAD version.
    let spec = format!("HEAD:{}", fc.old_path.as_deref().unwrap_or(&fc.path));
    let obj = repo.revparse_single(&spec).ok()?;
    let blob = obj.peel_to_blob().ok()?;
    let bytes = blob.content();
    if util::is_likely_binary(bytes) {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}
