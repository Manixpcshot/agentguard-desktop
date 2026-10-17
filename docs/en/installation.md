# Installation (Windows)

> فارسی: [docs/fa/installation.md](../fa/installation.md)

## Requirements

| Component | Requirement |
|---|---|
| OS | Windows 10 (1809+) / Windows 11, x64 |
| WebView2 | Preinstalled on Windows 11; on Windows 10 the installer fetches it if missing |
| Git | Any recent Git for Windows (AgentGuard reads repositories through libgit2; Git is only needed for repos that use features libgit2 delegates) |
| Disk | ~60 MB installed |
| Network | Not required after installation |

## Option 1 — NSIS installer (recommended)

1. Download `AgentGuard_<version>_x64-setup.exe` from the
   [Releases page](https://github.com/Manixpcshot/agentguard-desktop/releases/latest).
2. Run it. Per-user installation needs no admin rights; choose “for all users”
   if you want a machine-wide install (asks for elevation).
3. Launch **AgentGuard** from the Start menu.

Silent install:

```powershell
AgentGuard_0.1.0_x64-setup.exe /S
```

## Option 2 — MSI package

For group-policy / SCCM deployments:

```powershell
msiexec /i AgentGuard_0.1.0_x64_en-US.msi /qn
```

## Option 3 — Portable executable

`AgentGuard-portable.exe` runs without installation. Settings, history and
reports metadata are stored per user in:

```
%APPDATA%\dev.agentguard.desktop\
```

## Verifying a release

Every release is built by GitHub Actions from a tagged commit; the workflow
log shows the exact source revision. Compare the version shown in
*About* inside the app with the release tag.

## Updating

Download the new installer and run it — it upgrades in place. Your settings
and scan history are preserved in the data directory above.

## Uninstalling

- Settings → Apps → AgentGuard → Uninstall, or
- `Add/Remove Programs` → AgentGuard.

To also erase local history and settings, delete `%APPDATA%\dev.agentguard.desktop`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| “WebView2 not found” | Install the [Evergreen runtime](https://developer.microsoft.com/microsoft-edge/webview2/) |
| Folder picker shows nothing | The folder must be inside a Git repository for scanning; any folder can be opened |
| SmartScreen warning | The release binaries are not code-signed yet; choose “More info → Run anyway”. Signed builds are on the roadmap |
| Ollama not detected | Start Ollama (`ollama serve`) and confirm `http://127.0.0.1:11434` responds |
