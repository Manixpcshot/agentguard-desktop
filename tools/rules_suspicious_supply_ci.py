"""Suspicious-change, supply-chain and CI/CD hardening rules."""

from rules_lib import rule

CODE_INCLUDE = (
    "**/*.py", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.mjs", "**/*.cjs",
    "**/*.go", "**/*.rs", "**/*.java", "**/*.kt", "**/*.rb", "**/*.php", "**/*.cs",
)

# ------------------------------------------------------------- suspicious ---

rule(
    "SUS-OBFUSCATED-ENCODED-BLOB",
    "suspicious", "suspicious_change", "high", confidence=0.75,
    heuristic="encoded_blob",
    cwe=("CWE-506",), tags=("obfuscation", "heuristic"),
    title=("Long encoded/obfuscated blob added", "بلاب بلند رمزگذاری‌شده/مبهم افزوده شده است"),
    description=("An added line contains a very long base64/hex run. Legitimate code rarely embeds "
                 "such blobs; payloads and exfiltration tooling often do.",
                 "سطری افزوده‌شده شامل دنباله بسیار بلند base64/hex است. کد مشروع به‌ندرت چنین بلاب‌هایی "
                 "جاسازی می‌کند؛ بارهای مخرب اغلب چنین می‌کنند."),
    remediation=("Decode and inspect the blob; require a documented reason for embedding it.",
                 "بلاب را رمزگشایی و بازرسی کنید و دلیل مستند برای جاسازی آن الزام کنید."),
)

rule(
    "SUS-MINIFIED-LINE",
    "suspicious", "suspicious_change", "medium", confidence=0.6,
    heuristic="minified_line",
    cwe=("CWE-506",), tags=("obfuscation", "heuristic"),
    title=("Minified single-line code added", "کد فشرده تک‌سطری افزوده شده است"),
    description=("A very long, dense single line was added to a source file. Minified code cannot be "
                 "reviewed line by line.",
                 "سطری بسیار بلند و متراکم به فایل سورس افزوده شده است. کد فشرده قابل بازبینی سطر به سطر نیست."),
    remediation=("Add readable source instead; keep bundles out of review diffs.",
                 "سورس خوانا اضافه کنید؛ بسته‌های بیلد را بیرون از diff بازبینی نگه دارید."),
)

rule(
    "SUS-ZERO-WIDTH-CHARACTERS",
    "suspicious", "suspicious_change", "critical", confidence=0.95,
    heuristic="zero_width_chars",
    cwe=("CWE-506",), tags=("steganography", "trojan-source", "heuristic"),
    title=("Invisible zero-width characters in code", "نویسه‌های نامرئی با پهنای صفر در کد"),
    description=("Zero-width / bidi-control characters (U+200B–U+200F, U+2060–U+2064, U+FEFF, U+202A–"
                 "U+202E) can hide code from reviewers (Trojan Source attacks).",
                 "نویسه‌های با پهنای صفر / کنترل جهت متن (U+200B تا U+200F، U+2060 تا U+2064، U+FEFF، "
                 "U+202A تا U+202E) می‌توانند کد را از بازبین پنهان کنند (حمله Trojan Source)."),
    remediation=("Strip the invisible characters and re-review the affected lines carefully.",
                 "نویسه‌های نامرئی را حذف و سطرهای متأثر را با دقت بازبینی کنید."),
)

rule(
    "SUS-HOMOGLYPH-IDENTIFIER",
    "suspicious", "suspicious_change", "high", confidence=0.8,
    heuristic="homoglyph_identifier",
    cwe=("CWE-1007",), tags=("trojan-source", "heuristic"),
    title=("Mixed-script (look-alike) identifier", "شناسه با ترکیب الفباهای هم‌شکل"),
    description=("An identifier mixes Latin with look-alike Cyrillic/Greek characters, which can "
                 "shadow or impersonate real variables.",
                 "شناسه‌ای حروف لاتین را با حروف هم‌شکل سیریلیک/یونانی ترکیب می‌کند و می‌تواند متغیرهای واقعی را "
                 "جعل یا سایه کند."),
    remediation=("Replace with pure ASCII identifiers; add a linter rule (ruff RUF001-3, ESLint unicode).",
                 "با شناسه‌های ASCII خالص جایگزین کنید و قانون لینتر اضافه کنید (ruff RUF001-3، ESLint unicode)."),
)

rule(
    "SUS-MASS-DELETION",
    "suspicious", "suspicious_change", "medium", confidence=0.7,
    heuristic="mass_deletion",
    cwe=("CWE-77",), tags=("destructive", "heuristic"),
    title=("Mass deletion of code in one file", "حذف انبوه کد در یک فایل"),
    description=("The change removes a very large number of lines from a single file with little or no "
                 "replacement, which can silently delete security checks.",
                 "تغییر تعداد بسیار زیادی سطر را از یک فایل با جایگزین کم یا بدون جایگزین حذف می‌کند و "
                 "می‌تواند بررسی‌های امنیتی را بی‌صدا حذف کند."),
    remediation=("Confirm the deleted code (validation, auth, tests) is intentionally retired.",
                 "تأیید کنید کد حذف‌شده (اعتبارسنجی، احراز هویت، تست‌ها) عمدی بازنشسته شده است."),
)

rule(
    "SUS-BINARY-FILE-ADDED",
    "suspicious", "suspicious_change", "medium", confidence=0.8,
    heuristic="binary_added",
    cwe=("CWE-506",), tags=("binary", "heuristic"),
    title=("Binary/executable file added", "فایل باینری/اجرایی افزوده شده است"),
    description=("An executable, archive or other binary blob was added to the repository. Binaries "
                 "cannot be audited in a diff.",
                 "فایل اجرایی، آرشیو یا بلاب باینری دیگر به مخزن افزوده شده است. باینری‌ها در diff قابل "
                 "ممیزی نیستند."),
    remediation=("Verify provenance and checksum; prefer build-time fetch of pinned artifacts.",
                 "خاستگاه و checksum را راستی‌آزمایی کنید؛ دریافت زمان بیلد آثار ثابت‌شده را ترجیح دهید."),
)

rule(
    "SUS-GITIGNORE-TAMPER",
    "suspicious", "suspicious_change", "high", confidence=0.8,
    heuristic="gitignore_tamper",
    cwe=("CWE-562",), tags=("git", "evasion", "heuristic"),
    title=(".gitignore modified to hide or expose sensitive files",
           ".gitignore برای پنهان‌کردن یا آشکارسازی فایل‌های حساس تغییر کرده است"),
    description=("Sensitive-file patterns were removed from .gitignore (so secrets get committed) or "
                 "negation rules were added to force-commit ignored files.",
                 "الگوهای فایل حساس از .gitignore حذف شده‌اند (تا رازها کامیت شوند) یا قواعد نفی اضافه شده "
                 "تا فایل‌های ignore‌شده به‌زور کامیت شوند."),
    remediation=("Review every .gitignore line in the diff; keep secret patterns ignored.",
                 "هر سطر .gitignore در diff را بازبینی کنید و الگوهای راز را ignore نگه دارید."),
)

rule(
    "SUS-HOOKS-OR-GUARDS-REMOVED",
    "suspicious", "suspicious_change", "high", confidence=0.8,
    heuristic="guards_removed",
    cwe=("CWE-693",), tags=("hooks", "evasion", "heuristic"),
    title=("Quality/security guards removed (hooks, pre-commit, lint config)",
           "محافظ‌های کیفیت/امنیت حذف شده‌اند (هوک‌ها، pre-commit، پیکربندی لینت)"),
    description=("Pre-commit configuration, husky hooks, lint/security tool configs or secret-scanning "
                 "rules were deleted or disabled.",
                 "پیکربندی pre-commit، هوک‌های husky، پیکربندی ابزارهای لینت/امنیت یا قوانین اسکن راز حذف یا "
                 "غیرفعال شده‌اند."),
    remediation=("Restore the guards; fix findings instead of deleting the tooling.",
                 "محافظ‌ها را بازگردانید و به‌جای حذف ابزار، یافته‌ها را برطرف کنید."),
)

rule(
    "SUS-SECURITY-LINT-DISABLE",
    "suspicious", "suspicious_change", "medium", confidence=0.7,
    patterns=[
        r"//\s*eslint-disable(?:-next-line|-line)?\s*$",
        r"//\s*eslint-disable(?:-next-line|-line)?\s+[^\n]*(?:no-eval|no-new-func|no-implied-eval|security)",
        r"#\s*nosec\b", r"//\s*nolint\b", r"#\s*type:\s*ignore\b",
        r"@SuppressWarnings\s*\(\s*[\"'][^\"']*(?:security|all)",
        r"(?i)bandit:\s*skip", r"#\s*pragma:\s*no cover",
    ],
    include=CODE_INCLUDE + ("**/*.py",),
    cwe=("CWE-693",), tags=("lint", "evasion"),
    title=("Static-analysis suppression added", "سرکوب تحلیل ایستا افزوده شده است"),
    description=("A lint/secret/security suppression comment silences a tool exactly where it would "
                 "have complained.",
                 "کامنت سرکوب لینت/راز/امنیت دقیقاً جایی ابزار را خاموش می‌کند که قرار بود هشدار دهد."),
    remediation=("Fix the underlying issue; if suppression is unavoidable, add a justification comment.",
                 "مشکل ریشه‌ای را برطرف کنید؛ اگر سرکوب ناگزیر است، کامنت توجیه اضافه کنید."),
)

rule(
    "SUS-AUTH-FILE-ADDED",
    "suspicious", "suspicious_change", "high", confidence=0.85,
    heuristic="auth_file_added",
    cwe=("CWE-522",), tags=("credential-file", "heuristic"),
    title=("Registry/credential config file added (.npmrc, .pypirc, .netrc)",
           "فایل پیکربندی اعتبار رجیستری افزوده شده (.npmrc، .pypirc، .netrc)"),
    description=("These files carry registry tokens or plaintext passwords.",
                 "این فایل‌ها توکن رجیستری یا رمز عبور متن‌آشکار حمل می‌کنند."),
    remediation=("Remove and gitignore them; inject credentials in CI secrets.",
                 "حذف و gitignore کنید؛ اعتبارنامه را در رازهای CI تزریق کنید."),
)

rule(
    "SUS-PERSISTENCE-STARTUP",
    "suspicious", "suspicious_change", "high", confidence=0.7,
    patterns=[
        r"(?i)(?:HKEY_[^\\]*\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\Run)",
        r"/etc/rc\.local", r"@reboot\b", r"LaunchAgents/", r"systemctl\s+enable\b",
        r"\bcrontab\s+-e\b", r"/etc/cron\.", r"\bschtasks\s+/create\b",
        r"Startup\s*Folder", r"/etc/systemd/system/",
    ],
    include=("**",),
    cwe=("CWE-506",), tags=("persistence"),
    title=("Autostart / persistence location touched", "محل شروع خودکار / ماندگاری دست‌خورده است"),
    description=("The change writes to run-keys, cron, systemd units or startup folders — code that "
                 "survives reboots.",
                 "تغییر روی کلیدهای Run، cron، یونیت‌های systemd یا پوشه‌های شروع خودکار می‌نویسد؛ کدی که پس از "
                 "راه‌اندازی مجدد می‌ماند."),
    remediation=("Only intentional, reviewed installers may touch autostart; document owner and purpose.",
                 "فقط نصب‌کننده‌های عمدی و بازبینی‌شده مجاز به دست‌زدن به شروع خودکارند؛ مالک و هدف را مستند کنید."),
)

rule(
    "SUS-AUTHORIZED-KEYS-CHANGE",
    "suspicious", "suspicious_change", "critical", confidence=0.9,
    patterns=[r"^ssh-(?:rsa|ed25519|ecdsa|dss)\s+AAAA"],
    include=("**/authorized_keys", "**/authorized_keys2", "**/.ssh/**"),
    cwe=("CWE-284",), tags=("ssh", "persistence"),
    title=("SSH authorized_keys modified", "فایل authorized_keys_ssh تغییر کرده است"),
    description=("A public key was added to an authorized_keys file: someone (or something) granted "
                 "themselves SSH access.",
                 "کلید عمومی به فایل authorized_keys افزوده شده: کسی (یا چیزی) به خودش دسترسی SSH داده است."),
    remediation=("Verify the key fingerprint with the owner; remove unknown keys immediately.",
                 "اثر انگشت کلید را با مالک راستی‌آزمایی کنید و کلیدهای ناشناخته را فوراً حذف کنید."),
)

rule(
    "SUS-SUDOERS-CHANGE",
    "suspicious", "suspicious_change", "high", confidence=0.85,
    patterns=[r"(?:ALL|NOPASSWD)\s*[:=(]"],
    include=("**/sudoers", "**/sudoers.d/**"),
    cwe=("CWE-269",), tags=("privilege"),
    title=("sudoers policy modified", "سیاست sudoers تغییر کرده است"),
    description=("Granting passwordless or ALL privileges escalates any compromise to root.",
                 "اعطای دسترسی بدون رمز یا ALL، هر نفوذی را به ریشه ارتقا می‌دهد."),
    remediation=("Use the narrowest command-specific rule and require review for sudoers changes.",
                 "از محدودترین قاعده مخصوص دستور استفاده کنید و تغییرات sudoers را منوط به بازبینی کنید."),
)

rule(
    "SUS-HOSTS-FILE-CHANGE",
    "suspicious", "suspicious_change", "medium", confidence=0.75,
    patterns=[r"^\d{1,3}(?:\.\d{1,3}){3}\s+\S+"],
    include=("**/hosts", "**/etc/hosts"),
    cwe=("CWE-602",), tags=("dns", "mitm"),
    title=("Hosts file mapping added", "نگاشت فایل hosts افزوده شده است"),
    description=("Redirecting domains via hosts can intercept traffic for security or analytics "
                 "endpoints.",
                 "تغییرمسیر دامنه‌ها با hosts می‌تواند ترافیک endPointهای امنیتی یا تحلیلی را رهگیری کند."),
    remediation=("Confirm each mapping is intentional infrastructure.",
                 "تأیید کنید هر نگاشت، زیرساخت عمدی است."),
)

rule(
    "SUS-HIDDEN-FILE-ADDED",
    "suspicious", "suspicious_change", "low", confidence=0.6,
    heuristic="hidden_file_added",
    cwe=("CWE-506",), tags=("evasion", "heuristic"),
    title=("Hidden dot-file added", "فایل نقطه‌ای پنهان افزوده شده است"),
    description=("A new dot-prefixed file (config, rc, env) appeared. Dot-files are easy to overlook in "
                 "review.",
                 "فایل جدید با پیشوند نقطه (پیکربندی، rc، env) ظاهر شده است. فایل‌های نقطه‌ای در بازبینی به‌سادگی "
                 "نادیده گرفته می‌شوند."),
    remediation=("Check its contents for credentials or persistence.",
                 "محتوای آن را برای اعتبارنامه یا ماندگاری بررسی کنید."),
)

rule(
    "SUS-EXFIL-ENV-TO-NETWORK",
    "suspicious", "suspicious_change", "high", confidence=0.8,
    patterns=[
        r"(?:curl|wget)\s+[^\n|;&]*(?:process\.env|os\.environ|ENV\[|\$\{?[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD))",
        r"(?:fetch|axios\.(?:post|get)|requests\.(?:post|get)|http\.request)\s*\([^)\n]*(?:process\.env|os\.environ|ENV\[)",
    ],
    include=CODE_INCLUDE + ("**/*.sh", "**/*.ps1"),
    cwe=("CWE-200",), tags=("exfiltration"),
    title=("Environment/secret values sent over the network",
           "مقادیر محیط/رازها روی شبکه ارسال می‌شوند"),
    description=("The change reads credential-like environment values and passes them to a network "
                 "call.",
                 "تغییر مقادیر محیطی شبیه اعتبارنامه را می‌خواند و به فراخوانی شبکه می‌دهد."),
    remediation=("Remove the transmission; send only non-sensitive identifiers.",
                 "انتقال را حذف کنید و فقط شناسه‌های غیرحساس بفرستید."),
)

rule(
    "SUS-DNS-EXFIL",
    "suspicious", "suspicious_change", "high", confidence=0.8,
    patterns=[r"(?:\bdig\b|\bnslookup\b|\bhost\b)\s+[^\n|;&]*(?:\$\{?[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD)|process\.env|os\.environ)"],
    include=("**",),
    cwe=("CWE-200",), tags=("exfiltration", "dns"),
    title=("Possible DNS-based exfiltration", "افشای احتمالی مبتنی بر DNS"),
    description=("Secrets interpolated into DNS lookups encode data into domain names — a classic "
                 "covert channel.",
                 "درون‌یابی رازها در جست‌وجوی DNS، داده را در نام دامنه کدگذاری می‌کند؛ کانال مخفی کلاسیک."),
    remediation=("Remove the lookup or strip secrets from the queried name.",
                 "جست‌وجو را حذف کنید یا رازها را از نام پرس‌وجوشده حذف کنید."),
)

rule(
    "SUS-SETUID-BIT",
    "suspicious", "suspicious_change", "high", confidence=0.85,
    patterns=[r"\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:u\+s|g\+s|4755|2755|4777|6755)\b"],
    include=("**",),
    cwe=("CWE-269",), tags=("privilege"),
    title=("setuid/setgid bit set on a file", "بیت setuid/setgid روی فایل تنظیم شده است"),
    description=("setuid binaries run with the owner's privileges — a prime escalation target.",
                 "باینری‌های setuid با دسترسی مالک اجرا می‌شوند؛ هدف اصلی ارتقای دسترسی."),
    remediation=("Avoid setuid; use sudoers rules or capabilities instead.",
                 "از setuid پرهیز کنید و به‌جای آن قاعده sudoers یا capability استفاده کنید."),
)

rule(
    "SUS-EXEC-BIT-ADDED",
    "suspicious", "suspicious_change", "low", confidence=0.6,
    heuristic="exec_bit_added",
    cwe=("CWE-77",), tags=("permissions", "heuristic"),
    title=("File became executable", "فایل اجرایی شد"),
    description=("The change flips a file's mode to executable. Combined with other signals this can "
                 "indicate planted tooling.",
                 "تغییر حالت فایل را به اجرایی تبدیل می‌کند. همراه با سایر نشانه‌ها می‌تواند ابزار کارگذاشته‌شده "
                 "را نشان دهد."),
    remediation=("Confirm the file is meant to be executed.", "تأیید کنید فایل قرار است اجرا شود."),
)

rule(
    "SUS-COMMIT-DATE-SPOOF",
    "suspicious", "suspicious_change", "low", confidence=0.7,
    patterns=[r"GIT_(?:AUTHOR|COMMITTER)_DATE\s*=", r"\bgit\s+commit\b[^\n|;&]*--date\s*="],
    include=("**",),
    cwe=("CWE-506",), tags=("evasion", "git"),
    title=("Commit timestamps manipulated", "مهرهای زمانی کامیت دست‌کاری شده‌اند"),
    description=("Spoofed dates distort audit trails and can hide when a change really landed.",
                 "تاریخ‌های جعلی، ردیف ممیزی را مخدوش می‌کنند و می‌توانند زمان واقعی نشست تغییر را پنهان کنند."),
    remediation=("Use real timestamps; investigate scripts that rewrite them.",
                 "از مهرهای واقعی استفاده کنید و اسکریپت‌های بازنویسی تاریخ را بررسی کنید."),
)

# ----------------------------------------------------------- supply chain ---

rule(
    "SC-INSTALL-SCRIPT-ADDED",
    "supply_chain", "supply_chain", "high", confidence=0.85,
    heuristic="install_script_added",
    cwe=("CWE-506", "CWE-1357"), tags=("npm", "lifecycle", "heuristic"),
    refs=("https://owasp.org/www-community/attacks/Software_Supply_Chain_Attacks",),
    title=("Package install script added (preinstall/postinstall)",
           "اسکریپت نصب بسته افزوده شده (preinstall/postinstall)"),
    description=("Lifecycle scripts run automatically on `npm install` — the most abused supply-chain "
                 "vector. AI tools sometimes add them for 'setup'.",
                 "اسکریپت‌های چرخه حیات به‌صورت خودکار با `npm install` اجرا می‌شوند؛ پرتکرارترین بردار حمله "
                 "زنجیره تأمین. ابزارهای هوش مصنوعی گاهی برای «راه‌اندازی» آن‌ها را اضافه می‌کنند."),
    remediation=("Remove the lifecycle script or pin and review exactly what it runs; enable "
                 "ignore-scripts where possible.",
                 "اسکریپت چرخه حیات را حذف کنید یا دقیقاً آنچه اجرا می‌کند بازبینی و ثابت کنید؛ در امکان "
                 "ignore-scripts را فعال کنید."),
)

rule(
    "SC-DEP-WILDCARD-VERSION",
    "supply_chain", "supply_chain", "medium", confidence=0.8,
    patterns=[r"[\"'][^\"'\s]+[\"']\s*:\s*[\"'](?:\*|latest|x|X)[\"']"],
    include=("**/package.json",),
    cwe=("CWE-1357",), tags=("npm", "versioning"),
    title=("Dependency added with wildcard/`latest` version",
           "وابستگی با نسخه wildcard/`latest` افزوده شده است"),
    description=("Unpinned dependencies silently upgrade to whatever is published next — including a "
                 "compromised release.",
                 "وابستگی‌های ثابت‌نشده بی‌صدا به هر چه بعداً منتشر شود ارتقا می‌یابند؛ از جمله نسخه نفوذشده."),
    remediation=("Pin an exact version and commit the lockfile.",
                 "نسخه دقیق ثابت کنید و lockfile را کامیت کنید."),
)

rule(
    "SC-DEP-GIT-OR-URL",
    "supply_chain", "supply_chain", "high", confidence=0.8,
    patterns=[r"[\"'][^\"'\s]+[\"']\s*:\s*[\"'](?:git\+|git:|github:|gitlab:|bitbucket:|file:|link:|https?://)[^\"']*[\"']"],
    include=("**/package.json",),
    cwe=("CWE-1357",), tags=("npm", "provenance"),
    title=("Dependency installed from a Git/URL source",
           "وابستگی از منبع Git/URL نصب می‌شود"),
    description=("Non-registry sources skip registry provenance and signing; branch refs can move "
                 "under you.",
                 "منابع غیررجیستری، اصالت و امضای رجیستری را دور می‌زنند و ارجاع شاخه می‌تواند زیر پای شما تغییر "
                 "کند."),
    remediation=("Prefer registry versions; if unavoidable pin a commit SHA.",
                 "نسخه‌های رجیستری را ترجیح دهید؛ در صورت ناچاری، SHA کامیت ثابت کنید."),
)

rule(
    "SC-DEP-TARBALL",
    "supply_chain", "supply_chain", "high", confidence=0.85,
    patterns=[r"[\"'][^\"'\s]+[\"']\s*:\s*[\"']https?://[^\"']+\.(?:tgz|tar\.gz|zip|whl)[\"']"],
    include=("**/package.json", "**/requirements*.txt", "**/pyproject.toml"),
    cwe=("CWE-1357",), tags=("provenance"),
    title=("Dependency installed from a remote archive",
           "وابستگی از آرشیو راه دور نصب می‌شود"),
    description=("Direct archive installs bypass registry integrity checks.",
                 "نصب مستقیم آرشیو، بررسی‌های یکپارچگی رجیستری را دور می‌زند."),
    remediation=("Pin a checksum and host the artifact in trusted storage.",
                 "checksum ثابت کنید و أثر را در ذخیره‌سازی مورد اعتماد میزبانی کنید."),
)

rule(
    "SC-TYPOSQUAT-CANDIDATE",
    "supply_chain", "supply_chain", "high", confidence=0.8,
    heuristic="typosquat",
    cwe=("CWE-1357",), tags=("typosquatting", "heuristic"),
    title=("Possible typosquatted package name", "نام بسته با احتمال جعل هم‌شکل"),
    description=("A newly added dependency name is one edit away from a very popular package — the "
                 "classic typosquat pattern.",
                 "نام وابستگی تازه‌افزوده یک ویرایش با بسته‌ای بسیار محبوب فاصله دارد؛ الگوی کلاسیک typosquat."),
    remediation=("Verify the package on the official registry (author, downloads, repo) before use.",
                 "بسته را در رجیستری رسمی (نویسنده، دانلودها، مخزن) پیش از استفاده راستی‌آزمایی کنید."),
)

rule(
    "SC-LOCKFILE-DRIFT",
    "supply_chain", "supply_chain", "medium", confidence=0.8,
    heuristic="lockfile_drift",
    cwe=("CWE-1357",), tags=("lockfile", "heuristic"),
    title=("Manifest changed without its lockfile",
           "فایل manifest بدون lockfile متناظرش تغییر کرده است"),
    description=("package.json/Cargo.toml/requirements changed but no lockfile is part of the change, "
                 "so resolved versions are unreviewed.",
                 "package.json/Cargo.toml/requirements تغییر کرده ولی هیچ lockfile بخشی از تغییر نیست؛ پس "
                 "نسخه‌های resolve‌شده بازبینی‌نشده‌اند."),
    remediation=("Commit the updated lockfile with the manifest.",
                 "lockfile به‌روزشده را همراه manifest کامیت کنید."),
)

rule(
    "SC-REGISTRY-REDIRECT",
    "supply_chain", "supply_chain", "high", confidence=0.85,
    patterns=[
        r"(?i)(?:registry|index-url|extra-index-url|index_url)\s*=\s*https?://\S+",
        r"(?i)--index-url\s+https?://\S+",
    ],
    negative=[r"(?i)(registry\.npmjs\.org|pypi\.org|files\.pythonhosted\.org|registry\.yarnpkg\.com|pkgs\.dev\.azure\.com)"],
    include=("**",),
    cwe=("CWE-1357",), tags=("registry"),
    title=("Package registry redirected to a non-official host",
           "رجیستری بسته به میزبان غیررسمی تغییر مسیر یافته است"),
    description=("Pointing installers at another registry lets that host serve arbitrary packages "
                 "under official names.",
                 "اشاره نصب‌کننده‌ها به رجیستری دیگر به آن میزبان اجازه می‌دهد بسته‌های دلخواه را با نام‌های رسمی "
                 "ارائه دهد."),
    remediation=("Only use official registries or an audited internal mirror over TLS.",
                 "فقط از رجیستری‌های رسمی یا آینه داخلی ممیزی‌شده روی TLS استفاده کنید."),
)

rule(
    "SC-NPMRC-TOKEN",
    "supply_chain", "supply_chain", "high", confidence=0.9, redactable=True,
    patterns=[r"_authToken\s*=\s*\S+", r"^_auth\s*=\s*\S+", r"username\s*=\s*\S+\s*$"],
    include=("**/.npmrc", "**/.pypirc", "**/.netrc", "**/nuget.config"),
    cwe=("CWE-798",), tags=("credential", "registry"),
    title=("Registry credentials stored in a config file",
           "اعتبارنامه رجیستری در فایل پیکربندی ذخیره شده است"),
    description=(".npmrc/.pypirc/.netrc with tokens or passwords must never enter version control.",
                 ".npmrc/.pypirc/.netrc دارای توکن یا رمز هرگز نباید وارد کنترل نسخه شوند."),
    remediation=("Remove the file, add it to .gitignore, rotate the token, and use CI secret injection.",
                 "فایل را حذف و به .gitignore اضافه کنید، توکن را بچرخانید و از تزریق راز CI استفاده کنید."),
)

rule(
    "SC-DOCKER-REMOTE-ADD",
    "supply_chain", "supply_chain", "medium", confidence=0.75,
    patterns=[r"^\s*ADD\s+https?://"],
    include=("**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile"),
    cwe=("CWE-494",), tags=("docker", "provenance"),
    title=("Dockerfile ADDs a remote URL", "داکرفایل آدرس راه دور را ADD می‌کند"),
    description=("ADD of a remote archive fetches unverified content at build time with no checksum.",
                 "ADD آرشیو راه دور، محتوای راستی‌آزمایی‌نشده را در زمان بیلد بدون checksum واکشی می‌کند."),
    remediation=("Use COPY of a pinned artifact or verify checksums after download.",
                 "از COPY أثر ثابت‌شده استفاده کنید یا پس از دانلود checksum را راستی‌آزمایی کنید."),
)

rule(
    "SC-DOCKER-RUN-CURL-PIPE",
    "supply_chain", "supply_chain", "high", confidence=0.85,
    patterns=[r"(?:curl|wget)\s+[^\n|;&]*\|\s*(?:ba|z|da)?sh"],
    include=("**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile"),
    cwe=("CWE-494",), tags=("docker", "remote-exec"),
    title=("Dockerfile pipes a remote script to a shell",
           "داکرفایل اسکریپت راه دور را به شل لوله می‌کند"),
    description=("The image build executes unreviewed remote code.", "بیلد ایمیج، کد راه دور بازبینی‌نشده را اجرا می‌کند."),
    remediation=("Pin and checksum the script before executing.", "اسکریپت را پیش از اجرا ثابت و checksum کنید."),
)

rule(
    "SC-PIP-UNPINNED",
    "supply_chain", "supply_chain", "medium", confidence=0.6,
    patterns=[r"^\s*[A-Za-z0-9_.\-]+\s*(?:#.*)?$"],
    include=("**/requirements*.txt",),
    cwe=("CWE-1357",), tags=("python", "versioning"),
    title=("Unpinned Python requirement added", "نیازمندی پایتون بدون نسخه ثابت افزوده شده است"),
    description=("Requirements without version pins resolve to newest releases at install time.",
                 "نیازمندی‌های بدون پین نسخه، در زمان نصب به جدیدترین نسخه resolve می‌شوند."),
    remediation=("Pin exact versions (==) or use a lockfile (uv/pip-tools/poetry).",
                 "نسخه دقیق (==) ثابت کنید یا از lockfile استفاده کنید (uv/pip-tools/poetry)."),
)

rule(
    "SC-CARGO-GIT-DEP",
    "supply_chain", "supply_chain", "medium", confidence=0.75,
    patterns=[r"^\s*git\s*=\s*[\"']"],
    include=("**/Cargo.toml",),
    cwe=("CWE-1357",), tags=("rust", "provenance"),
    title=("Cargo dependency from a Git repository", "وابستگی Cargo از مخزن Git"),
    description=("Git dependencies move with the upstream branch unless pinned by rev.",
                 "وابستگی‌های Git با شاخه بالادستی جابه‌جا می‌شوند مگر با rev ثابت شوند."),
    remediation=("Pin `rev = \"<sha>\"` or use crates.io versions.", "‏`rev = \"<sha>\"` ثابت کنید یا از نسخه crates.io استفاده کنید."),
)

rule(
    "SC-GO-MODULE-REPLACE",
    "supply_chain", "supply_chain", "medium", confidence=0.75,
    patterns=[r"^\s*replace\s+\S+\s*=>"],
    include=("**/go.mod",),
    cwe=("CWE-1357",), tags=("go", "provenance"),
    title=("Go module replaced with a different source", "ماژول Go با منبع دیگری جایگزین شده است"),
    description=("`replace` directives swap a dependency for another path/repo, bypassing module "
                 "checksums.",
                 "دایرکتیوهای `replace` یک وابستگی را با مسیر/مخزن دیگری عوض می‌کنند و checksumهای ماژول را "
                 "دور می‌زنند."),
    remediation=("Keep replaces local-development only; never in shared builds.",
                 "replace را فقط برای توسعه محلی نگه دارید؛ هرگز در بیلد مشترک."),
)

# ------------------------------------------------------------------ ci/cd ---

rule(
    "CI-PR-TARGET-UNTRUSTED-CHECKOUT",
    "ci_cd", "ci_cd", "critical", confidence=0.9,
    heuristic="pr_target_checkout",
    cwe=("CWE-94",), tags=("github-actions", "injection"),
    refs=("https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",),
    title=("pull_request_target checks out pull-request code",
           "pull_request_target کد pull request را checkout می‌کند"),
    description=("`pull_request_target` runs with base-repo secrets; checking out (and typically "
                 "building/running) the PR head lets any fork steal them.",
                 "`pull_request_target` با رازهای مخزن پایه اجرا می‌شود؛ checkout کردن سرِ PR (و معمولاً بیلد/"
                 "اجرای آن) به هر فورک اجازه سرقت رازها را می‌دهد."),
    remediation=("Use `pull_request` for untrusted code, or keep `pull_request_target` to labelled/"
                 "approved steps that never execute PR code.",
                 "برای کد نامعتبر از `pull_request` استفاده کنید یا `pull_request_target` را به گام‌های برچسب/"
                 "تأییدشده‌ای محدود کنید که هرگز کد PR را اجرا نمی‌کنند."),
)

rule(
    "CI-EXPRESSION-INJECTION",
    "ci_cd", "ci_cd", "critical", confidence=0.9,
    patterns=[
        r"\$\{\{\s*github\.event\.(?:pull_request|issue|comment|discussion|review|review_comment)\.(?:title|body|head\.ref|head\.sha|head\.label|comment\.body|diff_hunk)\s*\}\}",
        r"\$\{\{\s*github\.event\.inputs\.[A-Za-z0-9_]+\s*\}\}",
        r"\$\{\{\s*github\.event\.comment\.body\s*\}\}",
    ],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-78", "CWE-94"), tags=("github-actions", "injection"),
    title=("Untrusted GitHub event data interpolated into shell",
           "داده نامعتبر رویداد GitHub در شل درون‌یابی شده است"),
    description=("`${{ github.event.*.body }}` inside `run:` is command injection: the attacker writes "
                 "the issue/PR text that becomes shell code.",
                 "‏`${{ github.event.*.body }}` داخل `run:` تزریق دستور است: مهاجم متن issue/PR را می‌نویسد که "
                 "کد شل می‌شود."),
    remediation=("Pass event data via `env:` and reference `$ENV_VAR`, never inline `${{ }}` in run.",
                 "داده رویداد را از طریق `env:` بدهید و به `$ENV_VAR` ارجاع دهید، هرگز `${{ }}` درون‌خطی در run."),
)

rule(
    "CI-PERMISSIONS-WRITE-ALL",
    "ci_cd", "ci_cd", "high", confidence=0.9,
    patterns=[r"^\s*permissions:\s*write-all\s*$"],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-269",), tags=("github-actions", "permissions"),
    title=("Workflow requests write-all permissions", "ورک‌فلو دسترسی write-all درخواست می‌کند"),
    description=("write-all grants the GITHUB_TOKEN full write access; a compromised step can push "
                 "code or cut releases.",
                 "write-all به GITHUB_TOKEN دسترسی نوشتن کامل می‌دهد؛ گام نفوذشده می‌تواند کد push کند یا ریلیز "
                 "ببرد."),
    remediation=("Declare the minimal permissions per job (contents: read, etc.).",
                 "کمینه دسترسی‌ها را per job اعلام کنید (contents: read و...)."),
)

rule(
    "CI-SECRETS-IN-PR-TARGET",
    "ci_cd", "ci_cd", "high", confidence=0.85,
    heuristic="secrets_in_pr_target",
    cwe=("CWE-522",), tags=("github-actions", "secrets", "heuristic"),
    title=("Secrets exposed to a pull_request_target workflow",
           "رازها در معرض ورک‌فلو pull_request_target"),
    description=("The workflow references `secrets.*` while running on pull_request_target, where fork "
                 "code executes.",
                 "ورک‌فلو به `secrets.*` ارجاع می‌دهد در حالی که روی pull_request_target اجرا می‌شود، جایی که "
                 "کد فورک اجرا می‌گردد."),
    remediation=("Gate secret use behind approval events or move to `pull_request` + environments.",
                 "استفاده از راز را پشت رویدادهای تأیید ببرید یا به `pull_request` + environments منتقل کنید."),
)

rule(
    "CI-SELF-HOSTED-RUNNER",
    "ci_cd", "ci_cd", "medium", confidence=0.75,
    patterns=[r"runs-on:\s*\[?[^\n\]]*self-hosted"],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-94",), tags=("github-actions", "runner"),
    title=("Workflow runs on a self-hosted runner", "ورک‌فلو روی رانر self-hosted اجرا می‌شود"),
    description=("Self-hosted runners persist state and credentials between jobs; untrusted PR code "
                 "there can poison the host.",
                 "رانرهای self-hosted وضعیت و اعتبارنامه را بین jobها نگه می‌دارند؛ کد نامعتبر PR آنجا می‌تواند "
                 "میزبان را آلوده کند."),
    remediation=("Use ephemeral runners for untrusted code; isolate self-hosted runners.",
                 "برای کد نامعتبر از رانرهای یک‌بارمصرف استفاده کنید و رانرهای self-hosted را ایزوله کنید."),
)

rule(
    "CI-ACTION-UNPINNED-BRANCH",
    "ci_cd", "ci_cd", "high", confidence=0.85,
    patterns=[r"uses:\s*[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+@(?:master|main|develop|head|latest)\b"],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-1357",), tags=("github-actions", "provenance"),
    title=("Third-party action pinned to a moving branch",
           "اکشن ثالث به شاخه متحرک پین شده است"),
    description=("Referencing @main/@master means the action's code can change silently under your "
                 "workflow.",
                 "ارجاع به @main/@master یعنی کد اکشن می‌تواند بی‌صدا زیر ورک‌فلوی شما تغییر کند."),
    remediation=("Pin actions to a full commit SHA (or a signed tag) and update deliberately.",
                 "اکشن‌ها را به SHA کامل کامیت (یا تگ امضاشده) پین کنید و عمدی به‌روز کنید."),
)

rule(
    "CI-ACTION-TAG-ONLY",
    "ci_cd", "ci_cd", "low", confidence=0.7,
    patterns=[r"uses:\s*(?:[A-Za-z0-9_.\-]+/)+[A-Za-z0-9_.\-]+@v\d+(?:\.\d+)*\s*$"],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-1357",), tags=("github-actions", "provenance"),
    title=("Action pinned by mutable tag", "اکشن با تگ قابل‌تغییر پین شده است"),
    description=("Tags can be moved; SHA pinning is the recommended hardening (informational).",
                 "تگ‌ها قابل جابه‌جایی‌اند؛ پین SHA سخت‌سازی توصیه‌شده است (اطلاعاتی)."),
    remediation=("Optionally pin the full commit SHA for supply-chain assurance.",
                 "در صورت نیاز، SHA کامل کامیت را برای تضمین زنجیره تأمین پین کنید."),
)

rule(
    "CI-OUTDATED-CHECKOUT",
    "ci_cd", "ci_cd", "low", confidence=0.8,
    patterns=[r"uses:\s*actions/checkout@v[12]\b"],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-1104",), tags=("github-actions"),
    title=("Outdated actions/checkout version", "نسخه قدیمی actions/checkout"),
    description=("checkout v1/v2 lack modern safety defaults and token scoping.",
                 "checkout v1/v2 پیش‌فرض‌های ایمن و محدوده‌بندی توکن مدرن را ندارند."),
    remediation=("Upgrade to the current major with `persist-credentials: false` where suitable.",
                 "به ماژور فعلی با `persist-credentials: false` در صورت مناسب بودن ارتقا دهید."),
)

rule(
    "CI-ARTIFACT-SENSITIVE-PATH",
    "ci_cd", "ci_cd", "high", confidence=0.8,
    patterns=[r"path:\s*[^\n]*(?:\.env\b|\.env\.|secrets?\b|credentials\b|\.pem\b|\.key\b|id_rsa)"],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-532",), tags=("github-actions", "artifacts"),
    title=("Workflow uploads sensitive files as artifacts",
           "ورک‌فلو فایل‌های حساس را به‌عنوان artifact بارگذاری می‌کند"),
    description=("Artifacts are downloadable by anyone with repo read access; uploading .env/secrets "
                 "leaks them.",
                 "artifactها برای هر کسی با دسترسی خواندن مخزن قابل دانلودند؛ بارگذاری .env/رازها آن‌ها را فاش "
                 "می‌کند."),
    remediation=("Exclude sensitive paths from upload-artifact.",
                 "مسیرهای حساس را از upload-artifact خارج کنید."),
)

rule(
    "CI-ECHO-SECRET",
    "ci_cd", "ci_cd", "critical", confidence=0.9,
    patterns=[r"(?i)(?:echo|printf|Write-Output|cat)\b[^\n|;&]*\$\{\{\s*secrets\."],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-532",), tags=("github-actions", "secrets"),
    title=("Secret printed to workflow logs", "راز در لاگ ورک‌فلو چاپ می‌شود"),
    description=("Echoing `${{ secrets.* }}` writes the secret into public logs (masking can be "
                 "bypassed by encoding).",
                 "چاپ `${{ secrets.* }}` راز را در لاگ عمومی می‌نویسد (ماسک‌سازی با رمزگذاری قابل دور زدن است)."),
    remediation=("Never print secrets; pass them to commands via env.",
                 "هرگز رازها را چاپ نکنید؛ از طریق env به دستورها بدهید."),
)

rule(
    "CI-SUDO-IN-WORKFLOW",
    "ci_cd", "ci_cd", "medium", confidence=0.6,
    patterns=[r"^\s*(?:-\s*)?run:\s*\|?\s*sudo\s+", r"^\s*sudo\s+\S+"],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-269",), tags=("github-actions", "privilege"),
    title=("sudo used in workflow step", "استفاده از sudo در گام ورک‌فلو"),
    description=("GitHub runners already run as a privileged user; sudo widens the impact of any "
                 "injected command.",
                 "رانرهای GitHub از قبل با کاربر دارای دسترسی اجرا می‌شوند؛ sudo تأثیر هر دستور تزریق‌شده را "
                 "بزرگ‌تر می‌کند."),
    remediation=("Avoid sudo; install dependencies in user space or use containers.",
                 "از sudo پرهیز کنید؛ وابستگی‌ها را در فضای کاربر نصب کنید یا از کانتینر استفاده کنید."),
)

rule(
    "CI-CURL-PIPE-IN-WORKFLOW",
    "ci_cd", "ci_cd", "high", confidence=0.85,
    patterns=[r"(?:curl|wget)\s+[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"],
    include=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-494",), tags=("github-actions", "remote-exec"),
    title=("Workflow pipes remote script to shell", "ورک‌فلو اسکریپت راه دور را به شل لوله می‌کند"),
    description=("CI executes unreviewed remote code with repository credentials present.",
                 "CI کد راه دور بازبینی‌نشده را با حضور اعتبارنامه‌های مخزن اجرا می‌کند."),
    remediation=("Pin installer scripts to checksummed releases.",
                 "اسکریپت‌های نصب‌کننده را به ریلیزهای دارای checksum پین کنید."),
)
