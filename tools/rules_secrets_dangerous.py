"""Secret-leak and dangerous-operation rules."""

from rules_lib import rule

NEG_EXAMPLE = [
    r"(?i)(example|sample|dummy|placeholder|changeme|change-me|xxxx|your[-_ ]?"
    r"(key|token|secret|password)|insert[-_ ]?(here|key)|todo|replace[-_ ]?me|"
    r"<[^>]+>|\$\{|\{\{|fake|test-only|redacted)"
]

# ---------------------------------------------------------------- secrets ---

rule(
    "SEC-SECRET-AWS-ACCESS-KEY",
    "secrets", "secret_leak", "critical", confidence=0.95, redactable=True,
    patterns=[r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}"],
    negative=[r"(?i)(example|sample|dummy|xxxx|AKIAIOSFODNN7EXAMPLE)"],
    cwe=("CWE-798", "CWE-321"), tags=("aws", "credential", "cloud"),
    refs=("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",),
    title=("AWS access key ID committed to the repository",
           "کلید دسترسی AWS در مخزن درج شده است"),
    description=("A string matching the AWS access key ID format (AKIA/ASIA/... followed by 16 "
                 "characters) was added. If real, anyone with repository access can use it.",
                 "رشته‌ای مطابق قالب کلید دسترسی AWS (شروع با AKIA/ASIA و ۱۶ نویسه پس از آن) افزوده شده است. "
                 "در صورت واقعی بودن، هر کسی با دسترسی به مخزن می‌تواند از آن استفاده کند."),
    remediation=("Rotate the key immediately in IAM, remove it from the current commit and from Git "
                 "history, and load credentials from the environment or a secret manager.",
                 "کلید را فوراً در IAM غیرفعال و جایگزین کنید، آن را از کامیت فعلی و تاریخچه Git حذف کنید و "
                 "اعتبارنامه‌ها را از متغیر محیطی یا مدیریت راز دریافت کنید."),
)

rule(
    "SEC-SECRET-AWS-SECRET-KEY",
    "secrets", "secret_leak", "critical", confidence=0.9, redactable=True,
    patterns=[r"(?i)aws[_-]?(?:secret[_-]?access[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"],
    negative=[NEG_EXAMPLE[0]],
    cwe=("CWE-798",), tags=("aws", "credential"),
    title=("AWS secret access key assigned in code",
           "کلید محرمانه دسترسی AWS در کد مقداردهی شده است"),
    description=("A 40-character value is assigned to an AWS secret access key variable. The secret "
                 "key plus an access key grants full API access.",
                 "یک مقدار ۴۰ نویسه‌ای به متغیر کلید محرمانه AWS اختصاص یافته است. این کلید همراه با کلید "
                 "دسترسی، دسترسی کامل API می‌دهد."),
    remediation=("Rotate the credential pair, purge it from history and inject it at runtime from a "
                 "secret store.",
                 "جفت اعتبارنامه را بچرخانید، از تاریخچه حذف کنید و در زمان اجرا از مخزن راز تزریق کنید."),
)

rule(
    "SEC-SECRET-PRIVATE-KEY-BLOCK",
    "secrets", "secret_leak", "critical", confidence=0.98, redactable=True,
    patterns=[r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"],
    target="both",
    cwe=("CWE-321",), tags=("private-key", "ssh", "tls"),
    title=("Private key material added to the repository",
           "کلید خصوصی به مخزن افزوده شده است"),
    description=("A PEM private key header was detected. Committing private keys (SSH, TLS, signing) "
                 "exposes every system that trusts the matching public key.",
                 "سربرگ کلید خصوصی PEM شناسایی شد. درج کلیدهای خصوصی (SSH، TLS، امضا) همه سامانه‌هایی را "
                 "که به کلید عمومی متناظر اعتماد دارند در معرض خطر قرار می‌دهد."),
    remediation=("Remove the key, revoke/reissue it, and reference it by path or secret manager. Add "
                 "*.pem / *.key / id_* to .gitignore.",
                 "کلید را حذف و ابطال/جایگزین کنید و به‌صورت مسیر فایل یا مدیریت راز ارجاع دهید. "
                 "الگوهای *.pem و *.key و id_* را به .gitignore اضافه کنید."),
)

rule(
    "SEC-SECRET-GITHUB-TOKEN",
    "secrets", "secret_leak", "critical", confidence=0.95, redactable=True,
    patterns=[r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}", r"github_pat_[A-Za-z0-9_]{22,}"],
    cwe=("CWE-798",), tags=("github", "credential"),
    title=("GitHub personal access token committed",
           "توکن دسترسی شخصی GitHub درج شده است"),
    description=("A GitHub PAT (classic or fine-grained) was added. GitHub also scans for these, but "
                 "the token must be considered compromised.",
                 "یک توکن PAT گیت‌هاب (کلاسیک یا دقیق) افزوده شده است. حتی با اسکن خودکار گیت‌هاب، این توکن "
                 "لو رفته محسوب می‌شود."),
    remediation=("Revoke the token in GitHub settings now, then remove it from the commit and history.",
                 "هم‌اکنون توکن را در تنظیمات GitHub باطل کنید و سپس آن را از کامیت و تاریخچه حذف کنید."),
)

rule(
    "SEC-SECRET-GITLAB-TOKEN",
    "secrets", "secret_leak", "critical", confidence=0.95, redactable=True,
    patterns=[r"glpat-[A-Za-z0-9_\-]{20,}"],
    cwe=("CWE-798",), tags=("gitlab", "credential"),
    title=("GitLab personal access token committed",
           "توکن دسترسی شخصی GitLab درج شده است"),
    description=("A GitLab PAT was added to the change.", "یک توکن PAT گیت‌لب به تغییرات افزوده شده است."),
    remediation=("Revoke it under GitLab > Preferences > Access Tokens and rotate any CI variables.",
                 "آن را در مسیر GitLab > Preferences > Access Tokens باطل کنید و متغیرهای CI را بچرخانید."),
)

rule(
    "SEC-SECRET-SLACK-TOKEN",
    "secrets", "secret_leak", "critical", confidence=0.95, redactable=True,
    patterns=[r"xox[baprs]-[0-9A-Za-z\-]{10,}"],
    cwe=("CWE-798",), tags=("slack", "credential"),
    title=("Slack token committed", "توکن Slack درج شده است"),
    description=("A Slack bot/user/app token (xoxb/xoxp/xoxa/xoxs/xoxr) was added.",
                 "یک توکن Slack با پیشوند xoxb/xoxp/xoxa/xoxs/xoxr افزوده شده است."),
    remediation=("Regenerate the token in the Slack app dashboard and review recent API activity.",
                 "توکن را در داشبورد اپلیکیشن Slack بازسازی کنید و فعالیت اخیر API را بررسی کنید."),
)

rule(
    "SEC-SECRET-SLACK-WEBHOOK",
    "secrets", "secret_leak", "high", confidence=0.9, redactable=True,
    patterns=[r"hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9]+"],
    cwe=("CWE-798",), tags=("slack", "webhook"),
    title=("Slack incoming webhook URL committed", "آدرس وب‌هوک Slack درج شده است"),
    description=("Anyone with this URL can post messages to the workspace channel.",
                 "هر کسی با این آدرس می‌تواند در کانال فضای کاری پیام بفرستد."),
    remediation=("Delete and regenerate the webhook in Slack app settings.",
                 "وب‌هوک را در تنظیمات اپلیکیشن Slack حذف و بازسازی کنید."),
)

rule(
    "SEC-SECRET-STRIPE-KEY",
    "secrets", "secret_leak", "critical", confidence=0.92, redactable=True,
    patterns=[r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"],
    cwe=("CWE-798",), tags=("stripe", "payment", "credential"),
    title=("Stripe secret/restricted key committed", "کلید محرمانه Stripe درج شده است"),
    description=("A Stripe secret (sk_) or restricted (rk_) key was added. Live keys allow charges, "
                 "refunds and payouts.",
                 "کلید محرمانه (sk_) یا محدودشده (rk_) استرایپ افزوده شده است. کلید زنده امکان برداشت، "
                 "استرداد و پرداخت می‌دهد."),
    remediation=("Roll the key in the Stripe dashboard and move it to server-side environment variables.",
                 "کلید را در داشبورد Stripe بچرخانید و به متغیر محیطی سمت سرور منتقل کنید."),
)

rule(
    "SEC-SECRET-OPENAI-KEY",
    "secrets", "secret_leak", "high", confidence=0.85, redactable=True,
    patterns=[r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"],
    negative=[r"(?i)(example|sample|dummy|xxxx|placeholder|sk-proj-xxx)"],
    cwe=("CWE-798",), tags=("openai", "llm", "credential"),
    title=("OpenAI API key committed", "کلید API OpenAI درج شده است"),
    description=("A value in OpenAI key format (sk-...) was added. It bills to the owning account.",
                 "مقداری در قالب کلید OpenAI (sk-...) افزوده شده که هزینه آن به حساب مالک می‌نشیند."),
    remediation=("Rotate the key in the OpenAI platform console and check usage for abuse.",
                 "کلید را در کنسول پلتفرم OpenAI بچرخانید و مصرف را برای سوءاستفاده بررسی کنید."),
)

rule(
    "SEC-SECRET-ANTHROPIC-KEY",
    "secrets", "secret_leak", "critical", confidence=0.95, redactable=True,
    patterns=[r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"],
    cwe=("CWE-798",), tags=("anthropic", "llm", "credential"),
    title=("Anthropic API key committed", "کلید API Anthropic درج شده است"),
    description=("An Anthropic key (sk-ant-...) was added to the change.",
                 "کلید Anthropic با پیشوند sk-ant- به تغییرات افزوده شده است."),
    remediation=("Rotate the key in the Anthropic console and load it from the environment.",
                 "کلید را در کنسول Anthropic بچرخانید و از متغیر محیطی بارگذاری کنید."),
)

rule(
    "SEC-SECRET-AZURE-ACCOUNT-KEY",
    "secrets", "secret_leak", "critical", confidence=0.9, redactable=True,
    patterns=[r"(?i)(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{40,}"],
    negative=[NEG_EXAMPLE[0]],
    cwe=("CWE-798",), tags=("azure", "cloud", "credential"),
    title=("Azure storage account key or SAS key committed",
           "کلید حساب ذخیره‌سازی Azure یا کلید SAS درج شده است"),
    description=("An Azure AccountKey/SharedAccessKey value was added. Account keys grant full read/"
                 "write access to the storage account.",
                 "مقدار AccountKey یا SharedAccessKey افزوده شده است. کلید حساب، دسترسی کامل خواندن/"
                 "نوشتن به حساب ذخیره‌سازی می‌دهد."),
    remediation=("Regenerate the storage key in Azure Portal and prefer managed identities or short-"
                 "lived SAS tokens.",
                 "کلید را در پورتال Azure بازسازی کنید و هویت مدیریت‌شده یا SAS کوتاه‌مدت را ترجیح دهید."),
)

rule(
    "SEC-SECRET-GCP-SERVICE-ACCOUNT",
    "secrets", "secret_leak", "critical", confidence=0.9,
    patterns=[r"(?i)\"private_key\"\s*:\s*\"-----BEGIN"],
    target="file", include=("**/*.json",),
    cwe=("CWE-798",), tags=("gcp", "service-account", "credential"),
    title=("GCP service account private key committed",
           "کلید خصوصی حساب سرویس GCP درج شده است"),
    description=("A service account JSON key file (with an embedded private key) was added. This "
                 "grants the service account's IAM roles to anyone.",
                 "فایل کلید JSON حساب سرویس با کلید خصوصی داخلی افزوده شده که نقش‌های IAM آن حساب را به "
                 "همه می‌دهد."),
    remediation=("Delete the key in IAM, remove the file from history and use workload identity or "
                 "ADC instead.",
                 "کلید را در IAM حذف کنید، فایل را از تاریخچه ببرید و از هویت بارکاری یا ADC استفاده کنید."),
)

rule(
    "SEC-SECRET-SENDGRID-KEY",
    "secrets", "secret_leak", "high", confidence=0.9, redactable=True,
    patterns=[r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"],
    cwe=("CWE-798",), tags=("sendgrid", "email", "credential"),
    title=("SendGrid API key committed", "کلید API SendGrid درج شده است"),
    description=("A SendGrid key (SG....) was added; it can send email as your domain (phishing risk).",
                 "کلید SendGrid افزوده شده که می‌تواند با دامنه شما ایمیل بفرستد (خطر فیشینگ)."),
    remediation=("Rotate the key and restrict its scopes.", "کلید را بچرخانید و محدوده دسترسی آن را محدود کنید."),
)

rule(
    "SEC-SECRET-NPM-TOKEN",
    "secrets", "secret_leak", "critical", confidence=0.95, redactable=True,
    patterns=[r"\bnpm_[A-Za-z0-9]{36}\b", r"//registry\.npmjs\.org/:_authToken\s*=\s*\S+"],
    cwe=("CWE-798",), tags=("npm", "registry", "credential", "supply-chain"),
    title=("npm registry token committed", "توکن رجیستری npm درج شده است"),
    description=("An npm automation token or registry auth token was added. This allows publishing "
                 "packages under your account (supply-chain attack vector).",
                 "توکن خودکارسازی npm یا توکن احراز هویت رجیستری افزوده شده که امکان انتشار بسته‌ها با حساب "
                 "شما را می‌دهد (بردار حمله زنجیره تأمین)."),
    remediation=("Revoke the token on npmjs.com, audit published versions and never store it in the repo.",
                 "توکن را در npmjs.com باطل کنید، نسخه‌های منتشرشده را بازبینی کنید و هرگز آن را در مخزن نگه ندارید."),
)

rule(
    "SEC-SECRET-PYPI-TOKEN",
    "secrets", "secret_leak", "critical", confidence=0.95, redactable=True,
    patterns=[r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}\b"],
    cwe=("CWE-798",), tags=("pypi", "registry", "credential", "supply-chain"),
    title=("PyPI upload token committed", "توکن بارگذاری PyPI درج شده است"),
    description=("A PyPI API token was added; it can publish releases of your packages.",
                 "توکن API PyPI افزوده شده که می‌تواند نسخه‌های بسته‌های شما را منتشر کند."),
    remediation=("Revoke the token on PyPI and prefer trusted publishing (OIDC) in CI.",
                 "توکن را در PyPI باطل کنید و در CI از انتشار مورد اعتماد (OIDC) استفاده کنید."),
)

rule(
    "SEC-SECRET-JWT-HARDCODED",
    "secrets", "secret_leak", "high", confidence=0.8, redactable=True,
    patterns=[r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"],
    negative=[r"(?i)(example|sample|dummy|xxxx|header\.payload|your[-_ ]?token)"],
    cwe=("CWE-798", "CWE-347"), tags=("jwt", "token"),
    title=("Hardcoded JWT committed", "توکن JWT سخت‌کد شده درج شده است"),
    description=("A JSON Web Token (three base64url segments) is embedded in the change. Tokens are "
                 "credentials and expire; hardcoding them leaks sessions or service identity.",
                 "یک JWT با سه بخش base64url در تغییرات جاسازی شده است. توکن‌ها اعتبارنامه‌اند و سخت‌کد کردن "
                 "آن‌ها نشست یا هویت سرویس را فاش می‌کند."),
    remediation=("Invalidate the token server-side and issue tokens at runtime with short expiry.",
                 "توکن را سمت سرور باطل کنید و توکن‌ها را در زمان اجرا با انقضای کوتاه صادر کنید."),
)

rule(
    "SEC-SECRET-DATABASE-URL",
    "secrets", "secret_leak", "critical", confidence=0.9, redactable=True,
    patterns=[r"(?:postgres|postgresql|mysql|mongodb\+srv|mongodb|redis|rediss|amqp|amqps|mssql|snowflake)://[^\s'\"@/]+:[^\s'\"@]+@[^\s'\"]+"],
    cwe=("CWE-798", "CWE-200"), tags=("database", "connection-string", "credential"),
    title=("Database connection string with credentials committed",
           "رشته اتصال پایگاه داده همراه با اعتبارنامه درج شده است"),
    description=("A connection URL containing username:password@host was added (SQL/NoSQL/broker).",
                 "آدرس اتصال شامل کاربر:رمز@میزبان افزوده شده است (SQL/NoSQL/بروکر)."),
    remediation=("Rotate the database password, drop the URL from history and build it from separate "
                 "environment variables.",
                 "رمز پایگاه داده را بچرخانید، آدرس را از تاریخچه حذف کنید و آن را از متغیرهای محیطی جدا بسازید."),
)

rule(
    "SEC-SECRET-GENERIC-CREDENTIAL",
    "secrets", "secret_leak", "high", confidence=0.7, redactable=True,
    patterns=[
        r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|secret|secret[_-]?key|token|auth[_-]?token|"
        r"access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|encryption[_-]?key|"
        r"signing[_-]?key|password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"
    ],
    negative=[NEG_EXAMPLE[0], r"(?i)(process\.env|os\.environ|getenv|import\.meta\.env|config\(|vault|secret_ref|from_env)"],
    cwe=("CWE-798",), tags=("credential", "generic"),
    title=("Possible hardcoded credential in an assignment",
           "اعتبارنامه سخت‌کد شده احتمالی در یک مقداردهی"),
    description=("A variable with a credential-like name is assigned a quoted literal value instead of "
                 "reading from the environment.",
                 "به متغیری با نام شبیه اعتبارنامه، یک مقدار ثابت رشته‌ای داده شده است نه خواندن از محیط."),
    remediation=("Move the value to an environment variable or secret manager and verify the literal "
                 "is not a real credential.",
                 "مقدار را به متغیر محیطی یا مدیریت راز منتقل کنید و تأیید کنید مقدار ثابت، اعتبارنامه واقعی نیست."),
)

rule(
    "SEC-SECRET-HIGH-ENTROPY-STRING",
    "secrets", "secret_leak", "medium", confidence=0.55,
    heuristic="high_entropy_assignment", redactable=True,
    cwe=("CWE-798",), tags=("entropy", "credential", "heuristic"),
    title=("High-entropy string assigned to a credential-like variable",
           "رشته با آنتروپی بالا به متغیر شبیه اعتبارنامه اختصاص یافته است"),
    description=("A long, high-entropy literal (random-looking characters) is assigned on this line. "
                 "Such values are often generated secrets, keys or tokens.",
                 "یک مقدار ثابت بلند با آنتروپی بالا (نویسه‌های تصادفی‌گونه) در این سطر اختصاص یافته است. "
                 "چنین مقادیری اغلب رازها، کلیدها یا توکن‌های تولیدشده‌اند."),
    remediation=("Confirm the value is not a live secret; if it is, rotate it and load it from the "
                 "environment.",
                 "تأیید کنید مقدار، راز زنده نیست؛ در صورت زنده بودن، آن را بچرخانید و از محیط بارگذاری کنید."),
)

rule(
    "SEC-SECRET-ENV-FILE",
    "secrets", "secret_leak", "high", confidence=0.85,
    patterns=[r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S.{2,}$"],
    target="file",
    include=("**/.env", "**/.env.*", "**/*.env", "**/env.local", "**/.envrc"),
    exclude=("**/.env.example", "**/.env.sample", "**/.env.template", "**/.env.dist"),
    cwe=("CWE-522", "CWE-312"), tags=("dotenv", "environment"),
    title=("Environment file with values committed", "فایل محیط همراه با مقادیر درج شده است"),
    description=("A .env-style file containing KEY=value pairs is part of the change. These files "
                 "usually hold live configuration secrets.",
                 "فایلی به سبک .env شامل جفت‌های KEY=value بخشی از تغییرات است. این فایل‌ها معمولاً رازهای "
                 "پیکربندی زنده را نگه می‌دارند."),
    remediation=("Remove the file from the commit and history, keep a .env.example with placeholders, "
                 "and add .env to .gitignore.",
                 "فایل را از کامیت و تاریخچه حذف کنید، یک .env.example با مقادیر نمونه نگه دارید و .env را "
                 "به .gitignore اضافه کنید."),
)

rule(
    "SEC-SECRET-CREDENTIAL-FILE-ADDED",
    "secrets", "secret_leak", "high", confidence=0.8,
    heuristic="credential_file_added",
    cwe=("CWE-522",), tags=("credential-file"),
    title=("Credential/key file added to the repository",
           "فایل اعتبارنامه/کلید به مخزن افزوده شده است"),
    description=("A file whose name indicates credentials (credentials.json, *.pem, *.key, id_rsa, "
                 ".netrc, .pypirc, keystore...) was added.",
                 "فایلی که نامش نشان‌دهنده اعتبارنامه است (credentials.json، *.pem، *.key، id_rsa، "
                 ".netrc، .pypirc، keystore و...) افزوده شده است."),
    remediation=("Remove the file, add its pattern to .gitignore and rotate anything it contained.",
                 "فایل را حذف کنید، الگوی آن را به .gitignore اضافه کنید و هرچه در آن بوده را بچرخانید."),
)

rule(
    "SEC-SECRET-AUTH-HEADER",
    "secrets", "secret_leak", "high", confidence=0.8, redactable=True,
    patterns=[r"(?i)(?:authorization|proxy-authorization)\s*[:=]\s*['\"]?(?:basic|bearer)\s+[A-Za-z0-9+/=:_\-]{8,}"],
    negative=[NEG_EXAMPLE[0]],
    cwe=("CWE-798",), tags=("http", "header", "credential"),
    title=("Hardcoded Authorization header", "سربرگ Authorization سخت‌کد شده"),
    description=("A Basic/Bearer Authorization value is written literally in code or config.",
                 "مقدار Basic/Bearer سربرگ Authorization به‌صورت ثابت در کد یا پیکربندی نوشته شده است."),
    remediation=("Load the header value from the environment at request time.",
                 "مقدار سربرگ را در زمان درخواست از محیط بارگذاری کنید."),
)

rule(
    "SEC-SECRET-GOOGLE-API-KEY",
    "secrets", "secret_leak", "high", confidence=0.85, redactable=True,
    patterns=[r"\bAIza[0-9A-Za-z_\-]{35}\b"],
    negative=[r"(?i)(example|sample|dummy|xxxx)"],
    cwe=("CWE-798",), tags=("google", "credential"),
    title=("Google API key committed", "کلید API گوگل درج شده است"),
    description=("A Google API key (AIza...) was added. Unrestricted keys can be abused for quota and "
                 "billing.",
                 "کلید API گوگل با پیشوند AIza افزوده شده است. کلیدهای بدون محدودیت قابل سوءاستفاده برای "
                 "سهمیه و صورتحساب‌اند."),
    remediation=("Restrict the key (HTTP referrers/IPs/APIs) or rotate it in Google Cloud Console.",
                 "کلید را محدود کنید (ارجاع‌دهنده/IP/API) یا در کنسول Google Cloud بچرخانید."),
)

rule(
    "SEC-SECRET-HUGGINGFACE-TOKEN",
    "secrets", "secret_leak", "high", confidence=0.9, redactable=True,
    patterns=[r"\bhf_[A-Za-z0-9]{30,}\b"],
    cwe=("CWE-798",), tags=("huggingface", "llm", "credential"),
    title=("Hugging Face token committed", "توکن Hugging Face درج شده است"),
    description=("A Hugging Face access token (hf_...) was added.", "توکن دسترسی Hugging Face افزوده شده است."),
    remediation=("Revoke the token in HF settings and use a scoped, read-only token in CI.",
                 "توکن را در تنظیمات HF باطل کنید و در CI از توکن فقط‌خواندنی استفاده کنید."),
)

rule(
    "SEC-SECRET-TELEGRAM-BOT-TOKEN",
    "secrets", "secret_leak", "high", confidence=0.9, redactable=True,
    patterns=[r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b"],
    cwe=("CWE-798",), tags=("telegram", "credential"),
    title=("Telegram bot token committed", "توکن ربات تلگرام درج شده است"),
    description=("A Telegram bot token was added; it grants full control of the bot.",
                 "توکن ربات تلگرام افزوده شده که کنترل کامل ربات را می‌دهد."),
    remediation=("Regenerate the token with @BotFather.", "توکن را با BotFather بازسازی کنید."),
)

rule(
    "SEC-SECRET-DISCORD-WEBHOOK",
    "secrets", "secret_leak", "high", confidence=0.9, redactable=True,
    patterns=[r"discord(?:app)?\.com/api/webhooks/\d{17,}/[A-Za-z0-9_\-]{20,}"],
    cwe=("CWE-798",), tags=("discord", "webhook"),
    title=("Discord webhook URL committed", "آدرس وب‌هوک Discord درج شده است"),
    description=("A Discord webhook was added; anyone with it can post to the channel.",
                 "وب‌هوک Discord افزوده شده که هر دارنده آن می‌تواند در کانال پیام بفرستد."),
    remediation=("Delete the webhook in channel settings.", "وب‌هوک را در تنظیمات کانال حذف کنید."),
)

rule(
    "SEC-SECRET-TWILIO-CREDENTIAL",
    "secrets", "secret_leak", "high", confidence=0.8, redactable=True,
    patterns=[r"(?i)twilio.{0,40}(?:auth[_-]?token|account[_-]?sid)\s*[:=]\s*['\"]?[A-Za-z0-9]{20,}"],
    negative=[NEG_EXAMPLE[0]],
    cwe=("CWE-798",), tags=("twilio", "credential"),
    title=("Twilio credential committed", "اعتبارنامه Twilio درج شده است"),
    description=("A Twilio auth token or account SID was added.", "توکن احراز هویت یا SID حساب Twilio افزوده شده است."),
    remediation=("Rotate the auth token in the Twilio console.", "توکن را در کنسول Twilio بچرخانید."),
)

rule(
    "SEC-SECRET-DOCKER-REGISTRY-AUTH",
    "secrets", "secret_leak", "high", confidence=0.85, redactable=True,
    patterns=[r"(?i)\"auth\"\s*:\s*\"[A-Za-z0-9+/=]{16,}\""],
    include=("**/config.json", "**/.dockerconfigjson", "**/docker/config.json"),
    cwe=("CWE-798",), tags=("docker", "registry", "credential"),
    title=("Docker registry auth blob committed", "بلاب احراز هویت رجیستری داکر درج شده است"),
    description=("A base64 username:password blob from a Docker config.json was added.",
                 "بلاب base64 کاربر:رمز از config.json داکر افزوده شده است."),
    remediation=("Remove the file and use credential helpers or CI secret injection.",
                 "فایل را حذف کنید و از کمک‌کننده اعتبار یا تزریق راز CI استفاده کنید."),
)

rule(
    "SEC-SECRET-HEROKU-API-KEY",
    "secrets", "secret_leak", "high", confidence=0.8, redactable=True,
    patterns=[r"(?i)heroku.{0,20}(?:api[_-]?key|token)\s*[:=]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"],
    cwe=("CWE-798",), tags=("heroku", "credential"),
    title=("Heroku API key committed", "کلید API Heroku درج شده است"),
    description=("A Heroku API key was added; it can deploy and modify your apps.",
                 "کلید API Heroku افزوده شده که می‌تواند اپ‌های شما را مستقر و تغییر دهد."),
    remediation=("Regenerate the key in Heroku account settings.", "کلید را در تنظیمات حساب Heroku بازسازی کنید."),
)

# -------------------------------------------------------------- dangerous ---

rule(
    "DGR-REMOVE-RECURSIVE-ROOT",
    "dangerous", "dangerous_operation", "critical", confidence=0.9,
    patterns=[
        r"\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:/[ \t]*(?:$|;|&&|\|)|~[ \t]*(?:$|;|&&|\|)|\*[ \t]*(?:$|;|&&|\|))",
        r"\brm\s+-rf\s+/(?:\s|$|;|&&)",
    ],
    cwe=("CWE-77",), tags=("destructive", "filesystem"),
    title=("Recursive deletion of a filesystem root", "حذف بازگشتی ریشه فایل‌سیستم"),
    description=("The change introduces `rm -rf` (or similar) targeting `/`, `~` or a bare wildcard. "
                 "Executed, this destroys the machine or home directory.",
                 "تغییرات شامل `rm -rf` (یا مشابه) با هدف `/` یا `~` یا wildcard خالی است. در صورت اجرا، "
                 "دستگاه یا پوشه خانگی نابود می‌شود."),
    remediation=("Remove or narrow the command to an explicit, validated directory; never interpolate "
                 "unvalidated variables into destructive paths.",
                 "دستور را حذف یا به یک مسیر صریح و اعتبارسنجی‌شده محدود کنید؛ هرگز متغیر بدون اعتبارسنجی در "
                 "مسیر مخرب درج نکنید."),
)

rule(
    "DGR-REMOVE-RECURSIVE-VARIABLE",
    "dangerous", "dangerous_operation", "high", confidence=0.7,
    patterns=[r"\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+\$\{?[A-Za-z_][A-Za-z0-9_]*\}?(?:/\S*)?[ \t]*(?:$|;|&&|\|)"],
    negative=[r"(?i)(node_modules|\.cache|tmp|temp|build|dist|__pycache__)"],
    cwe=("CWE-77",), tags=("destructive", "filesystem"),
    title=("Recursive delete on an interpolated variable",
           "حذف بازگشتی روی متغیر درج‌شده در مسیر"),
    description=("`rm -rf` targets a shell variable. If the variable is empty or attacker-controlled "
                 "the command deletes far more than intended.",
                 "`rm -rf` روی یک متغیر شل اجرا می‌شود. اگر متغیر خالی یا تحت کنترل مهاجم باشد، بسیار بیشتر "
                 "از حد قصد حذف می‌شود."),
    remediation=("Quote the variable, validate it is non-empty and absolute, or use a dedicated clean-"
                 "up routine with an allow-list.",
                 "متغیر را نقل‌قول کنید، غیرخالی و مطلق بودنش را اعتبارسنجی کنید یا از روال پاک‌سازی با فهرست "
                 "مجاز استفاده کنید."),
)

rule(
    "DGR-DD-TO-DEVICE",
    "dangerous", "dangerous_operation", "critical", confidence=0.95,
    patterns=[r"\bdd\s+[^\n|]*\bof=/dev/(?:sd[a-z]|hd[a-z]|nvme|disk|md)[0-9a-z]*"],
    cwe=("CWE-77",), tags=("destructive", "disk"),
    title=("Raw write to a block device (`dd of=/dev/...`)",
           "نوشتن خام روی دستگاه بلوکی (`dd of=/dev/...`)"),
    description=("A `dd` command writes directly to a disk device, which overwrites partitions or "
                 "whole disks.",
                 "دستور `dd` مستقیماً روی دستگاه دیسک می‌نویسد و می‌تواند پارتیشن‌ها یا کل دیسک را بازنویسی کند."),
    remediation=("Only keep such commands behind explicit operator confirmation with a validated "
                 "device path.",
                 "چنین دستورهایی را فقط پشت تأیید صریح کاربر و با مسیر دستگاه اعتبارسنجی‌شده نگه دارید."),
)

rule(
    "DGR-MKFS",
    "dangerous", "dangerous_operation", "critical", confidence=0.95,
    patterns=[r"\bmkfs(?:\.[a-z0-9]+)?\s+(?:-[a-zA-Z]+\s+)*(?:/dev/|[A-Za-z]:\\)"],
    cwe=("CWE-77",), tags=("destructive", "filesystem"),
    title=("Filesystem format command introduced", "دستور فرمت فایل‌سیستم افزوده شده است"),
    description=("`mkfs` irreversibly erases a volume.", "`mkfs` یک حجم را به‌طور برگشت‌ناپذیر پاک می‌کند."),
    remediation=("Remove it from automated flows; formatting must be a manual, confirmed operation.",
                 "آن را از جریان‌های خودکار حذف کنید؛ فرمت باید عملیات دستی و تأییدشده باشد."),
)

rule(
    "DGR-FORK-BOMB",
    "dangerous", "dangerous_operation", "critical", confidence=0.98,
    patterns=[r":\s*\(\s*\)\s*\{[^}]*\|[^}]*&[^}]*\}\s*;"],
    cwe=("CWE-400",), tags=("dos", "malware"),
    title=("Fork bomb pattern detected", "الگوی بمب فورک شناسایی شد"),
    description=("The classic self-replicating function `:(){ :|:& };:` (or a variant) was added. It "
                 "exhausts process table and hangs the machine.",
                 "تابع خودتکثیر کلاسیک `:(){ :|:& };:` (یا گونه‌ای از آن) افزوده شده که جدول فرایندها را پر و "
                 "دستگاه را قفل می‌کند."),
    remediation=("Delete immediately and treat the change as hostile.",
                 "فوراً حذف کنید و تغییر را خصمانه تلقی کنید."),
)

rule(
    "DGR-CHMOD-777",
    "dangerous", "dangerous_operation", "high", confidence=0.8,
    patterns=[r"\bchmod\s+(?:-[a-zA-Z]+\s+)*777\b"],
    cwe=("CWE-732",), tags=("permissions"),
    title=("World-writable permissions (chmod 777)", "مجوز نوشتن برای همه (chmod 777)"),
    description=("chmod 777 makes files writable by every user and process, a classic privilege-"
                 "escalation and tampering vector.",
                 "chmod 777 فایل را برای همه کاربران و فرایندها قابل نوشتن می‌کند؛ بردار کلاسیک ارتقای دسترسی "
                 "و دستکاری."),
    remediation=("Use the least privilege needed (e.g. 0640/0750) and explicit ownership.",
                 "از کمینه مجوز لازم (مثل 0640/0750) و مالکیت صریح استفاده کنید."),
)

rule(
    "DGR-CURL-PIPE-SHELL",
    "dangerous", "dangerous_operation", "high", confidence=0.85,
    patterns=[r"(?:curl|wget)\s+[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"],
    cwe=("CWE-494",), tags=("supply-chain", "remote-exec"),
    title=("Remote script piped into a shell", "اسکریپت راه دور به شل لوله شده است"),
    description=("`curl | sh` (or wget | bash) executes unreviewed remote code, possibly as root with "
                 "sudo.",
                 "`curl | sh` (یا wget | bash) کد راه دور بازبینی‌نشده را اجرا می‌کند، احتمالاً با sudo و "
                 "دسترسی ریشه."),
    remediation=("Download the script, inspect and pin its checksum, then execute the local copy.",
                 "اسکریپت را دانلود و checksum آن را ثابت کنید، سپس نسخه محلی را اجرا کنید."),
)

rule(
    "DGR-POWERSHELL-ENCODED",
    "dangerous", "dangerous_operation", "high", confidence=0.85,
    patterns=[r"(?i)powershell(?:\.exe)?\s+[^\n|;&]*-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{32,}"],
    cwe=("CWE-506",), tags=("obfuscation", "windows"),
    title=("Encoded PowerShell command", "دستور رمزگذاری‌شده PowerShell"),
    description=("An -EncodedCommand payload hides what actually runs; this pattern is common in "
                 "malware and in AI output that copies obfuscated snippets.",
                 "بار -EncodedCommand آنچه واقعاً اجرا می‌شود را پنهان می‌کند؛ این الگو در بدافزار و خروجی‌های "
                 "کپی‌شده مبسوط رایج است."),
    remediation=("Decode and review the payload; replace with plain, readable commands.",
                 "بار را رمزگشایی و بازبینی کنید و با دستورات خوانا جایگزین کنید."),
)

rule(
    "DGR-INVOKE-EXPRESSION",
    "dangerous", "dangerous_operation", "high", confidence=0.8,
    patterns=[r"\b(?:Invoke-Expression|IEX)\s*[\(\s]"],
    cwe=("CWE-95",), tags=("powershell", "injection"),
    title=("Invoke-Expression evaluates dynamic input",
           "Invoke-Expression ورودی پویا را ارزیابی می‌کند"),
    description=("IEX executes arbitrary strings as code and defeats script review.",
                 "IEX رشته‌های دلخواه را به‌عنوان کد اجرا می‌کند و بازبینی اسکریپت را بی‌اثر می‌کند."),
    remediation=("Call commands/operators directly instead of evaluating strings.",
                 "به‌جای ارزیابی رشته‌ها، دستورها را مستقیم فراخوانی کنید."),
)

rule(
    "DGR-POWERSHELL-REMOVE-ROOT",
    "dangerous", "dangerous_operation", "high", confidence=0.85,
    patterns=[
        r"(?i)Remove-Item\s+(?:-[a-zA-Z]+\s+)*(?:/|\\|C:\\|\\\*|\*|\$env:USERPROFILE|\$HOME|\$home)\b",
        r"(?i)Remove-Item\s+(?:-[a-zA-Z]+\s+)*-Recurse\b[^\n|;&]*-Force\b",
    ],
    negative=[r"(?i)(node_modules|\.cache|tmp|temp|\\build|\\dist)"],
    cwe=("CWE-77",), tags=("destructive", "windows"),
    title=("Recursive PowerShell removal of a broad path",
           "حذف بازگشتی PowerShell روی مسیر گسترده"),
    description=("`Remove-Item -Recurse -Force` targets a root, home directory or wildcard.",
                 "`Remove-Item -Recurse -Force` روی ریشه، پوشه خانگی یا wildcard اجرا می‌شود."),
    remediation=("Scope the path explicitly and avoid -Force unless reviewed.",
                 "مسیر را صریح محدود کنید و از -Force بدون بازبینی پرهیز کنید."),
)

rule(
    "DGR-WINDOWS-DISK-FORMAT",
    "dangerous", "dangerous_operation", "high", confidence=0.85,
    patterns=[r"(?i)\bformat\s+(?:/[a-z]+\s+)*[a-z]:\s*(?:/|$|;|&&)", r"(?i)\bdel\s+/[sfq]{1,3}\s+[a-z]:\\"],
    cwe=("CWE-77",), tags=("destructive", "windows"),
    title=("Windows disk format / recursive delete command",
           "دستور فرمت دیسک یا حذف بازگشتی ویندوز"),
    description=("A `format X:` or `del /s /q X:\\` command erases volumes or directory trees.",
                 "دستور `format X:` یا `del /s /q X:\\` حجم‌ها یا درخت پوشه‌ها را پاک می‌کند."),
    remediation=("Remove from automated scripts entirely.", "کاملاً از اسکریپت‌های خودکار حذف کنید."),
)

rule(
    "DGR-REGISTRY-DELETE",
    "dangerous", "dangerous_operation", "high", confidence=0.85,
    patterns=[r"(?i)\breg\s+delete\s+(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\b"],
    cwe=("CWE-77",), tags=("windows", "registry"),
    title=("Windows registry key deletion", "حذف کلید رجیستری ویندوز"),
    description=("Deleting registry keys can disable security features or break the OS.",
                 "حذف کلیدهای رجیستری می‌تواند قابلیت‌های امنیتی را غیرفعال یا سیستم‌عامل را خراب کند."),
    remediation=("Restrict to documented, reviewed keys with backups exported first.",
                 "به کلیدهای مستند و بازبینی‌شده با پشتیبان گیری اولیه محدود کنید."),
)

rule(
    "DGR-DEFENDER-DISABLE",
    "dangerous", "dangerous_operation", "critical", confidence=0.95,
    patterns=[
        r"(?i)Set-MpPreference\s+[^\n|;&]*-DisableRealtimeMonitoring\s+\$?true",
        r"(?i)(?:sc\s+(?:config|stop)|net\s+stop)\s+windefend",
        r"(?i)Set-MpPreference\s+[^\n|;&]*-Disable(?:IOAVProtection|ScriptScanning|BehaviorMonitoring)\s+\$?true",
    ],
    cwe=("CWE-693",), tags=("antivirus", "defense-evasion", "windows"),
    title=("Windows Defender / real-time protection disabled",
           "غیرفعال‌سازی Windows Defender / محافظت بلادرنگ"),
    description=("The change turns off antivirus real-time protection — a hallmark of malware and of "
                 "insecure 'make it work' AI suggestions.",
                 "تغییرات محافظت بلادرنگ آنتی‌ویروس را خاموش می‌کند؛ نشانه بارز بدافزار و پیشنهادهای ناامن "
                 "«راه‌اندازی سریع»."),
    remediation=("Remove these commands; add exclusions for specific paths only if truly required.",
                 "این دستورها را حذف کنید؛ فقط در صورت نیاز واقعی، استثنا برای مسیرهای مشخص اضافه کنید."),
)

rule(
    "DGR-FIREWALL-DISABLE",
    "dangerous", "dangerous_operation", "high", confidence=0.9,
    patterns=[
        r"(?i)\bufw\s+disable\b",
        r"(?i)\biptables\s+-F\b",
        r"(?i)netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off",
        r"(?i)Set-NetFirewallProfile\s+[^\n|;&]*-Enabled\s+False",
    ],
    cwe=("CWE-693",), tags=("firewall", "defense-evasion"),
    title=("Host firewall disabled or rules flushed",
           "فایروال میزبان غیرفعال یا قوانین آن پاک شده است"),
    description=("Disabling the host firewall or flushing iptables removes network protections.",
                 "غیرفعال‌سازی فایروال میزبان یا پاک‌سازی iptables حفاظت‌های شبکه را حذف می‌کند."),
    remediation=("Open only the specific ports needed instead of disabling the firewall.",
                 "به‌جای غیرفعال‌سازی، فقط پورت‌های مشخص مورد نیاز را باز کنید."),
)

rule(
    "DGR-EXECUTION-POLICY-BYPASS",
    "dangerous", "dangerous_operation", "high", confidence=0.85,
    patterns=[r"(?i)Set-ExecutionPolicy\s+(?:-[a-zA-Z]+\s+)*(?:Bypass|Unrestricted)"],
    cwe=("CWE-693",), tags=("windows", "powershell"),
    title=("PowerShell execution policy set to Bypass/Unrestricted",
           "سیاست اجرای PowerShell روی Bypass/Unrestricted"),
    description=("Lowers the script-execution guardrail for the machine or user scope.",
                 "محافظ اجرای اسکریپت را در دامنه دستگاه یا کاربر پایین می‌آورد."),
    remediation=("Prefer per-process `-ExecutionPolicy Bypass` for a single reviewed script, or sign "
                 "scripts.",
                 "برای یک اسکریپت بازبینی‌شده `-ExecutionPolicy Bypass` در سطح فرایند را ترجیح دهید یا "
                 "اسکریپت‌ها را امضا کنید."),
)

rule(
    "DGR-GIT-FORCE-PUSH",
    "dangerous", "dangerous_operation", "medium", confidence=0.8,
    patterns=[r"\bgit\s+push\s+[^\n|;&]*--force\b", r"\bgit\s+push\s+-f\b"],
    negative=[r"--force-with-lease"],
    cwe=("CWE-77",), tags=("git", "destructive"),
    title=("Force push rewrites shared history", "پوش اجباری تاریخچه مشترک را بازنویسی می‌کند"),
    description=("`git push --force` can destroy teammates' commits on the remote branch.",
                 "`git push --force` می‌تواند کامیت‌های هم‌تیمی‌ها را روی شاخه راه دور نابود کند."),
    remediation=("Use --force-with-lease and only on personal branches.",
                 "از --force-with-lease و فقط روی شاخه‌های شخصی استفاده کنید."),
)

rule(
    "DGR-GIT-NO-VERIFY",
    "dangerous", "dangerous_operation", "medium", confidence=0.85,
    patterns=[r"\bgit\s+(?:commit|push|rebase)\b[^\n|;&]*--no-verify\b"],
    cwe=("CWE-693",), tags=("git", "hooks", "defense-evasion"),
    title=("Git hooks bypassed with --no-verify", "رد شدن از هوک‌های Git با --no-verify"),
    description=("Pre-commit/commit-msg hooks (linters, secret scanners, signing) are skipped, which "
                 "is how protected secrets and broken code enter history.",
                 "هوک‌های pre-commit/commit-msg (لینترها، اسکنرهای راز، امضا) رد می‌شوند؛ راهی که رازهای "
                 "محافظت‌شده و کد خراب وارد تاریخچه می‌شوند."),
    remediation=("Fix what the hooks report instead of bypassing them.",
                 "به‌جای رد شدن، آنچه هوک‌ها گزارش می‌کنند را برطرف کنید."),
)

rule(
    "DGR-GIT-RESET-HARD",
    "dangerous", "dangerous_operation", "medium", confidence=0.8,
    patterns=[r"\bgit\s+reset\s+--hard\b", r"\bgit\s+checkout\s+(?:--\s+)?\.\s*$", r"\bgit\s+clean\s+-[a-zA-Z]*f[a-zA-Z]*\b"],
    cwe=("CWE-77",), tags=("git", "destructive"),
    title=("Discarding local work (reset --hard / clean -f)",
           "دور ریختن کار محلی (reset --hard / clean -f)"),
    description=("These commands permanently delete uncommitted changes and untracked files.",
                 "این دستورها تغییرات کامیت‌نشده و فایل‌های ردیابی‌نشده را برای همیشه حذف می‌کنند."),
    remediation=("Stash or back up work first; avoid in shared automation.",
                 "ابتدا کار را stash یا پشتیبان‌گیری کنید؛ در خودکارسازی مشترک پرهیز کنید."),
)

rule(
    "DGR-GIT-HISTORY-REWRITE",
    "dangerous", "dangerous_operation", "high", confidence=0.85,
    patterns=[r"\bgit\s+(?:filter-branch|filter-repo)\b", r"\bgit\s+update-ref\s+-d\b", r"\bgit\s+push\b[^\n|;&]*--mirror\b"],
    cwe=("CWE-77",), tags=("git", "destructive"),
    title=("Git history rewriting / ref deletion", "بازنویسی تاریخچه Git / حذف ref"),
    description=("Rewriting or deleting refs can erase commits for everyone and is often used to hide "
                 "evidence after a bad commit.",
                 "بازنویسی یا حذف ref می‌تواند کامیت‌ها را برای همه پاک کند و اغلب برای پنهان‌کردن شواهد پس از "
                 "یک کامیت بد استفاده می‌شود."),
    remediation=("Only run history rewrites with team agreement and full backups.",
                 "بازنویسی تاریخچه را فقط با توافق تیم و پشتیبان کامل اجرا کنید."),
)

rule(
    "DGR-BASE64-EXEC",
    "dangerous", "dangerous_operation", "high", confidence=0.85,
    patterns=[r"(?:base64\s+(?:-d|--decode)|atob\s*\(|FromBase64String)[^\n|;&]*(?:\|\s*(?:ba|z|da)?sh|eval|Invoke-Expression|IEX)"],
    cwe=("CWE-506",), tags=("obfuscation", "remote-exec"),
    title=("Base64 payload decoded and executed", "بار base64 رمزگشایی و اجرا می‌شود"),
    description=("Decoding a base64 blob straight into a shell/eval hides the executed code from "
                 "review.",
                 "رمزگشایی بلاب base64 مستقیم به شل/eval، کد اجرایی را از بازبینی پنهان می‌کند."),
    remediation=("Decode, review and inline the actual commands.",
                 "بار را رمزگشایی، بازبینی و دستورات واقعی را جایگذاری کنید."),
)

rule(
    "DGR-PERSISTENCE-CRON",
    "dangerous", "dangerous_operation", "high", confidence=0.8,
    patterns=[r"\bcrontab\s+[-]<", r">>\s*/etc/cron", r"(?i)schtasks\s+/create\b"],
    cwe=("CWE-506",), tags=("persistence"),
    title=("Scheduled-task persistence added", "ماندگاری از طریق وظایف زمان‌بندی‌شده افزوده شد"),
    description=("Installing cron entries or scheduled tasks gives code persistence beyond the "
                 "current process.",
                 "نصب ورودی cron یا وظایف زمان‌بندی‌شده به کد ماندگاری فراتر از فرایند فعلی می‌دهد."),
    remediation=("Only schedule reviewed, versioned jobs; document owner and purpose.",
                 "فقط کارهای بازبینی‌شده و نسخه‌دار را زمان‌بندی کنید؛ مالک و هدف را مستند کنید."),
)

rule(
    "DGR-SUDO-IN-SCRIPT",
    "dangerous", "dangerous_operation", "medium", confidence=0.55,
    patterns=[r"^\s*sudo\s+\S+"],
    include=("**/*.sh", "**/*.bash", "**/Dockerfile", "**/Dockerfile.*", "**/*.ps1",
             "**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
    cwe=("CWE-269",), tags=("privilege"),
    title=("Privileged command (sudo) in a script", "دستور با دسترسی بالا (sudo) در اسکریپت"),
    description=("The script runs commands as root. In CI or setup scripts this widens the blast "
                 "radius of any injected or mistaken command.",
                 "اسکریپت دستورها را با کاربر ریشه اجرا می‌کند؛ در CI یا اسکریپت نصب، دامنه آسیب هر دستور "
                 "تزریق‌شده یا اشتباه را بزرگ می‌کند."),
    remediation=("Drop privileges where possible and keep the privileged section minimal and reviewed.",
                 "در امکان دسترسی را کاهش دهید و بخش دارای دسترسی بالا را کمینه و بازبینی‌شده نگه دارید."),
)

rule(
    "DGR-EVAL-EXEC-SHELL",
    "dangerous", "dangerous_operation", "high", confidence=0.7,
    patterns=[
        r"\bos\.system\s*\(",
        r"\bpopen\s*\(",
        r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(",
        r"\bshell_exec\s*\(",
        r"\bexec\s*\(\s*\$\w+",
    ],
    cwe=("CWE-78",), tags=("command-injection"),
    title=("Shell execution of dynamic strings", "اجرای شل روی رشته‌های پویا"),
    description=("Process-spawning APIs that take full command strings invite command injection when "
                 "any part is user- or model-controlled.",
                 "APIهای ایجاد فرایند که رشته دستور کامل می‌گیرند، هرگاه بخشی از آن تحت کنترل کاربر یا مدل "
                 "باشد، تزریق دستور را ممکن می‌کنند."),
    remediation=("Use argument-array process APIs with no shell, and validate/allow-list inputs.",
                 "از API فرایند با آرایه آرگومان بدون شل استفاده کنید و ورودی‌ها را اعتبارسنجی/فهرست‌مجاز کنید."),
)

rule(
    "DGR-SHUTDOWN-REBOOT",
    "dangerous", "dangerous_operation", "medium", confidence=0.75,
    patterns=[r"\bshutdown\s+(?:/[a-z]+\s+)*[/](?:s|r)\b", r"\bshutdown\s+(?:-[a-zA-Z]+\s+)*-[hrP]\b", r"\breboot\s*$", r"\binit\s+[06]\b"],
    cwe=("CWE-77",), tags=("availability"),
    title=("System shutdown / reboot command", "دستور خاموش/راه‌اندازی مجدد سامانه"),
    description=("A shutdown or reboot command was added to code or CI; unexpected reboots cause data "
                 "loss and outages.",
                 "دستور خاموش یا راه‌اندازی مجدد به کد یا CI افزوده شده؛ راه‌اندازی غافلگیر‌کننده باعث از دست "
                 "رفتن داده و قطعی می‌شود."),
    remediation=("Keep reboots out of automation or gate them behind explicit confirmation.",
                 "راه‌اندازی مجدد را از خودکارسازی بیرون نگه دارید یا پشت تأیید صریح قرار دهید."),
)
