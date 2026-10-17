"""Vulnerability-pattern and test-integrity rules."""

from rules_lib import rule

NEG_EXAMPLE = [
    r"(?i)(example|sample|dummy|placeholder|changeme|xxxx|your[-_ ]?"
    r"(key|token|secret|password)|insert[-_ ]?here|<[^>]+>|\$\{)"
]

CODE_INCLUDE = (
    "**/*.py", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.mjs", "**/*.cjs",
    "**/*.go", "**/*.rs", "**/*.java", "**/*.kt", "**/*.rb", "**/*.php", "**/*.cs",
    "**/*.c", "**/*.h", "**/*.cpp", "**/*.hpp", "**/*.scala", "**/*.swift",
)

# --------------------------------------------------------------- security ---

rule(
    "SEC-VULN-SQL-CONCAT",
    "security", "vulnerability", "high", confidence=0.6, require_all=True,
    patterns=[
        r"(?i)(?:execute|executemany|query|raw_query|raw|executeSql|createQuery)\s*\(",
        r"(?:\+\s*[A-Za-z_][A-Za-z0-9_.\[\]'\"]*|%\s*\(|\{[A-Za-z_][A-Za-z0-9_]*\}|\$\{)",
    ],
    negative=[r"(?i)(\?\s*[,)]|:\w+\s*[,)]|params\s*=|prepared|parameterized|\$\d)"],
    include=CODE_INCLUDE,
    cwe=("CWE-89",), tags=("sql", "injection"),
    refs=("https://owasp.org/www-community/attacks/SQL_Injection",),
    title=("SQL statement built by string concatenation",
           "ساخت عبارت SQL با الحاق رشته"),
    description=("A query call receives a string assembled with concatenation/interpolation instead "
                 "of bound parameters — the classic SQL injection sink.",
                 "فراخوانی پرس‌وجو رشته‌ای را می‌گیرد که با الحاق/درون‌یابی ساخته شده نه پارامترهای مقید؛ "
                 "sink کلاسیک تزریق SQL."),
    remediation=("Use parameterized queries (`?`/`:name` placeholders) and never interpolate user or "
                 "model input into SQL.",
                 "از پرس‌وجوهای پارامتری (جای‌نماهای `?` یا `:name`) استفاده کنید و هرگز ورودی کاربر یا مدل را "
                 "در SQL درج نکنید."),
)

rule(
    "SEC-VULN-SQL-FSTRING",
    "security", "vulnerability", "high", confidence=0.75,
    patterns=[r"(?i)f['\"]\s*(?:select|insert\s+into|update|delete\s+from)\b",
              r"(?i)['\"](?:select|insert\s+into|update|delete\s+from)\b[^'\"\n]{0,120}\{\w+\}"],
    negative=[r"(?i)(\?\s*[,)]|:\w+\s*[,)]|params\s*=)"],
    include=CODE_INCLUDE,
    cwe=("CWE-89",), tags=("sql", "injection"),
    title=("SQL query uses f-string / template interpolation",
           "پرس‌وجوی SQL از f-string / درون‌یابی قالب استفاده می‌کند"),
    description=("Interpolated SQL is executable attacker input the moment any variable carries user "
                 "or model-generated data.",
                 "SQL درون‌یابی‌شده به‌محض اینکه متغیری داده کاربر یا مدل را حمل کند، ورودی اجرایی مهاجم است."),
    remediation=("Convert to bound parameters; validate identifiers against an allow-list if dynamic "
                 "columns are unavoidable.",
                 "به پارامترهای مقید تبدیل کنید؛ اگر ستون پویا ناگزیر است، شناسه‌ها را با فهرست مجاز "
                 "اعتبارسنجی کنید."),
)

rule(
    "SEC-VULN-COMMAND-INJECTION",
    "security", "vulnerability", "high", confidence=0.75,
    patterns=[
        r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
        r"child_process\.(?:exec|execSync)\s*\(",
        r"\bexec\s*\(\s*(?:`|\$\{|\+|.*\+\s*\w)",
        r"os\.system\s*\(\s*(?:f?['\"][^'\"]*\{|.*\+)",
    ],
    negative=[r"(?i)(shell\s*=\s*False)"],
    include=CODE_INCLUDE,
    cwe=("CWE-78",), tags=("command-injection"),
    title=("Shell command built from interpolated input",
           "دستور شل ساخته‌شده از ورودی درون‌یابی‌شده"),
    description=("Spawning a shell with a composed command string allows `;`, `&&` or backtick "
                 "injection from any tainted fragment.",
                 "اجرای شل با رشته دستور ترکیبی، تزریق با `;` یا `&&` یا بک‌تیک را از هر بخش آلوده ممکن می‌کند."),
    remediation=("Pass an argument list with shell=False (or execFile) and allow-list every argument.",
                 "فهرست آرگومان با shell=False (یا execFile) بدهید و هر آرگومان را فهرست‌مجاز کنید."),
)

rule(
    "SEC-VULN-XSS-REACT",
    "security", "vulnerability", "medium", confidence=0.85,
    patterns=[r"dangerouslySetInnerHTML"],
    include=("**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"),
    cwe=("CWE-79",), tags=("xss", "react"),
    title=("dangerouslySetInnerHTML injects raw HTML",
           "dangerouslySetInnerHTML اچ‌تی‌ام‌ال خام تزریق می‌کند"),
    description=("Rendering unescaped HTML bypasses React's XSS protection; AI-generated UIs often add "
                 "it for 'markdown previews'.",
                 "رندر HTML بدون escape حفاظت XSS ری‌اکت را دور می‌زند؛ UIهای تولیدشده با هوش مصنوعی اغلب "
                 "برای «پیش‌نمایش مارک‌داون» آن را اضافه می‌کنند."),
    remediation=("Sanitize with DOMPurify (or render structured markup) before injecting.",
                 "پیش از تزریق با DOMPurify پاک‌سازی کنید یا مارک‌آپ ساختاریافته رندر کنید."),
)

rule(
    "SEC-VULN-XSS-DOM",
    "security", "vulnerability", "medium", confidence=0.85,
    patterns=[r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write\s*\(", r"insertAdjacentHTML\s*\("],
    include=("**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.html"),
    cwe=("CWE-79",), tags=("xss", "dom"),
    title=("Direct DOM HTML injection (innerHTML / document.write)",
           "تزریق مستقیم HTML به DOM (innerHTML / document.write)"),
    description=("Assigning strings to innerHTML or calling document.write executes embedded script "
                 "from any tainted source.",
                 "اختصاص رشته به innerHTML یا فراخوانی document.write، اسکریپت جاسازی‌شده از هر منبع آلوده "
                 "را اجرا می‌کند."),
    remediation=("Use textContent / createElement, or sanitize the HTML first.",
                 "از textContent / createElement استفاده کنید یا ابتدا HTML را پاک‌سازی کنید."),
)

rule(
    "SEC-VULN-XSS-VUE",
    "security", "vulnerability", "medium", confidence=0.85,
    patterns=[r"\bv-html\s*="],
    include=("**/*.vue", "**/*.js", "**/*.ts"),
    cwe=("CWE-79",), tags=("xss", "vue"),
    title=("Vue v-html renders unescaped content", "Vue با v-html محتوای بدون escape رندر می‌کند"),
    description=("v-html disables Vue's escaping for that node.", "v-html برای آن گره، escape کردن Vue را غیرفعال می‌کند."),
    remediation=("Sanitize content or use interpolation {{ }}.", "محتوا را پاک‌سازی کنید یا از درون‌یابی {{ }} استفاده کنید."),
)

rule(
    "SEC-VULN-INSECURE-DESER-PY",
    "security", "vulnerability", "high", confidence=0.85,
    patterns=[
        r"\bpickle\.loads?\s*\(", r"\bcPickle\.loads?\s*\(", r"\bmarshal\.loads?\s*\(",
        r"\byaml\.load\s*\(",
        r"\bshelve\.open\s*\(",
    ],
    negative=[r"Loader\s*=\s*yaml\.SafeLoader", r"yaml\.safe_load"],
    include=("**/*.py",),
    cwe=("CWE-502",), tags=("deserialization", "python"),
    title=("Unsafe deserialization (pickle/marshal/yaml.load)",
           "واحدسازی ناامن (pickle/marshal/yaml.load)"),
    description=("Unpickling untrusted data executes arbitrary code; yaml.load without SafeLoader has "
                 "the same class of issue.",
                 "واحدسازی pickle داده نامعتبر کد دلخواه اجرا می‌کند؛ yaml.load بدون SafeLoader هم‌خانواده همین "
                 "مشکل است."),
    remediation=("Use JSON or yaml.safe_load; never deserialize model- or user-supplied blobs with "
                 "pickle.",
                 "از JSON یا yaml.safe_load استفاده کنید؛ هرگز بلاب‌های کاربر/مدل را با pickle واحدسازی نکنید."),
)

rule(
    "SEC-VULN-INSECURE-DESER-JVM",
    "security", "vulnerability", "high", confidence=0.8,
    patterns=[r"new\s+ObjectInputStream\s*\(", r"\bXMLDecoder\s*\(", r"\breadObject\s*\(\s*\)\s*;"],
    include=("**/*.java", "**/*.kt", "**/*.scala"),
    cwe=("CWE-502",), tags=("deserialization", "java"),
    title=("Native Java deserialization of untrusted data",
           "واحدسازی بومی جاوا روی داده نامعتبر"),
    description=("ObjectInputStream/XMLDecoder on attacker-controlled bytes is a well-known RCE path.",
                 "ObjectInputStream/XMLDecoder روی بایت‌های تحت کنترل مهاجم، مسیر شناخته‌شده RCE است."),
    remediation=("Use a safe data format (JSON/protobuf) or an allow-listing serialization filter.",
                 "از قالب داده امن (JSON/protobuf) یا فیلتر سریال‌سازی فهرست‌مجاز استفاده کنید."),
)

rule(
    "SEC-VULN-INSECURE-DESER-PHP",
    "security", "vulnerability", "high", confidence=0.8,
    patterns=[r"\bunserialize\s*\("],
    include=("**/*.php",),
    cwe=("CWE-502",), tags=("deserialization", "php"),
    title=("PHP unserialize on external data", "unserialize پی‌اچ‌پی روی داده خارجی"),
    description=("unserialize() on request data enables object-injection gadgets.",
                 "unserialize() روی داده درخواست، گجت‌های تزریق شیء را فعال می‌کند."),
    remediation=("Use json_decode with validated schemas.", "از json_decode با اسکیماهای اعتبارسنجی‌شده استفاده کنید."),
)

rule(
    "SEC-VULN-PATH-TRAVERSAL",
    "security", "vulnerability", "medium", confidence=0.55,
    patterns=[
        r"(?:req|request)\.(?:query|params|body|args|form)\b[^\n;]{0,80}(?:\.\.|path\.join|fs\.|open\s*\(|readFile|sendFile)",
        r"(?:sendFile|readFile|createReadStream)\s*\(\s*(?:req|request)\.",
    ],
    include=CODE_INCLUDE,
    cwe=("CWE-22",), tags=("path-traversal"),
    title=("User input flows into a filesystem path",
           "ورودی کاربر به مسیر فایل‌سیستم جاری می‌شود"),
    description=("Request data reaches file APIs without canonicalization, allowing ../../ escapes out "
                 "of the intended directory.",
                 "داده درخواست بدون نرمال‌سازی به APIهای فایل می‌رسد و گریز ../../ از پوشه مورد نظر ممکن می‌شود."),
    remediation=("Resolve the path and assert it stays inside the allowed root; reject `..` sequences.",
                 "مسیر را resolve کنید و بررسی کنید داخل ریشه مجاز می‌ماند؛ توالی‌های `..` را رد کنید."),
)

rule(
    "SEC-VULN-WEAK-HASH",
    "security", "vulnerability", "medium", confidence=0.7,
    patterns=[r"\bhashlib\.(?:md5|sha1)\s*\(", r"\bMD5\.Create\s*\(", r"\bSHA1\.Create\s*\(",
              r"\bDigestUtils\.(?:md5|sha1)", r"\bmd5\s*\(\s*[^)\n]*(?:password|passwd|pwd|secret)"],
    negative=[r"(?i)(checksum|etag|cache[-_ ]?key|fingerprint|dedup|integrity)"],
    include=CODE_INCLUDE,
    cwe=("CWE-328",), tags=("crypto", "hashing"),
    title=("Weak hash algorithm (MD5/SHA-1)", "الگوریتم هش ضعیف (MD5/SHA-1)"),
    description=("MD5/SHA-1 are broken for security purposes; for passwords they are trivially "
                 "brute-forced.",
                 "MD5/SHA-1 برای مقاصد امنیتی شکسته‌اند و برای رمز عبور به‌سادگی قابل جست‌وجوی فراگیرند."),
    remediation=("Use SHA-256+ for integrity and bcrypt/argon2/scrypt for passwords.",
                 "برای یکپارچگی SHA-256 به بالا و برای رمز عبور bcrypt/argon2/scrypt استفاده کنید."),
)

rule(
    "SEC-VULN-WEAK-CIPHER",
    "security", "vulnerability", "high", confidence=0.8,
    patterns=[r"[\"'](?:AES|DES(?:ede)?|Blowfish)/(?:ECB|NoPadding)", r"\bgetInstance\s*\(\s*[\"']DES",
              r"\bDESede\b", r"rc4\b"],
    include=CODE_INCLUDE,
    cwe=("CWE-327",), tags=("crypto", "cipher"),
    title=("Weak or ECB-mode cipher", "رمزنگاری ضعیف یا حالت ECB"),
    description=("ECB mode leaks plaintext patterns; DES/3DES/RC4 are deprecated.",
                 "حالت ECB الگوهای متن آشکار را لو می‌دهد؛ DES/3DES/RC4 منسوخ‌اند."),
    remediation=("Use AES-GCM or ChaCha20-Poly1305 with unique nonces.",
                 "از AES-GCM یا ChaCha20-Poly1305 با nonce یکتا استفاده کنید."),
)

rule(
    "SEC-VULN-INSECURE-RANDOM",
    "security", "vulnerability", "high", confidence=0.75,
    patterns=[
        r"Math\.random\s*\(\s*\)[^\n;]{0,60}(?:token|session|csrf|password|secret|nonce|otp|key)",
        r"(?:token|session|csrf|password|secret|nonce|otp)[^\n;]{0,40}(?:Math\.random|\brand\s*\(|random\.random\s*\(|mt_rand\s*\()",
        r"\brand\s*\(\s*\)[^\n;]{0,40}(?:token|secret|password|nonce)",
    ],
    include=CODE_INCLUDE,
    cwe=("CWE-338",), tags=("crypto", "random"),
    title=("Non-cryptographic RNG used for a security value",
           "تولیدکننده اعداد شبه‌تصادفی غیررمزنگاری برای مقدار امنیتی"),
    description=("Math.random / rand() are predictable; tokens built from them can be guessed.",
                 "Math.random و rand() قابل پیش‌بینی‌اند؛ توکن‌های ساخته‌شده با آن‌ها قابل حدس‌اند."),
    remediation=("Use crypto.randomBytes / secrets.token_urlsafe / SecureRandom.",
                 "از crypto.randomBytes یا secrets.token_urlsafe یا SecureRandom استفاده کنید."),
)

rule(
    "SEC-VULN-HARDCODED-CRYPTO-KEY",
    "security", "vulnerability", "high", confidence=0.8, redactable=True,
    patterns=[r"(?i)(?:aes|cipher|encryption|signing|hmac)[-_ ]?key\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"],
    negative=[NEG_EXAMPLE[0], r"(?i)(process\.env|getenv|os\.environ|import\.meta)"],
    include=CODE_INCLUDE,
    cwe=("CWE-321",), tags=("crypto", "key-management"),
    title=("Hardcoded cryptographic key", "کلید رمزنگاری سخت‌کد شده"),
    description=("An encryption/signing key literal is embedded in source; every checkout leaks it.",
                 "کلید رمزنگاری/امضا به‌صورت ثابت در سورس جاسازی شده و هر بررسی مخزن آن را فاش می‌کند."),
    remediation=("Load keys from a KMS/secret manager and rotate the exposed key.",
                 "کلیدها را از KMS/مدیریت راز بارگذاری کنید و کلید فاش‌شده را بچرخانید."),
)

rule(
    "SEC-VULN-TLS-VERIFY-DISABLED",
    "security", "vulnerability", "high", confidence=0.9,
    patterns=[
        r"\bverify\s*=\s*False\b",
        r"(?i)checkCertificate\s*:\s*false",
        r"(?i)InsecureSkipVerify\s*:\s*true",
        r"danger_accept_invalid_certs\s*\(\s*true\s*\)",
        r"(?i)CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)",
        r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
        r"(?i)ssl\.verify\s*=\s*false",
        r"(?i)trustAllCerts|TrustAllCertificates|ALLOW_ALL_HOSTNAME_VERIFIER",
    ],
    negative=[r"(?i)(test|localhost|127\.0\.0\.1)" ],
    include=("**",),
    cwe=("CWE-295",), tags=("tls", "mitm"),
    title=("TLS certificate verification disabled", "اعتبارسنجی گواهی TLS غیرفعال شده است"),
    description=("Disabling certificate checks makes every HTTPS call MITM-able, including calls that "
                 "carry credentials.",
                 "غیرفعال‌سازی بررسی گواهی، همه فراخوانی‌های HTTPS را در برابر MITM آسیب‌پذیر می‌کند؛ از جمله "
                 "فراخوانی‌هایی که اعتبارنامه حمل می‌کنند."),
    remediation=("Remove the override; for internal CAs add the CA bundle to the trust store instead.",
                 "بازنویسی را حذف کنید؛ برای CA داخلی، بسته CA را به مخزن اعتماد اضافه کنید."),
)

rule(
    "SEC-VULN-OLD-TLS-PROTOCOL",
    "security", "vulnerability", "medium", confidence=0.8,
    patterns=[r"\bSSLv[23]\b", r"\bTLSv1_0\b", r"\bTLSv1_1\b", r"PROTOCOL_SSLv23",
              r"(?i)tls_minimum_version\s*[:=]\s*(?:TLSv1_0|TLSv1_1|SSLv3)"],
    include=("**",),
    cwe=("CWE-326",), tags=("tls"),
    title=("Deprecated TLS/SSL protocol version", "نسخه پروتکل منسوخ TLS/SSL"),
    description=("SSLv2/SSLv3/TLS1.0/TLS1.1 have known attacks and fail compliance checks.",
                 "SSLv2/SSLv3/TLS1.0/TLS1.1 حملات شناخته‌شده دارند و بررسی‌های انطباق را رد می‌کنند."),
    remediation=("Require TLS 1.2 or 1.3.", "TLS 1.2 یا 1.3 را الزامی کنید."),
)

rule(
    "SEC-VULN-CORS-WILDCARD",
    "security", "vulnerability", "medium", confidence=0.8,
    patterns=[r"(?i)Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']?\*",
              r"(?i)cors\s*\(\s*\)|origin\s*:\s*[\"']\*[\"']"],
    include=("**",),
    cwe=("CWE-942",), tags=("cors"),
    title=("CORS allows any origin", "CORS هر مبدأی را مجاز می‌کند"),
    description=("A wildcard CORS origin lets any website read responses from this endpoint in "
                 "victims' browsers.",
                 "مبدأ wildcard در CORS به هر وب‌گاهی اجازه می‌دهد پاسخ‌های این نقطه پایانی را در مرورگر قربانی "
                 "بخواند."),
    remediation=("Allow-list exact origins; never combine `*` with credentials.",
                 "مبدأهای دقیق را فهرست‌مجاز کنید؛ هرگز `*` را با اعتبارنامه ترکیب نکنید."),
)

rule(
    "SEC-VULN-CORS-WILDCARD-CREDENTIALS",
    "security", "vulnerability", "high", confidence=0.85, require_all=True,
    patterns=[
        r"(?i)Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']?\*",
        r"(?i)Access-Control-Allow-Credentials[\"']?\s*[:=]\s*(?:true|True|\"true\")",
    ],
    include=("**",),
    cwe=("CWE-942",), tags=("cors", "credentials"),
    title=("Wildcard CORS combined with credentials", "CORS wildcard همراه با اعتبارنامه"),
    description=("This combination allows any site to make authenticated cross-origin requests.",
                 "این ترکیب به هر وب‌گاهی اجازه درخواست‌های احرازهویتی بین‌مبدأی می‌دهد."),
    remediation=("Echo a validated origin from an allow-list when credentials are required.",
                 "هنگام نیاز به اعتبارنامه، مبدأ اعتبارسنجی‌شده از فهرست مجاز را بازگردانید."),
)

rule(
    "SEC-VULN-DEBUG-MODE",
    "security", "vulnerability", "medium", confidence=0.65,
    patterns=[r"app\.run\s*\([^)]*debug\s*=\s*True", r"\bDEBUG\s*=\s*(?:True|true)\b",
              r"(?i)debug\s*:\s*true\b", r"\bFlask\s*\([^)]*debug\s*=\s*True"],
    negative=[r"(?i)(false|0\b|process\.env|getenv|os\.environ|import\.meta)"],
    include=("**/*.py", "**/*.js", "**/*.ts", "**/*.rb", "**/*.php", "**/*.java",
             "**/settings.py", "**/config.*"),
    cwe=("CWE-489",), tags=("debug", "info-leak"),
    title=("Debug mode enabled", "حالت اشکال‌زدایی فعال شده است"),
    description=("Debug modes expose stack traces, and in Flask/Werkzeug an interactive console that "
                 "is effectively RCE.",
                 "حالت اشکال‌زدایی stack trace و در Flask/Werkzeug کنسول تعاملی فاش می‌کند که عملاً RCE است."),
    remediation=("Disable debug outside local development via environment configuration.",
                 "اشکال‌زدایی را بیرون از توسعه محلی از طریق پیکربندی محیط غیرفعال کنید."),
)

rule(
    "SEC-VULN-CREDENTIALS-IN-URL",
    "security", "vulnerability", "high", confidence=0.85, redactable=True,
    patterns=[r"https?://[^\s'\"@/]+:[^\s'\"@/]+@[^\s'\"@]+"],
    negative=[r"(?i)(user:pass@localhost|username:password@example|<user>:<pass>)"],
    include=("**",),
    cwe=("CWE-598", "CWE-200"), tags=("credential", "url"),
    title=("Credentials embedded in a URL", "اعتبارنامه جاسازی‌شده در آدرس"),
    description=("user:password@host URLs leak through logs, proxies, referrers and history.",
                 "آدرس‌های کاربر:رمز@میزبان از طریق لاگ‌ها، پروکسی‌ها، referrer و تاریخچه لو می‌روند."),
    remediation=("Move credentials to headers or environment-driven connection settings.",
                 "اعتبارنامه را به سربرگ‌ها یا تنظیمات اتصال مبتنی بر محیط منتقل کنید."),
)

rule(
    "SEC-VULN-HARDCODED-PASSWORD",
    "security", "vulnerability", "high", confidence=0.7, redactable=True,
    patterns=[r"(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"],
    negative=[NEG_EXAMPLE[0], r"(?i)(process\.env|getenv|os\.environ|import\.meta|input\(|prompt|read\(|readline|argv|getpass)"],
    include=("**",),
    cwe=("CWE-798",), tags=("credential", "password"),
    title=("Hardcoded password literal", "رمز عبور ثابت سخت‌کد شده"),
    description=("A password-like literal value was added to code or configuration.",
                 "مقدار ثابتی شبیه رمز عبور به کد یا پیکربندی افزوده شده است."),
    remediation=("Read the password from the environment or a secret manager.",
                 "رمز را از محیط یا مدیریت راز بخوانید."),
)

rule(
    "SEC-VULN-JWT-NONE-ALG",
    "security", "vulnerability", "critical", confidence=0.9,
    patterns=[r"(?i)alg[\"']?\s*[:=]\s*[\"']none[\"']",
              r"(?i)algorithms\s*=\s*\[?\s*[\"']none[\"']",
              r"(?i)verify_signature\s*=\s*False"],
    include=("**",),
    cwe=("CWE-347",), tags=("jwt", "auth"),
    title=("JWT signature verification weakened (`alg: none`)",
           "ضعیف‌سازی راستی‌آزمایی امضای JWT (`alg: none`)"),
    description=("Accepting unsigned tokens (or skipping verification) lets anyone mint admin tokens.",
                 "پذیرش توکن بدون امضا (یا رد شدن از راستی‌آزمایی) به هر کسی اجازه ساخت توکن مدیر می‌دهد."),
    remediation=("Validate with an explicit algorithm allow-list and a pinned key.",
                 "با فهرست مجاز الگوریتم صریح و کلید ثابت راستی‌آزمایی کنید."),
)

rule(
    "SEC-VULN-OPEN-REDIRECT",
    "security", "vulnerability", "medium", confidence=0.6,
    patterns=[r"(?:redirect|res\.redirect|window\.location(?:\.href)?\s*=|navigate\s*\()\s*\(?\s*(?:req|request|params|query|searchParams|url\b)"],
    negative=[r"(?i)(allow[-_ ]?list|whitelist|startsWith\s*\(\s*['\"]/|new\s+URL)"],
    include=CODE_INCLUDE,
    cwe=("CWE-601",), tags=("redirect"),
    title=("Unvalidated redirect target", "مقصود تغییرمسیر بدون اعتبارسنجی"),
    description=("Redirecting to a request-controlled URL enables phishing through your trusted "
                 "domain.",
                 "تغییرمسیر به آدرس کنترل‌شده توسط درخواست، فیشینگ با دامنه مورد اعتماد شما را ممکن می‌کند."),
    remediation=("Validate against an allow-list of paths/origins before redirecting.",
                 "پیش از تغییرمسیر، مقابل فهرست مجاز مسیر/مبدأ اعتبارسنجی کنید."),
)

rule(
    "SEC-VULN-XXE",
    "security", "vulnerability", "medium", confidence=0.7,
    patterns=[r"\bXMLParser\s*\(", r"\bDocumentBuilderFactory\.newInstance\s*\(", r"\betree\.parse\s*\(", r"\bSAXParser\s*\("],
    negative=[r"(?i)(setFeature|disallow-doctype|resolve_entities\s*=\s*False|defused|FEATURE_SECURE)"],
    include=CODE_INCLUDE,
    cwe=("CWE-611",), tags=("xxe", "xml"),
    title=("XML parsed without disabling external entities",
           "تجزیه XML بدون غیرفعال‌سازی موجودیت‌های خارجی"),
    description=("Default XML parsers may resolve external entities, enabling file reads and SSRF.",
                 "تجزیه‌کننده‌های پیش‌فرض XML ممکن است موجودیت‌های خارجی را resolve کنند و خواندن فایل و SSRF "
                 "را ممکن سازند."),
    remediation=("Disable DTDs/external entities or use a hardened parser (defusedxml).",
                 "DTD/موجودیت‌های خارجی را غیرفعال کنید یا از تجزیه‌کننده سخت‌شده (defusedxml) استفاده کنید."),
)

rule(
    "SEC-VULN-POSTMESSAGE-STAR",
    "security", "vulnerability", "medium", confidence=0.8,
    patterns=[r"postMessage\s*\([^)]*,\s*[\"']\*[\"']\s*\)"],
    include=("**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx", "**/*.html"),
    cwe=("CWE-346",), tags=("postmessage"),
    title=("postMessage with wildcard target origin", "postMessage با مبدأ مقصد wildcard"),
    description=("Sending messages to `*` leaks them to whichever window ended up in the frame.",
                 "ارسال پیام به `*` آن را به هر پنجره‌ای که در قاب قرار گرفته لو می‌دهد."),
    remediation=("Specify the exact expected origin.", "مبدأ مورد انتظار دقیق را مشخص کنید."),
)

rule(
    "SEC-VULN-LOCALSTORAGE-SECRET",
    "security", "vulnerability", "medium", confidence=0.8,
    patterns=[r"localStorage\.setItem\s*\(\s*[\"'](?:[^\"']*(?:token|jwt|session|api[_-]?key|secret|refresh)[^\"']*)[\"']"],
    include=("**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"),
    cwe=("CWE-922",), tags=("storage", "xss"),
    title=("Sensitive token stored in localStorage", "توکن حساس در localStorage ذخیره می‌شود"),
    description=("localStorage is readable by any XSS, so tokens stored there are one injection away "
                 "from exfiltration.",
                 "localStorage برای هر XSS خواندنی است؛ پس توکن‌های ذخیره‌شده در آن یک تزریق تا افشا فاصله دارند."),
    remediation=("Prefer httpOnly Secure cookies or in-memory storage with refresh rotation.",
                 "کوکی‌های httpOnly Secure یا حافظه موقت با چرخش refresh را ترجیح دهید."),
)

rule(
    "SEC-VULN-PLAIN-HTTP-ENDPOINT",
    "security", "vulnerability", "low", confidence=0.5,
    patterns=[r"http://[a-z0-9.\-]+(?:\.[a-z]{2,})(?::\d+)?/(?:api|auth|login|token|upload|webhook)"],
    negative=[r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.|test|schema|xmlns|xml\.apache\.org|www\.w3\.org)"],
    include=("**",),
    cwe=("CWE-319",), tags=("tls", "transport"),
    title=("Cleartext HTTP used for an API endpoint", "استفاده از HTTP بدون رمزنگاری برای نقطه API"),
    description=("Traffic to this endpoint (credentials, tokens, payloads) travels unencrypted.",
                 "ترافیک این نقطه پایانی (اعتبارنامه‌ها، توکن‌ها، بارها) بدون رمزنگاری جابه‌جا می‌شود."),
    remediation=("Use https:// and fail closed on certificate errors.",
                 "از https:// استفاده کنید و در خطای گواهی، اتصال را قطع کنید."),
)

rule(
    "SEC-VULN-BIND-ALL-INTERFACES",
    "security", "vulnerability", "low", confidence=0.6,
    patterns=[r"(?i)(?:host|listen|bind|address)\s*[:=]\s*[\"']0\.0\.0\.0[\"']", r"\blisten\s*\(\s*[\"']?0\.0\.0\.0"],
    include=("**",),
    cwe=("CWE-668",), tags=("network", "exposure"),
    title=("Service binds to all network interfaces", "سرویس روی همه رابط‌های شبکه bind می‌شود"),
    description=("Binding 0.0.0.0 exposes a development/service port to the whole network by default.",
                 "bind روی 0.0.0.0 پورت توسعه/سرویس را به‌صورت پیش‌فرض روی کل شبکه باز می‌کند."),
    remediation=("Bind to 127.0.0.1 unless external exposure is intended and protected.",
                 "مگر اینکه دسترسی خارجی عمدی و محافظت‌شده باشد، سرویس را روی 127.0.0.1 بایند کنید."),
)

rule(
    "SEC-VULN-EVAL-DYNAMIC",
    "security", "vulnerability", "high", confidence=0.75,
    patterns=[
        r"\beval\s*\(\s*(?:req|request|user|input|data|params|event|body|query)",
        r"new\s+Function\s*\(\s*(?:req|user|input|data|body)",
        r"\bsetTimeout\s*\(\s*[\"'][^\"']*[\"']\s*,",
        r"\bvm\.runIn\w+\s*\(\s*(?:req|user|input|data)",
    ],
    include=CODE_INCLUDE,
    cwe=("CWE-95",), tags=("code-injection"),
    title=("Dynamic code evaluation of external input", "ارزیابی پویای کد ورودی خارجی"),
    description=("eval/new Function/vm with tainted input yields direct code execution.",
                 "eval/new Function/vm با ورودی آلوده به اجرای مستقیم کد می‌انجامد."),
    remediation=("Replace with a safe expression parser or structured data handling.",
                 "با تجزیه‌کننده عبارت امن یا پردازش داده ساختاریافته جایگزین کنید."),
)

rule(
    "SEC-VULN-PROTOTYPE-POLLUTION",
    "security", "vulnerability", "medium", confidence=0.7,
    patterns=[r"__proto__\s*[\]\.]", r"\bconstructor\s*\]\s*\[\s*[\"']prototype", r"\bObject\.assign\s*\(\s*\{\}\s*,\s*(?:req|JSON\.parse)"],
    include=("**/*.js", "**/*.ts", "**/*.mjs", "**/*.cjs"),
    cwe=("CWE-1321",), tags=("prototype-pollution"),
    title=("Prototype pollution sink", "sink آلودگی پروتوتایپ"),
    description=("Writing to __proto__/constructor.prototype from parsed input pollutes every object.",
                 "نوشتن روی __proto__/constructor.prototype از ورودی تجزیه‌شده، همه اشیاء را آلوده می‌کند."),
    remediation=("Use Map or null-prototype objects and reject `__proto__` keys on merge.",
                 "از Map یا اشیاء با پروتوتایپ null استفاده کنید و کلیدهای `__proto__` را در merge رد کنید."),
)

rule(
    "SEC-VULN-COOKIE-INSECURE",
    "security", "vulnerability", "medium", confidence=0.75,
    patterns=[r"(?i)httpOnly\s*[:=]\s*(?:false|False)", r"(?i)secure\s*[:=]\s*(?:false|False)[^\n]{0,40}cookie",
              r"(?i)sameSite\s*[:=]\s*[\"']?none[\"']?"],
    include=CODE_INCLUDE,
    cwe=("CWE-1004", "CWE-614"), tags=("cookie", "session"),
    title=("Session cookie missing hardening flags", "کوکی نشست بدون پرچم‌های سخت‌سازی"),
    description=("Cookies without httpOnly/secure/sameSite are exposed to XSS exfiltration and CSRF.",
                 "کوکی‌های بدون httpOnly/secure/sameSite در معرض افشای XSS و CSRF هستند."),
    remediation=("Set httpOnly, secure and sameSite=lax/strict on session cookies.",
                 "روی کوکی نشست، httpOnly و secure و sameSite=lax/strict تنظیم کنید."),
)

rule(
    "SEC-VULN-LOG-SECRET",
    "security", "vulnerability", "medium", confidence=0.75,
    patterns=[r"(?:console\.log|logger\.\w+|log\.\w+|println!|print|logging\.\w+)\s*\([^)\n]*(?:password|passwd|pwd|secret|api[_-]?key|authorization|token\s*=)"],
    negative=[r"(?i)(mask|redact|sanitize|hash)"],
    include=CODE_INCLUDE,
    cwe=("CWE-532",), tags=("logging", "info-leak"),
    title=("Secret material written to logs", "مواد محرمانه در لاگ نوشته می‌شود"),
    description=("Logging credentials or tokens leaks them into every log sink and aggregation "
                 "system.",
                 "لاگ کردن اعتبارنامه یا توکن، آن‌ها را در همه مخازن لاگ و سامانه‌های تجمیع فاش می‌کند."),
    remediation=("Log identifiers only; mask secrets before logging.",
                 "فقط شناسه‌ها را لاگ کنید و رازها را پیش از لاگ ماسک کنید."),
)

rule(
    "SEC-VULN-UPLOAD-EXEC",
    "security", "vulnerability", "medium", confidence=0.6,
    patterns=[r"(?:move_uploaded_file|writeFileSync|createWriteStream|saveAs|Files\.write)\s*\([^)\n]*(?:req|request|\$_(FILES|GET|POST)|filename|file\.name)"],
    negative=[r"(?i)(sanitize|allow[-_ ]?list|ext(?:ension)?s?\s*[:=]|mime)"],
    include=CODE_INCLUDE,
    cwe=("CWE-434",), tags=("upload"),
    title=("Upload written using client-controlled name/path",
           "بارگذاری با نام/مسیر کنترل‌شده توسط کلاینت نوشته می‌شود"),
    description=("Trusting the client filename enables path traversal and executable-upload attacks.",
                 "اعتماد به نام فایل کلاینت، حمله پیمایش مسیر و بارگذاری فایل اجرایی را ممکن می‌کند."),
    remediation=("Generate server-side names, allow-list extensions, store outside the web root.",
                 "نام سمت سرور تولید کنید، پسوندها را فهرست‌مجاز کنید و بیرون از ریشه وب ذخیره کنید."),
)

# ------------------------------------------------------------------ tests ---

rule(
    "TST-SKIP-JS",
    "tests", "test_integrity", "high", confidence=0.9,
    patterns=[r"\b(?:it|test|describe|context)\.(?:skip)\s*\(", r"\bx(?:it|describe|test)\s*\(", r"\bskip\s*\(\s*[\"'][^\"']+[\"']\s*,"],
    include=("**",),
    cwe=("CWE-561",), tags=("skip", "jest", "mocha", "vitest"),
    title=("Test skipped (it.skip / xit / describe.skip)", "تست رد شده (it.skip / xit / describe.skip)"),
    description=("A test was disabled in the change. AI assistants sometimes 'fix' failing suites by "
                 "skipping tests instead of fixing code.",
                 "تستی در تغییرات غیرفعال شده است. دستیارهای هوش مصنوعی گاهی به‌جای اصلاح کد، مجموعه‌های "
                 "ناموفق را با رد کردن تست «درست» می‌کنند."),
    remediation=("Re-enable the test and fix the underlying failure, or document a tracked reason.",
                 "تست را فعال و خرابی ریشه‌ای را برطرف کنید یا دلیل ردیابی‌شده مستند کنید."),
)

rule(
    "TST-SKIP-PY",
    "tests", "test_integrity", "high", confidence=0.9,
    patterns=[r"@pytest\.mark\.skip(?:if)?\b", r"\bunittest\.skip(?:If)?\b", r"\bself\.skipTest\s*\(", r"@skip\b"],
    include=("**",),
    cwe=("CWE-561",), tags=("skip", "pytest"),
    title=("Python test skipped", "تست پایتون رد شده است"),
    description=("A pytest/unittest skip decorator was added.", "دکوراتور skip pytest/unittest افزوده شده است."),
    remediation=("Fix the failure or file a tracked issue for the skip.",
                 "خرابی را برطرف کنید یا برای رد کردن، مسئله ردیابی‌شده ثبت کنید."),
)

rule(
    "TST-SKIP-OTHER",
    "tests", "test_integrity", "high", confidence=0.9,
    patterns=[r"^\s*#\[ignore\]", r"@Ignore\b", r"@Disabled\b", r"\bt\.Skip(?:Now)?\s*\(", r"\btesting\.Short\b[^\n]*return"],
    include=("**",),
    cwe=("CWE-561",), tags=("skip"),
    title=("Test disabled (#[ignore] / @Ignore / t.Skip)", "تست غیرفعال شده (#[ignore] / @Ignore / t.Skip)"),
    description=("A Rust/Java/Go test was disabled in this change.", "تستی در Rust/Java/Go در این تغییر غیرفعال شده است."),
    remediation=("Restore the test and address the failure it covers.",
                 "تست را بازگردانید و خرابی‌ای که پوشش می‌دهد رسیدگی کنید."),
)

rule(
    "TST-ONLY-JS",
    "tests", "test_integrity", "high", confidence=0.9,
    patterns=[r"\b(?:it|test|describe)\.only\s*\(", r"\bf(?:it|describe)\s*\("],
    include=("**",),
    cwe=("CWE-561",), tags=("focus", "jest"),
    title=("Focused test run (.only / fit) disables the rest of the suite",
           "اجرای متمرکز تست (.only / fit) بقیه مجموعه را غیرفعال می‌کند"),
    description=("`.only` makes CI run a single test while reporting success — every other regression "
                 "goes unnoticed.",
                 "`.only` باعث می‌شود CI فقط یک تست را اجرا کند و موفقیت گزارش دهد؛ هر رگرسیون دیگر بی‌خبر می‌ماند."),
    remediation=("Remove .only before merging; add a CI guard (e.g. eslint-plugin-no-only-tests).",
                 "پیش از ادغام .only را حذف کنید و محافظ CI اضافه کنید (مثل eslint-plugin-no-only-tests)."),
)

rule(
    "TST-TAUTOLOGY",
    "tests", "test_integrity", "high", confidence=0.8,
    patterns=[
        r"expect\s*\(\s*(?:true|1)\s*\)\s*\.to(?:Be|Equal)\s*\(\s*(?:true|1)\s*\)",
        r"^\s*assert\s+True\s*(?:#.*)?$",
        r"assertTrue\s*\(\s*(?:True|true)\s*\)",
        r"assert\s+1\s*==\s*1",
        r"assertEqual\s*\(\s*1\s*,\s*1\s*\)",
        r"expect\s*\(\s*1\s*\)\s*\.toBe\s*\(\s*1\s*\)",
    ],
    include=("**",),
    cwe=("CWE-561",), tags=("tautology", "fake-test"),
    title=("Tautological assertion (assert True) — test proves nothing",
           "گزاره بدیهی (assert True) — تست چیزی را ثابت نمی‌کند"),
    description=("A test body was replaced with an assertion that can never fail; coverage stays green "
                 "while behaviour is unverified.",
                 "بدنه تست با گزاره‌ای جایگزین شده که هرگز شکست نمی‌خورد؛ پوشش سبز می‌ماند ولی رفتار راستی‌آزمایی "
                 "نمی‌شود."),
    remediation=("Restore meaningful assertions covering the behaviour under test.",
                 "گزاره‌های معنادار پوشش‌دهنده رفتار مورد تست را بازگردانید."),
)

rule(
    "TST-ASSERTIONS-REMOVED",
    "tests", "test_integrity", "high", confidence=0.8,
    heuristic="assertions_removed",
    cwe=("CWE-561",), tags=("assertions", "heuristic"),
    title=("Assertions removed from a test file", "گزاره‌ها از فایل تست حذف شده‌اند"),
    description=("The change deletes multiple assertion/expectation lines without adding replacements, "
                 "weakening what the suite verifies.",
                 "تغییر چند سطر assert/expect را بدون جایگزین حذف می‌کند و آنچه مجموعه راستی‌آزمایی می‌کند "
                 "ضعیف می‌سازد."),
    remediation=("Restore the assertions or replace them with equivalent, stronger checks.",
                 "گزاره‌ها را بازگردانید یا با بررسی‌های معادل و قوی‌تر جایگزین کنید."),
)

rule(
    "TST-FILE-DELETED",
    "tests", "test_integrity", "high", confidence=0.85,
    heuristic="test_file_deleted",
    cwe=("CWE-561",), tags=("coverage", "heuristic"),
    title=("Test file deleted", "فایل تست حذف شده است"),
    description=("A test/spec file was removed by this change. Deleting tests is a fast way to make a "
                 "broken build green.",
                 "فایل test/spec در این تغییر حذف شده است. حذف تست‌ها راه سریعی برای سبز کردن build خراب است."),
    remediation=("Restore the file, or confirm the deletion is an intentional, reviewed refactor.",
                 "فایل را بازگردانید یا تأیید کنید حذف، یک بازسازی عمدی و بازبینی‌شده است."),
)

rule(
    "TST-CI-TEST-STEP-REMOVED",
    "tests", "test_integrity", "high", confidence=0.85,
    heuristic="ci_test_step_removed",
    cwe=("CWE-561",), tags=("ci", "heuristic"),
    title=("Test step removed from CI pipeline", "گام تست از خط لوله CI حذف شده است"),
    description=("A CI job/step that ran the test suite (npm test, pytest, cargo test, go test...) was "
                 "removed or commented out.",
                 "یک job/step در CI که مجموعه تست را اجرا می‌کرد (npm test، pytest، cargo test، go test و...) "
                 "حذف یا کامنت شده است."),
    remediation=("Keep tests in CI; fix failures instead of removing the gate.",
                 "تست‌ها را در CI نگه دارید و به‌جای حذف سد، خرابی‌ها را برطرف کنید."),
)

rule(
    "TST-SNAPSHOT-FORCE-UPDATE",
    "tests", "test_integrity", "medium", confidence=0.8,
    patterns=[r"\bjest\s+[^\n|;&]*\s-u\b", r"\bvitest\s+[^\n|;&]*\s-u\b", r"--updateSnapshot\b", r"--update-snapshots\b", r"SNAPSHOT_UPDATE\s*=\s*1"],
    include=("**",),
    cwe=("CWE-561",), tags=("snapshot"),
    title=("Snapshot tests force-updated", "تست‌های snapshot با به‌روزرسانی اجباری"),
    description=("Updating snapshots unreviewed bakes current (possibly wrong) output in as the "
                 "expected baseline.",
                 "به‌روزرسانی بدون بازبینی snapshot، خروجی فعلی (احتمالاً غلط) را به‌عنوان مبنای مورد انتظار ثبت "
                 "می‌کند."),
    remediation=("Review each snapshot diff before accepting.", "هر diff snapshot را پیش از پذیرش بازبینی کنید."),
)

rule(
    "TST-COVERAGE-GATE-REMOVED",
    "tests", "test_integrity", "medium", confidence=0.8,
    heuristic="coverage_gate_removed",
    cwe=("CWE-561",), tags=("coverage", "heuristic"),
    title=("Coverage gate or threshold removed", "سد یا آستانه پوشش حذف شده است"),
    description=("Coverage thresholds / fail-under settings were removed, so untested code can merge "
                 "silently.",
                 "آستانه‌های پوشش / fail-under حذف شده‌اند و کد بدون تست بی‌صدا ادغام می‌شود."),
    remediation=("Restore thresholds and add tests for new code.", "آستانه‌ها را بازگردانید و برای کد جدید تست اضافه کنید."),
)

rule(
    "TST-EXCEPT-PASS-TEST",
    "tests", "test_integrity", "medium", confidence=0.7,
    patterns=[r"except\s*(?:\w+\s*)?:\s*$"],
    include=("**/test_*.py", "**/*_test.py", "**/tests/**/*.py", "**/test/**/*.py"),
    cwe=("CWE-561",), tags=("swallowed-error"),
    title=("Bare except in test may swallow failures", "except خالی در تست ممکن است شکست‌ها را ببلعد"),
    description=("Catching everything in a test body can turn real failures into silent passes.",
                 "گرفتن همه استثناها در بدنه تست می‌تواند شکست‌های واقعی را به موفقیت خاموش تبدیل کند."),
    remediation=("Assert the expected exception type explicitly (pytest.raises / assertRaises).",
                 "نوع استثنا مورد انتظار را صریح بررسی کنید (pytest.raises / assertRaises)."),
)

rule(
    "TST-MOCK-ALWAYS-SUCCESS",
    "tests", "test_integrity", "low", confidence=0.5,
    patterns=[r"(?:return_value|returnValue)\s*=\s*(?:True|0|200|MagicMock\(\s*\))", r"\bmock\w*\.(?:resolve|returnValue)\s*\(\s*(?:true|200|0)\s*\)"],
    include=("**",),
    cwe=("CWE-561",), tags=("mock"),
    title=("Mock hardcodes success, weakening the test", "ماسک موفقیت را ثابت می‌کند و تست را ضعیف می‌سازد"),
    description=("Stubbing every dependency to unconditional success can hide integration failures.",
                 "ثبت‌جای‌گذاری همه وابستگی‌ها با موفقیت بی‌قید می‌تواند شکست‌های یکپارچگی را پنهان کند."),
    remediation=("Include at least one failing-path case per behaviour.",
                 "حداقل یک حالت مسیر شکست برای هر رفتار اضافه کنید."),
)

rule(
    "TST-TIMEOUT-DISABLED",
    "tests", "test_integrity", "low", confidence=0.6,
    patterns=[r"(?i)jest\s+[^\n|;&]*--testTimeout\s*=\s*(?:0|999999)", r"(?i)timeout\s*=\s*0\b[^\n]*(?:test|pytest)", r"--durations\s*=\s*0"],
    include=("**",),
    cwe=("CWE-561",), tags=("timeout"),
    title=("Test timeout disabled or inflated", "مهلت تست غیرفعال یا بسیار بزرگ شده است"),
    description=("Removing timeouts lets hung tests block or silently pass in CI.",
                 "حذف مهلت‌ها اجازه می‌دهد تست‌های معلق CI را قفل کنند یا بی‌صدا موفق شوند."),
    remediation=("Keep sensible per-test timeouts.", "مهلت‌های معقول per-test را نگه دارید."),
)
