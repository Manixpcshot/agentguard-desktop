## AgentGuard v0.1.0 — first release 🎉

**Download below.** Windows x64: pick the installer (`…_x64-setup.exe`), the MSI,
or the portable executable. No paid APIs, no telemetry — everything runs locally.

### What's inside

- 🧩 **Real Git review** — working tree, staged changes, branch merge-base, a
  single commit or the last N commits, with optional untracked files and a full
  unified diff viewer.
- 🛡 **144 detection rules / 7 engines** — secrets & API keys, dangerous
  commands, security regressions, test integrity, suspicious changes, supply
  chain, CI/CD hardening.
- 🧠 **22 contextual heuristics** — typosquatted dependencies, lockfile drift,
  removed assertions & CI test steps, zero-width/homoglyph characters,
  `pull_request_target` + checkout, encoded blobs, and more.
- 📊 **Risk score 0–100** with Safe→Critical bands and a PASS / REVIEW / BLOCK
  verdict, plus per-severity, per-category and per-engine breakdowns.
- 🔧 **Actionable findings** — remediation text, CWE references, confidence,
  masked secret snippets, copy summary, jump to diff.
- 🤖 **Optional local AI review** via Ollama (e.g. `qwen2.5-coder:7b`) — masked
  diffs only, and the app is fully usable without it.
- 🌐 **Bilingual** — English (default) and Persian with full RTL layout,
  including rule explanations and exported reports.
- 🔒 **Safety first** — scans are read-only. Redacting a secret (with backup) and
  running your test suite both require an explicit, time-limited confirmation.

### Install

1. Download `AgentGuard_0.1.0_x64-setup.exe`.
2. Run it (per-user install needs no admin rights).
3. Open a project folder → *Start scan*.

Full guide: https://github.com/Manixpcshot/agentguard-desktop/blob/main/docs/en/installation.md

---

## AgentGuard v0.1.0 — نخستین نسخه 🎉

**از پایین دانلود کنید.** ویندوز x64: نصب‌کننده (`…_x64-setup.exe`)، بسته MSI یا
فایل اجرایی قابل‌حمل را انتخاب کنید. بدون API پولی، بدون تله‌متری — همه‌چیز محلی اجرا می‌شود.

### چه چیزی داخل است

- 🧩 **بازبینی واقعی Git** — درخت کاری، تغییرات staged، پایه ادغام شاخه، یک کامیت
  یا N کامیت اخیر، با امکان شامل کردن فایل‌های ردیابی‌نشده و نمایش کامل diff.
- 🛡 **۱۴۴ قانون تشخیص / ۷ موتور** — رازها و کلیدهای API، دستورات خطرناک،
  رگرسیون‌های امنیتی، یکپارچگی تست، تغییرات مشکوک، زنجیره تأمین، سخت‌سازی CI/CD.
- 🧠 **۲۲ هیوریستیک زمینه‌ای** — وابستگی‌های جعل‌نام، اختلاف lockfile، حذف
  گزاره‌ها و گام‌های تست CI، نویسه‌های پهنای‌صفر/هم‌شکل، `pull_request_target` +
  checkout، بلاب‌های کدگذاری‌شده و بیشتر.
- 📊 **امتیاز ریسک ۰–۱۰۰** با بازه‌های امن تا بحرانی و حکم قبول / نیازمند
  بازبینی / مسدود، به‌همراه تفکیک بر اساس شدت، دسته و موتور.
- 🔧 **یافته‌های کاربردی** — متن راه اصلاح، ارجاع CWE، اطمینان، قطعه ماسک‌شده
  راز، کپی خلاصه، پرش به diff.
- 🤖 **بازبینی اختیاری با هوش مصنوعی محلی** از طریق Ollama (مثلاً
  `qwen2.5-coder:7b`) — فقط diffهای ماسک‌شده؛ برنامه بدون آن هم کامل کار می‌کند.
- 🌐 **دوزبانه** — انگلیسی (پیش‌فرض) و فارسی با چیدمان کامل راست‌به‌چپ، شامل توضیح
  قوانین و گزارش‌های برون‌بری.
- 🔒 **ایمنی در اولویت** — اسکن‌ها فقط-خواندنی‌اند. پوشاندن راز (همراه پشتیبان) و
  اجرای مجموعه تست هر دو به تأیید صریح و زمان‌دار کاربر نیاز دارند.

### نصب

1. `AgentGuard_0.1.0_x64-setup.exe` را دانلود کنید.
2. اجرا کنید (نصب per-user نیازی به دسترسی مدیر ندارد).
3. پوشه پروژه را باز کنید → *شروع اسکن*.

راهنمای کامل: https://github.com/Manixpcshot/agentguard-desktop/blob/main/docs/fa/installation.md
