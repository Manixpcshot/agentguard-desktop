## AgentGuard v0.1.1 — secret-masking hardening

**Download below.** Windows x64: the NSIS installer (`…_x64-setup.exe`), the MSI,
or the portable executable. No paid APIs, no telemetry — everything runs locally.

This is a recommended update for anyone using v0.1.0: it closes a gap in how
detected credentials were displayed and stored.

### Fixed

- 🔒 **Secrets are now masked everywhere they leave the app.** In v0.1.0 a
  credential found by an engine other than *Secrets*, or by a heuristic that
  reports no matched fragment (for example `SEC-SECRET-HIGH-ENTROPY-STRING`),
  could appear in clear text in the finding's context line — and therefore in
  the UI, the local JSON history and exported Markdown/HTML/JSON reports. Every
  finding now passes a masking gate before it is emitted, stored or exported.
- 🔒 **The optional Ollama prompt is really masked.** It documented a masked
  diff but forwarded raw lines; secret-shaped tokens are now masked with the
  catalog's secrets rules before the prompt is built.
- The AWS access key rule keeps filtering the documented placeholder keys, and
  masking keeps a recognizable prefix (`AKIA••••T4VB`) so findings stay useful.

### Added

- ✅ An end-to-end pipeline test: a real temporary Git repository → diff → all
  seven engines → scoring. It asserts that a fake AWS key is flagged critical,
  that `curl … | bash` is flagged, that the verdict is **BLOCK**, that the raw
  key appears in neither the snippet nor the matched fragment, and that a clean
  documentation change yields zero findings and **PASS**.
- ✅ A catalog test for the new masking helper (`mask_secrets_in`) proving
  ordinary code is left untouched.
- 📛 CI / release / download / license / platform badges in both READMEs.
- 📖 A **Cutting a release** checklist in `CONTRIBUTING.md`, documenting that
  every tag must publish Windows binaries — never source only.

### Unchanged in this release

144 detection rules across 7 engines, risk scoring with PASS / REVIEW / BLOCK
verdicts, read-only Git analysis, bilingual UI and reports (English default,
فارسی with full RTL), optional local AI review, and confirmation-gated
redaction / test execution.

### Install

1. Download `AgentGuard_0.1.1_x64-setup.exe`.
2. Run it (a per-user install needs no admin rights) — it upgrades v0.1.0 in
   place and keeps your settings and history.
3. Open a project folder → *Start scan*.

Verify your download with `SHA256SUMS.txt` attached to this release:

```powershell
Get-FileHash AgentGuard_0.1.1_x64-setup.exe -Algorithm SHA256
```

Full guide: https://github.com/Manixpcshot/agentguard-desktop/blob/main/docs/en/installation.md

---

## AgentGuard v0.1.1 — سخت‌سازی ماسک‌سازی رازها

**از پایین دانلود کنید.** ویندوز x64: نصب‌کننده NSIS (`…_x64-setup.exe`)، بسته MSI
یا فایل اجرایی قابل‌حمل. بدون API پولی، بدون تله‌متری — همه‌چیز محلی اجرا می‌شود.

این نسخه به همه کاربران v0.1.0 توصیه می‌شود: شکافی در نحوه نمایش و ذخیره
اعتبارنامه‌های تشخیص‌شده برطرف شده است.

### اصلاح‌شده

- 🔒 **رازها اکنون در هر نقطه‌ای که از برنامه بیرون می‌روند ماسک می‌شوند.** در
  v0.1.0 اعتبارنامه‌ای که توسط موتوری غیر از *رازها* یا توسط هیوریستی بدون قطعه
  منطبق (مثلاً `SEC-SECRET-HIGH-ENTROPY-STRING`) پیدا می‌شد، می‌توانست به‌صورت
  متن آشکار در سطر زمینه یافته ظاهر شود — و در نتیجه در رابط کاربری، تاریخچه
  JSON محلی و گزارش‌های برون‌بری Markdown/HTML/JSON. اکنون هر یافته پیش از ارسال،
  ذخیره یا برون‌بری از یک دروازه ماسک‌سازی عبور می‌کند.
- 🔒 **پرامپت اختیاری Ollama واقعاً ماسک می‌شود.** پیش‌تر diff ماسک‌شده را وعده
  می‌داد ولی سطرهای خام را می‌فرستاد؛ اکنون توکن‌های شبیه راز پیش از ساخت پرامپت
  با قوانین موتور رازها ماسک می‌شوند.
- قانون کلید دسترسی AWS همچنان کلیدهای نمونه مستند را فیلتر می‌کند و ماسک‌سازی
  پیشوندی قابل تشخیص نگه می‌دارد (`AKIA••••T4VB`) تا یافته‌ها کاربردی بمانند.

### افزوده‌شده

- ✅ تست سرتاسری خط لوله: یک مخزن Git موقت واقعی → diff → هر هفت موتور →
  امتیازدهی. این تست تأیید می‌کند که یک کلید AWS جعلی بحرانی علامت می‌خورد،
  `curl … | bash` تشخیص داده می‌شود، حکم **مسدود** است، کلید خام نه در قطعه و نه
  در بخش منطبق ظاهر نمی‌شود، و یک تغییر تمیز مستندات صفر یافته و حکم **قبول** دارد.
- ✅ تست فهرست قوانین برای تابع کمکی جدید ماسک‌سازی (`mask_secrets_in`) که نشان می‌دهد
  کد معمولی دست‌نخورده می‌ماند.
- 📛 نشان‌های CI / ریلیز / دانلود / پروانه / سکو در هر دو README.
- 📖 چک‌لیست **انتشار نسخه** در `CONTRIBUTING.md` که قید می‌کند هر تگ باید
  باینری‌های ویندوز را منتشر کند — نه فقط سورس.

### بدون تغییر در این نسخه

۱۴۴ قانون تشخیص در ۷ موتور، امتیازدهی ریسک با حکم‌های قبول / نیازمند بازبینی /
مسدود، تحلیل فقط-خواندنی Git، رابط و گزارش دوزبانه (پیش‌فرض انگلیسی، فارسی با
RTL کامل)، بازبینی اختیاری با هوش مصنوعی محلی، و پوشاندن راز / اجرای تست منوط به
تأیید کاربر.

### نصب

1. `AgentGuard_0.1.1_x64-setup.exe` را دانلود کنید.
2. اجرا کنید (نصب per-user دسترسی مدیر نمی‌خواهد) — v0.1.0 را در جا ارتقا می‌دهد
   و تنظیمات و تاریخچه شما را نگه می‌دارد.
3. پوشه پروژه را باز کنید → *شروع اسکن*.

دانلود خود را با `SHA256SUMS.txt` پیوست‌شده به این نسخه راستی‌آزمایی کنید:

```powershell
Get-FileHash AgentGuard_0.1.1_x64-setup.exe -Algorithm SHA256
```

راهنمای کامل: https://github.com/Manixpcshot/agentguard-desktop/blob/main/docs/fa/installation.md
