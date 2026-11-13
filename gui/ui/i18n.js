"use strict";

// Interface text. English is the default; Arabic is right-to-left.
// `{name}` is replaced by the value passed to t().
const I18N = {
  en: {
    dir: "ltr",
    languageName: "English",
    tagline: "Password-protect any file or folder",
    copy: "Copy",
    copied: "Copied",
    close: "Close",
    show: "Show",
    hide: "Hide",
    remove: "Remove",

    "encrypt.verb": "Encrypt",
    "encrypt.hint": "",
    "encrypt.drop": "Drop files or folders here",
    "encrypt.start": "Encrypt {files}",
    "encrypt.working": "Encrypting…",
    "encrypt.done": "encrypted",
    "encrypt.empty": "No files to encrypt in this selection.",
    "encrypt.deleteLabel": "Delete the originals after encrypting",
    "encrypt.deleteNote":
      "Each encrypted file is decrypted back and checked before its original is removed. " +
      "This is a normal delete, not a secure wipe.",

    "decrypt.verb": "Decrypt",
    "decrypt.hint": "",
    "decrypt.drop": "Drop .topal files or folders here",
    "decrypt.start": "Decrypt {files}",
    "decrypt.working": "Decrypting…",
    "decrypt.done": "decrypted",
    "decrypt.empty": "No .topal files in this selection.",
    "decrypt.deleteLabel": "Delete the .topal files after decrypting",
    "decrypt.deleteNote": "Each .topal file is removed only after its content is fully restored.",

    "verify.verb": "Verify",
    "verify.hint":
      "Checks that the password is right and that every encrypted file is intact. Nothing is written.",
    "verify.drop": "Drop .topal files or folders here",
    "verify.start": "Verify {files}",
    "verify.working": "Verifying…",
    "verify.done": "intact",
    "verify.empty": "No .topal files in this selection.",

    "change.verb": "Change password",
    "change.hint":
      "Gives encrypted files a new password without re-encrypting them, so it takes seconds. " +
      "An older copy of a file still opens with the old password.",
    "change.drop": "Drop .topal files or folders here",
    "change.start": "Change password of {files}",
    "change.working": "Changing password…",
    "change.done": "changed",
    "change.empty": "No .topal files in this selection.",

    "drop.or": "or",
    "drop.addFiles": "Add files",
    "drop.addFolder": "Add folder",
    "selection.clear": "Clear",
    "selection.scanning": "Scanning…",
    "selection.unreadable": "{items} could not be read and will be left out.",
    "selection.packed": "{files} in {folders}",

    "password.label": "Password",
    "password.new": "New password",
    "password.current": "Current password",
    "password.repeat": "Repeat password",
    "password.generate": "Generate",
    "password.generatedNote":
      "Write this passphrase down or save it in a password manager before you continue.",
    "password.mismatch": "The two passwords do not match.",
    "strength.1": "Weak",
    "strength.2": "Fair",
    "strength.3": "Good",
    "strength.4": "Strong",

    "unlock.recoveryLabel": "Recovery key",
    "unlock.useRecovery": "Use the recovery key instead",
    "unlock.usePassword": "Use the password instead",

    "hide.label": "Hide file names",
    "hide.note":
      "Every output gets a random name, and each folder becomes a single file, so names, " +
      "structure and file count are hidden. The real names come back when decrypting. " +
      "Running again makes new copies instead of skipping.",
    "output.label": "Save to",
    "output.beside": "Next to the originals",
    "output.choose": "Choose folder…",
    "output.reset": "Reset",

    "recovery.button": "Recovery key",
    "recovery.title": "Recovery key",
    "recovery.what":
      "A recovery key is a second way to open your files if you forget the password. " +
      "Files you encrypt after creating it can be opened with either the password or the key.",
    "recovery.risk":
      "Anyone who gets the key can open those files without the password. " +
      "Keep it on paper or in a password manager, not next to the encrypted files.",
    "recovery.create": "Create a recovery key",
    "recovery.onText":
      "A recovery key is on. Files you encrypt from now on can also be opened with it.",
    "recovery.onNote":
      "The key itself is not stored on this PC. Files encrypted before it was created are " +
      "not covered. Turning it off does not remove it from files that already have it.",
    "recovery.replace": "Create a new key",
    "recovery.disable": "Turn off",
    "recovery.createdText": "This is your recovery key:",
    "recovery.save": "Save to a file…",
    "recovery.saved": "Saved",
    "recovery.once":
      "It is shown only once and is not stored by the app. If you lose it, it cannot be shown again.",
    "recovery.confirm": "I have saved the key somewhere safe",
    "recovery.lineOn": "Recovery key {id} is on: these files can also be opened with it.",
    "recovery.id": "Key ID (must match the one saved with your key):",
    "recovery.lineOff":
      "There is no password recovery. If you forget the password, the files cannot be opened by anyone.",

    "working.preparing": "Preparing key…",
    "working.cancel": "Cancel",
    "working.cancelling": "Cancelling…",
    "working.detail": "{done} / {total} · {bytes} of {totalBytes}",

    "result.skipped": "skipped",
    "result.failed": "failed",
    "result.again": "Done",
    "result.allDone": "All done",
    "result.problems": "Finished with problems",
    "result.cancelled": "Cancelled",
    "result.wrongPassword": "Wrong password",
    "result.wrongRecoveryKey": "Wrong recovery key",
    "result.noteSkipped": "Skipped files already had an output next to them.",
    "result.notePrograms":
      "Written as programs, under names the encrypted files did not show: {names}. " +
      "Open them only if you trust where the encrypted files came from.",
    "result.noteCancelled": "Files that were not finished were left untouched.",
    "result.noteWrong": "None of the files could be opened. Nothing was changed.",
    "result.noteFirst": "Showing the first {count} failures.",

    "err.empty_password": "The password cannot be empty.",
    "err.busy": "A job is already running.",
    "err.invalid_recovery_key": "This is not a valid recovery key. Check it for typing mistakes.",
    "err.wrong_password": "Wrong password, or the file header is damaged",
    "err.wrong_recovery_key": "Wrong recovery key, or the file header is damaged",
    "err.no_recovery_slot": "This file was not encrypted with a recovery key",
    "err.not_topal": "Not a Topal Encryption file",
    "err.corrupted": "The file content is damaged or incomplete",
    "err.verification_failed": "The file changed while it was being encrypted",
    "err.unsafe_path": "The encrypted folder contains an unsafe path",
    "err.output_exists": "An output with this name already exists",
    "err.unsupported_name": "A name in this folder is too long or not allowed on Windows. Rename it and try again:",
    "err.unsupported_version": "Made by a newer version of Topal Encryption",

    units: ["B", "KB", "MB", "GB", "TB"],
    files: (n) => `${fmt(n)} ${n === 1 ? "file" : "files"}`,
    folders: (n) => `${fmt(n)} ${n === 1 ? "folder" : "folders"}`,
    items: (n) => `${fmt(n)} ${n === 1 ? "item" : "items"}`,
  },

  ar: {
    dir: "rtl",
    languageName: "العربية",
    tagline: "احمِ أي ملف أو مجلد بكلمة سر",
    copy: "نسخ",
    copied: "تم النسخ",
    close: "إغلاق",
    show: "إظهار",
    hide: "إخفاء",
    remove: "إزالة",

    "encrypt.verb": "تشفير",
    "encrypt.hint": "",
    "encrypt.drop": "اسحب الملفات أو المجلدات إلى هنا",
    "encrypt.start": "تشفير {files}",
    "encrypt.working": "جارٍ التشفير…",
    "encrypt.done": "تم تشفيرها",
    "encrypt.empty": "لا توجد ملفات للتشفير في هذا التحديد.",
    "encrypt.deleteLabel": "حذف الملفات الأصلية بعد التشفير",
    "encrypt.deleteNote":
      "يُفك كل ملف مشفّر ويُتحقق منه قبل حذف أصله. هذا حذف عادي وليس مسحاً آمناً.",

    "decrypt.verb": "فك التشفير",
    "decrypt.hint": "",
    "decrypt.drop": "اسحب ملفات ‎.topal‎ أو المجلدات إلى هنا",
    "decrypt.start": "فك تشفير {files}",
    "decrypt.working": "جارٍ فك التشفير…",
    "decrypt.done": "تم فكها",
    "decrypt.empty": "لا توجد ملفات ‎.topal‎ في هذا التحديد.",
    "decrypt.deleteLabel": "حذف ملفات ‎.topal‎ بعد فك التشفير",
    "decrypt.deleteNote": "لا يُحذف أي ملف ‎.topal‎ إلا بعد استعادة محتواه كاملاً.",

    "verify.verb": "فحص",
    "verify.hint": "يتأكد من أن كلمة السر صحيحة وأن كل ملف مشفّر سليم. لا يُكتب أي شيء.",
    "verify.drop": "اسحب ملفات ‎.topal‎ أو المجلدات إلى هنا",
    "verify.start": "فحص {files}",
    "verify.working": "جارٍ الفحص…",
    "verify.done": "سليمة",
    "verify.empty": "لا توجد ملفات ‎.topal‎ في هذا التحديد.",

    "change.verb": "تغيير كلمة السر",
    "change.hint":
      "يعطي الملفات المشفّرة كلمة سر جديدة دون إعادة تشفيرها، فيستغرق ثوانيَ. " +
      "أي نسخة أقدم من الملف تبقى تُفتح بكلمة السر القديمة.",
    "change.drop": "اسحب ملفات ‎.topal‎ أو المجلدات إلى هنا",
    "change.start": "تغيير كلمة السر لـ {files}",
    "change.working": "جارٍ تغيير كلمة السر…",
    "change.done": "تم تغييرها",
    "change.empty": "لا توجد ملفات ‎.topal‎ في هذا التحديد.",

    "drop.or": "أو",
    "drop.addFiles": "إضافة ملفات",
    "drop.addFolder": "إضافة مجلد",
    "selection.clear": "مسح",
    "selection.scanning": "جارٍ الفحص…",
    "selection.unreadable": "تعذّرت قراءة {items} وسيُستثنى.",
    "selection.packed": "{files} في {folders}",

    "password.label": "كلمة السر",
    "password.new": "كلمة السر الجديدة",
    "password.current": "كلمة السر الحالية",
    "password.repeat": "أعد كتابة كلمة السر",
    "password.generate": "توليد",
    "password.generatedNote": "اكتب هذه العبارة أو احفظها في مدير كلمات السر قبل المتابعة.",
    "password.mismatch": "كلمتا السر غير متطابقتين.",
    "strength.1": "ضعيفة",
    "strength.2": "مقبولة",
    "strength.3": "جيدة",
    "strength.4": "قوية",

    "unlock.recoveryLabel": "مفتاح الاسترداد",
    "unlock.useRecovery": "استخدم مفتاح الاسترداد",
    "unlock.usePassword": "استخدم كلمة السر",

    "hide.label": "إخفاء أسماء الملفات",
    "hide.note":
      "يأخذ كل ملف ناتج اسماً عشوائياً ويصبح كل مجلد ملفاً واحداً، فتختفي الأسماء والهيكل " +
      "وعدد الملفات. تعود الأسماء الحقيقية عند فك التشفير. تكرار العملية ينشئ نسخاً جديدة ولا يتخطى.",
    "output.label": "الحفظ في",
    "output.beside": "بجانب الملفات الأصلية",
    "output.choose": "اختيار مجلد…",
    "output.reset": "إعادة",

    "recovery.button": "مفتاح الاسترداد",
    "recovery.title": "مفتاح الاسترداد",
    "recovery.what":
      "مفتاح الاسترداد طريقة ثانية لفتح ملفاتك إذا نسيت كلمة السر. " +
      "الملفات التي تشفّرها بعد إنشائه تُفتح بكلمة السر أو بالمفتاح.",
    "recovery.risk":
      "من يحصل على المفتاح يفتح تلك الملفات دون كلمة السر. " +
      "احفظه على ورقة أو في مدير كلمات السر، لا بجانب الملفات المشفّرة.",
    "recovery.create": "إنشاء مفتاح استرداد",
    "recovery.onText": "مفتاح الاسترداد مفعّل. الملفات التي تشفّرها من الآن تُفتح به أيضاً.",
    "recovery.onNote":
      "المفتاح نفسه غير محفوظ على هذا الحاسوب. الملفات المشفّرة قبل إنشائه غير مشمولة. " +
      "إيقافه لا يزيله من الملفات التي تحمله.",
    "recovery.replace": "إنشاء مفتاح جديد",
    "recovery.disable": "إيقاف",
    "recovery.createdText": "هذا مفتاح الاسترداد الخاص بك:",
    "recovery.save": "حفظ في ملف…",
    "recovery.saved": "تم الحفظ",
    "recovery.once": "يظهر مرة واحدة فقط ولا يحفظه التطبيق. إذا فقدته فلا يمكن عرضه مرة أخرى.",
    "recovery.confirm": "حفظت المفتاح في مكان آمن",
    "recovery.lineOn": "مفتاح الاسترداد {id} مفعّل: هذه الملفات تُفتح به أيضاً.",
    "recovery.id": "معرّف المفتاح (يجب أن يطابق المعرّف المحفوظ مع مفتاحك):",
    "recovery.lineOff": "لا توجد استعادة لكلمة السر. إذا نسيتها فلن يستطيع أحد فتح الملفات.",

    "working.preparing": "جارٍ تجهيز المفتاح…",
    "working.cancel": "إلغاء",
    "working.cancelling": "جارٍ الإلغاء…",
    "working.detail": "{done} / {total} · {bytes} من {totalBytes}",

    "result.skipped": "تم تخطيها",
    "result.failed": "فشلت",
    "result.again": "تم",
    "result.allDone": "اكتمل كل شيء",
    "result.problems": "انتهى مع مشاكل",
    "result.cancelled": "أُلغيت العملية",
    "result.wrongPassword": "كلمة السر خاطئة",
    "result.wrongRecoveryKey": "مفتاح الاسترداد خاطئ",
    "result.noteSkipped": "الملفات المتخطاة كان ناتجها موجوداً من قبل.",
    "result.notePrograms":
      "كُتبت كبرامج بأسماء لم تكن ظاهرة في أسماء الملفات المشفّرة: {names}. " +
      "لا تفتحها إلا إذا كنت تثق بمصدر الملفات المشفّرة.",
    "result.noteCancelled": "الملفات التي لم تكتمل بقيت كما هي.",
    "result.noteWrong": "تعذّر فتح أي ملف. لم يتغير شيء.",
    "result.noteFirst": "تُعرض أول {count} حالة فشل.",

    "err.empty_password": "لا يمكن أن تكون كلمة السر فارغة.",
    "err.busy": "هناك عملية جارية.",
    "err.invalid_recovery_key": "هذا ليس مفتاح استرداد صالحاً. تحقق من أخطاء الكتابة.",
    "err.wrong_password": "كلمة السر خاطئة أو رأس الملف تالف",
    "err.wrong_recovery_key": "مفتاح الاسترداد خاطئ أو رأس الملف تالف",
    "err.no_recovery_slot": "هذا الملف لم يُشفّر مع مفتاح استرداد",
    "err.not_topal": "ليس ملف Topal Encryption",
    "err.corrupted": "محتوى الملف تالف أو ناقص",
    "err.verification_failed": "تغيّر الملف أثناء تشفيره",
    "err.unsafe_path": "المجلد المشفّر يحتوي مساراً غير آمن",
    "err.output_exists": "يوجد ناتج بهذا الاسم من قبل",
    "err.unsupported_name": "يوجد في هذا المجلد اسم طويل جداً أو غير مسموح في Windows. غيّر الاسم ثم أعد المحاولة:",
    "err.unsupported_version": "أُنشئ بإصدار أحدث من Topal Encryption",

    units: ["بايت", "ك.ب", "م.ب", "غ.ب", "ت.ب"],
    files: (n) => arabicCount(n, "ملف واحد", "ملفان", "ملفات", "ملف"),
    folders: (n) => arabicCount(n, "مجلد واحد", "مجلدان", "مجلدات", "مجلد"),
    items: (n) => arabicCount(n, "عنصر واحد", "عنصران", "عناصر", "عنصر"),
  },
};

/** Digits stay Western in both languages so sizes and counts read the same. */
function fmt(n) {
  return n.toLocaleString("en-US");
}

/** Arabic number agreement: 1, 2, 3 to 10 (plural), and the rest (singular). */
function arabicCount(n, one, two, few, many) {
  if (n === 1) return one;
  if (n === 2) return two;
  const tail = n % 100;
  return `${fmt(n)} ${tail >= 3 && tail <= 10 ? few : many}`;
}
