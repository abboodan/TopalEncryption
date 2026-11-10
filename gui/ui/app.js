"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

const MODES = ["encrypt", "decrypt", "verify", "change"];
/** What each mode shows. `unlock` opens existing files; `newPassword` sets one. */
const FEATURES = {
  encrypt: { newPassword: true, deleteSource: true, hideNames: true, output: true, skips: true },
  decrypt: { unlock: true, deleteSource: true, output: true, skips: true },
  verify: { unlock: true },
  change: { unlock: true, newPassword: true },
};

const state = {
  lang: "en",
  mode: "encrypt",
  paths: [],
  scan: null, // { items, files, bytes, warnings } for the current paths and mode
  scanToken: 0,
  startedAt: 0,
  useRecoveryKey: false,
  outputDir: null,
  recoveryOn: false,
  generated: false,
};

/** Text for `key` in the current language, with `{name}` placeholders filled in. */
function t(key, values = {}) {
  const text = I18N[state.lang][key] ?? I18N.en[key] ?? key;
  return text.replace(/\{(\w+)\}/g, (_, name) => values[name] ?? "");
}

const count = (kind, n) => I18N[state.lang][kind](n);

function formatBytes(bytes) {
  const units = I18N[state.lang].units;
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(value < 10 ? 2 : 1)} ${units[unit]}`;
}

/** Rough strength estimate, 1 (weak) to 4 (strong): length matters most. */
function strength(password) {
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  const bits = password.length * [0, 4.7, 5.7, 5.95, 6.5][classes];
  if (bits < 40) return 1;
  if (bits < 60) return 2;
  if (bits < 80) return 3;
  return 4;
}

function show(section) {
  for (const id of ["setup", "working", "result"]) $(id).hidden = id !== section;
}

function setLanguage(lang) {
  state.lang = I18N[lang] ? lang : "en";
  try {
    localStorage.setItem("lang", state.lang);
  } catch {
    // Remembering the language is a convenience only.
  }
  document.documentElement.lang = state.lang;
  document.documentElement.dir = I18N[state.lang].dir;
  for (const node of document.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.dataset.i18n);
  }
  // The button offers the other language, written in that language.
  $("language").textContent = I18N[state.lang === "en" ? "ar" : "en"].languageName;
  render();
}

function revealed(inputId) {
  return $(inputId).type === "text";
}

function setRevealed(inputIds, reveal) {
  for (const id of inputIds) $(id).type = reveal ? "text" : "password";
}

function render() {
  const mode = state.mode;
  const features = FEATURES[mode];
  for (const name of MODES) {
    $(`mode-${name}`).setAttribute("aria-selected", String(name === mode));
  }
  $("mode-hint").textContent = t(`${mode}.hint`);
  $("mode-hint").hidden = t(`${mode}.hint`) === "";
  $("drop-title").textContent = t(`${mode}.drop`);

  $("selection").hidden = state.paths.length === 0;
  // Once something is selected the drop zone shrinks to its two buttons.
  $("drop").classList.toggle("compact", state.paths.length > 0);
  $("paths").replaceChildren(
    ...state.paths.map((path) => {
      const item = document.createElement("li");
      const label = document.createElement("span");
      // Shown right-to-left so a long path is cut at its start, keeping the file name.
      label.textContent = `‎${path}`;
      label.title = path;
      const remove = document.createElement("button");
      remove.textContent = "×";
      remove.title = t("remove");
      remove.addEventListener("click", () => setPaths(state.paths.filter((p) => p !== path)));
      item.append(label, remove);
      return item;
    }),
  );

  const scan = state.scan;
  const packed = scan && scan.items < scan.files;
  const what = !scan
    ? ""
    : packed
      ? t("selection.packed", { files: count("files", scan.files), folders: count("folders", scan.items) })
      : count("files", scan.files);
  $("scan-summary").textContent = !scan
    ? t("selection.scanning")
    : scan.items === 0
      ? t(`${mode}.empty`)
      : `${what} · ${formatBytes(scan.bytes)}`;
  const warnings = scan ? scan.warnings : [];
  $("scan-warnings").hidden = warnings.length === 0;
  $("scan-warnings").textContent =
    warnings.length === 0 ? "" : t("selection.unreadable", { items: count("items", warnings.length) });

  // Opening existing files.
  $("unlock-group").hidden = !features.unlock;
  $("unlock-label").textContent = state.useRecoveryKey
    ? t("unlock.recoveryLabel")
    : t(mode === "change" ? "password.current" : "password.label");
  $("toggle-unlock-kind").textContent = t(state.useRecoveryKey ? "unlock.usePassword" : "unlock.useRecovery");
  $("toggle-unlock").textContent = t(revealed("unlock") ? "hide" : "show");
  $("toggle-unlock").hidden = state.useRecoveryKey;

  // Setting a password.
  const password = $("password").value;
  $("new-group").hidden = !features.newPassword;
  $("password-label").textContent = t(mode === "change" ? "password.new" : "password.label");
  $("toggle-password").textContent = t(revealed("password") ? "hide" : "show");
  $("strength").hidden = !features.newPassword || password.length === 0;
  if (password.length > 0) {
    const level = strength(password);
    $("strength-bar").className = `s${level}`;
    $("strength-label").textContent = t(`strength.${level}`);
  }
  $("generated-note").hidden = !state.generated;

  $("delete-field").hidden = !features.deleteSource;
  if (features.deleteSource) {
    $("delete-label").textContent = t(`${mode}.deleteLabel`);
    $("delete-note").textContent = t(`${mode}.deleteNote`);
  }
  $("hide-field").hidden = !features.hideNames;
  $("output-field").hidden = !features.output;
  $("output-value").textContent = state.outputDir ?? t("output.beside");
  $("output-value").title = state.outputDir ?? "";
  $("output-reset").hidden = state.outputDir === null;

  $("recovery-dot").classList.toggle("on", state.recoveryOn);
  $("recovery-line").hidden = mode !== "encrypt";
  $("recovery-line").textContent = t(state.recoveryOn ? "recovery.lineOn" : "recovery.lineOff");

  const ready = scan && scan.items > 0;
  const secrets =
    (!features.unlock || $("unlock").value.length > 0) && (!features.newPassword || password.length > 0);
  $("start").textContent = ready
    ? t(`${mode}.start`, { files: count("files", scan.files) })
    : t(`${mode}.verb`);
  $("start").disabled = !ready || !secrets;
}

async function setPaths(paths) {
  state.paths = [...new Set(paths)];
  state.scan = null;
  $("error").hidden = true;
  const token = ++state.scanToken;
  render();
  if (state.paths.length === 0) return;
  const scan = await invoke("scan", {
    mode: state.mode,
    paths: state.paths,
    hideNames: state.mode === "encrypt" && $("hide-names").checked,
  });
  if (token === state.scanToken) {
    state.scan = scan;
    render();
  }
}

function setMode(mode, paths = state.paths) {
  if (mode !== state.mode) {
    state.mode = mode;
    // Options belong to one kind of job: start each mode from the safe defaults.
    $("delete-source").checked = false;
    state.outputDir = null;
  }
  setPaths(paths);
}

function fail(message) {
  const key = `err.${message}`;
  $("error").textContent = I18N.en[key] ? t(key) : message;
  $("error").hidden = false;
}

async function start() {
  const features = FEATURES[state.mode];
  const password = $("password").value;
  if (features.newPassword && password !== $("confirm").value) {
    fail(t("password.mismatch"));
    return;
  }
  $("error").hidden = true;
  $("working-title").textContent = t(`${state.mode}.working`);
  $("progress-bar").style.width = "0";
  $("progress-percent").textContent = "0%";
  $("progress-detail").textContent = t("working.preparing");
  $("cancel").disabled = false;
  $("cancel").textContent = t("working.cancel");
  state.startedAt = performance.now();
  show("working");

  try {
    const summary = await invoke("start", {
      request: {
        mode: state.mode,
        paths: state.paths,
        secret: features.unlock ? $("unlock").value : password,
        useRecoveryKey: Boolean(features.unlock) && state.useRecoveryKey,
        newPassword: state.mode === "change" ? password : null,
        deleteSource: Boolean(features.deleteSource) && $("delete-source").checked,
        hideNames: Boolean(features.hideNames) && $("hide-names").checked,
        outputDir: features.output ? state.outputDir : null,
      },
    });
    showResult(summary);
  } catch (err) {
    show("setup");
    fail(String(err));
  }
}

function onProgress({ bytes, total_bytes: totalBytes, files, total_files: totalFiles }) {
  const fraction = totalBytes > 0 ? bytes / totalBytes : totalFiles > 0 ? files / totalFiles : 0;
  $("progress-bar").style.width = `${(fraction * 100).toFixed(1)}%`;
  $("progress-percent").textContent = `${Math.floor(fraction * 100)}%`;
  if (bytes === 0 && files === 0) return;
  const seconds = (performance.now() - state.startedAt) / 1000;
  const speed = seconds > 0.5 ? ` · ${formatBytes(bytes / seconds)}/s` : "";
  $("progress-detail").textContent =
    t("working.detail", {
      done: fmt(files),
      total: fmt(totalFiles),
      bytes: formatBytes(bytes),
      totalBytes: formatBytes(totalBytes),
    }) + speed;
}

function showResult(summary) {
  // Every file refusing the password is one problem, not hundreds: say so plainly.
  const allFailedWith = (code) =>
    summary.done === 0 && summary.failed > 0 && summary.failures.every((failure) => failure.code === code);
  const wrong = allFailedWith("wrong_password")
    ? "result.wrongPassword"
    : allFailedWith("wrong_recovery_key")
      ? "result.wrongRecoveryKey"
      : null;
  const failures = wrong ? [] : summary.failures;
  $("result-title").textContent = summary.cancelled
    ? t("result.cancelled")
    : wrong
      ? t(wrong)
      : summary.failed > 0
        ? t("result.problems")
        : t("result.allDone");
  $("result-done").textContent = fmt(summary.done);
  $("result-done-label").textContent = t(`${state.mode}.done`);
  $("result-skipped").textContent = fmt(summary.skipped);
  $("skipped-tile").hidden = !FEATURES[state.mode].skips;
  $("tiles").classList.toggle("two", !FEATURES[state.mode].skips);
  $("result-failed").textContent = fmt(summary.failed);
  $("result-failed").parentElement.classList.toggle("bad", summary.failed > 0);

  const notes = [];
  if (summary.skipped > 0) notes.push(t("result.noteSkipped"));
  if (summary.cancelled) notes.push(t("result.noteCancelled"));
  if (wrong) {
    notes.push(t("result.noteWrong"));
  } else if (summary.failed > failures.length) {
    notes.push(t("result.noteFirst", { count: fmt(failures.length) }));
  }
  $("result-note").hidden = notes.length === 0;
  $("result-note").textContent = notes.join(" ");

  $("failures").hidden = failures.length === 0;
  $("failures").replaceChildren(
    ...failures.map(({ path, code, reason }) => {
      const item = document.createElement("li");
      const why = document.createElement("span");
      // Disk errors come from Windows already worded; the rest are ours to translate.
      why.textContent = I18N.en[`err.${code}`] ? t(`err.${code}`) : reason;
      const where = document.createElement("code");
      where.textContent = path;
      item.append(why, where);
      return item;
    }),
  );
  show("result");
}

function clearSecrets() {
  for (const id of ["password", "confirm", "unlock"]) $(id).value = "";
  setRevealed(["password", "confirm", "unlock"], false);
  state.generated = false;
}

function reset() {
  clearSecrets();
  $("delete-source").checked = false;
  $("hide-names").checked = false;
  state.outputDir = null;
  setPaths([]);
  show("setup");
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Older WebView2 builds refuse the async API without focus: fall back.
    const area = document.createElement("textarea");
    area.value = text;
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
}

/** Briefly replaces a button's label to confirm an action. */
function flash(button, key) {
  const original = button.dataset.i18n;
  button.textContent = t(key);
  setTimeout(() => (button.textContent = t(original)), 1500);
}

// ---- Recovery key dialog ----

function showRecoveryView(view) {
  for (const id of ["recovery-off", "recovery-on", "recovery-created"]) $(id).hidden = id !== view;
  $("recovery-error").hidden = true;
}

async function refreshRecovery() {
  state.recoveryOn = await invoke("recovery_status");
  render();
}

async function openRecovery() {
  await refreshRecovery();
  showRecoveryView(state.recoveryOn ? "recovery-on" : "recovery-off");
  $("recovery-dialog").showModal();
}

function closeRecovery() {
  // The key lives only in this dialog: wipe it from the page on the way out.
  $("recovery-key").textContent = "";
  $("recovery-dialog").close();
}

async function recoveryAction(action) {
  try {
    await action();
  } catch (err) {
    $("recovery-error").textContent = String(err);
    $("recovery-error").hidden = false;
  }
}

async function createRecoveryKey() {
  const key = await invoke("recovery_create");
  $("recovery-key").textContent = key;
  $("recovery-saved").checked = false;
  $("recovery-done").disabled = true;
  $("recovery-feedback").textContent = "";
  showRecoveryView("recovery-created");
  await refreshRecovery();
}

// ---- Wiring ----

for (const mode of MODES) {
  $(`mode-${mode}`).addEventListener("click", () => setMode(mode));
}
$("language").addEventListener("click", () => setLanguage(state.lang === "en" ? "ar" : "en"));
$("add-files").addEventListener("click", async () => {
  setPaths([...state.paths, ...(await invoke("pick_files"))]);
});
$("add-folders").addEventListener("click", async () => {
  setPaths([...state.paths, ...(await invoke("pick_folders"))]);
});
$("clear").addEventListener("click", () => setPaths([]));

$("password").addEventListener("input", () => {
  state.generated = false;
  render();
});
$("unlock").addEventListener("input", render);
$("toggle-password").addEventListener("click", () => {
  setRevealed(["password", "confirm"], !revealed("password"));
  render();
});
$("toggle-unlock").addEventListener("click", () => {
  setRevealed(["unlock"], !revealed("unlock"));
  render();
});
$("toggle-unlock-kind").addEventListener("click", () => {
  state.useRecoveryKey = !state.useRecoveryKey;
  $("unlock").value = "";
  // A recovery key is long and typed from paper: show it while typing.
  setRevealed(["unlock"], state.useRecoveryKey);
  render();
  $("unlock").focus();
});
$("generate").addEventListener("click", async () => {
  const passphrase = await invoke("generate_passphrase");
  $("password").value = passphrase;
  $("confirm").value = passphrase;
  setRevealed(["password", "confirm"], true);
  state.generated = true;
  render();
});
$("copy-password").addEventListener("click", async () => {
  await copyText($("password").value);
  flash($("copy-password"), "copied");
});

$("hide-names").addEventListener("change", () => setPaths(state.paths));
$("output-choose").addEventListener("click", async () => {
  const folder = await invoke("pick_output_folder");
  if (folder) {
    state.outputDir = folder;
    render();
  }
});
$("output-reset").addEventListener("click", () => {
  state.outputDir = null;
  render();
});

$("start").addEventListener("click", start);
$("cancel").addEventListener("click", () => {
  $("cancel").disabled = true;
  $("cancel").textContent = t("working.cancelling");
  invoke("cancel");
});
$("again").addEventListener("click", reset);
document.addEventListener("keydown", (event) => {
  const idle = !$("setup").hidden && !$("recovery-dialog").open;
  if (event.key === "Enter" && idle && !$("start").disabled) start();
});

$("open-recovery").addEventListener("click", openRecovery);
for (const button of document.querySelectorAll(".close-dialog")) {
  button.addEventListener("click", closeRecovery);
}
$("recovery-dialog").addEventListener("cancel", (event) => {
  // Escape must not dismiss a key that has not been saved yet.
  if (!$("recovery-created").hidden) event.preventDefault();
});
$("recovery-create").addEventListener("click", () => recoveryAction(createRecoveryKey));
$("recovery-replace").addEventListener("click", () => recoveryAction(createRecoveryKey));
$("recovery-disable").addEventListener("click", () =>
  recoveryAction(async () => {
    await invoke("recovery_disable");
    await refreshRecovery();
    showRecoveryView("recovery-off");
  }),
);
$("recovery-copy").addEventListener("click", async () => {
  await copyText($("recovery-key").textContent);
  $("recovery-feedback").textContent = t("copied");
});
$("recovery-save").addEventListener("click", () =>
  recoveryAction(async () => {
    if (await invoke("save_recovery_key", { key: $("recovery-key").textContent })) {
      $("recovery-feedback").textContent = t("recovery.saved");
    }
  }),
);
$("recovery-saved").addEventListener("change", () => {
  $("recovery-done").disabled = !$("recovery-saved").checked;
});
$("recovery-done").addEventListener("click", closeRecovery);

/** Paths handed over by Explorer's right-click menu or a double click on a file. */
function openRequest({ mode, paths }) {
  if ($("setup").hidden) return;
  // Several selected files arrive one by one: keep adding while the mode is the same.
  setMode(mode, mode === state.mode ? [...state.paths, ...paths] : paths);
}

listen("progress", (event) => onProgress(event.payload));
listen("open-paths", (event) => openRequest(event.payload));
listen("tauri://drag-enter", () => $("drop").classList.add("over"));
listen("tauri://drag-leave", () => $("drop").classList.remove("over"));
listen("tauri://drag-drop", (event) => {
  $("drop").classList.remove("over");
  if (!$("setup").hidden) setPaths([...state.paths, ...event.payload.paths]);
});

let savedLanguage = "en";
try {
  savedLanguage = localStorage.getItem("lang") ?? "en";
} catch {
  // Falls back to English.
}
setLanguage(savedLanguage);
refreshRecovery();
invoke("launch_request").then((request) => {
  if (request) openRequest(request);
});
