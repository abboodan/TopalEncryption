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
  recoveryId: null, // ID of the key in use, for the user to compare with the one they noted
  generated: false,
  summary: null, // the last job's result, kept so the results screen follows the language
  app: { version: "", installed: false, daily_check: false },
  // phase: idle | checking | current | available | downloading | ready | installing
  update: { phase: "idle", version: null, error: null, downloaded: 0, total: null },
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
  // Repeating a character adds little: each distinct one counts at most twice.
  const length = Math.min(password.length, new Set(password).size * 2);
  // The first things anyone tries. Containing one halves the estimate.
  const common = /pass|qwert|asdf|1234|4321|abcd|admin|letmein|welcome|iloveyou|0000|1111/i.test(password);
  const bits = length * [0, 4.7, 5.7, 5.95, 6.5][classes] * (common ? 0.5 : 1);
  if (bits < 40) return 1;
  if (bits < 60) return 2;
  if (bits < 80) return 3;
  return 4;
}

/**
 * A path or name as it really is: characters that change the direction text is drawn
 * in are replaced by a visible mark, so a name cannot be displayed as something else.
 */
function plainName(text) {
  return text.replace(/[\u202A-\u202E\u2066-\u2069]/g, "\uFFFD");
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
  renderAbout();
  if (state.summary && !$("result").hidden) renderResult(state.summary);
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
      label.textContent = `‎${plainName(path)}`;
      label.title = plainName(path);
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
  // Isolated so that the ID keeps its order inside right-to-left text.
  $("recovery-line").textContent = state.recoveryOn
    ? t("recovery.lineOn", { id: `\u2068${state.recoveryId}\u2069` })
    : t("recovery.lineOff");
  $("recovery-id-on").textContent = state.recoveryId ?? "";

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
  state.summary = summary;
  renderResult(summary);
  // The job is over: the secrets have no reason to stay in the page.
  clearSecrets();
  show("result");
}

function renderResult(summary) {
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
  if (summary.programs.length > 0) {
    // Isolated so that each name keeps its own order inside right-to-left text.
    const names = summary.programs.map((name) => `\u2068${plainName(name)}\u2069`).join(", ");
    notes.push(t("result.notePrograms", { names }));
  }
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
    ...failures.map(({ path, code, reason, detail }) => {
      const item = document.createElement("li");
      const why = document.createElement("span");
      // Disk errors come from Windows already worded; the rest are ours to translate.
      why.textContent = I18N.en[`err.${code}`] ? t(`err.${code}`) : reason;
      const where = document.createElement("code");
      where.textContent = plainName(detail ?? path);
      item.append(why, where);
      return item;
    }),
  );

  // What was written, by name. Nothing for the modes that write no new file.
  $("outputs-box").hidden = summary.outputs_total === 0;
  $("outputs-title").textContent = t("result.outputs", { count: fmt(summary.outputs_total) });
  $("outputs").replaceChildren(
    ...summary.outputs.map((name) => {
      const item = document.createElement("li");
      const label = document.createElement("code");
      label.textContent = plainName(name);
      item.append(label);
      return item;
    }),
  );
  const more = summary.outputs_total > summary.outputs.length;
  $("outputs-note").hidden = !more;
  $("outputs-note").classList.remove("error");
  $("outputs-note").textContent = more ? t("result.outputsFirst", { count: fmt(summary.outputs.length) }) : "";
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
  state.recoveryId = await invoke("recovery_status");
  state.recoveryOn = state.recoveryId !== null;
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
  const { key, id } = await invoke("recovery_create");
  $("recovery-key").textContent = key;
  $("recovery-id-created").textContent = id;
  $("recovery-saved").checked = false;
  $("recovery-done").disabled = true;
  $("recovery-feedback").textContent = "";
  showRecoveryView("recovery-created");
  await refreshRecovery();
}

// ---- About and updates ----

function renderAbout() {
  const { phase, version, error, downloaded, total } = state.update;
  const current = state.app.version;
  $("about-version").textContent = current;
  $("about-description").textContent = t("about.description");
  $("daily-check").checked = state.app.daily_check;

  // Isolated so that version numbers keep their order inside right-to-left text.
  const values = { version: `\u2068${version}\u2069`, current: `\u2068${current}\u2069` };
  let status = "";
  if (error) {
    status = t(`err.${error}`);
  } else if (phase === "checking") {
    status = t("update.checking");
  } else if (phase === "current") {
    status = t("update.current");
  } else if (phase === "available") {
    status = t(state.app.installed ? "update.available" : "update.portable", values);
  } else if (phase === "downloading") {
    const percent = total ? `${Math.floor((downloaded / total) * 100)}%` : formatBytes(downloaded);
    status = t("update.downloading", { ...values, percent: `\u2068${percent}\u2069` });
  } else if (phase === "ready") {
    status = t("update.ready", values);
  } else if (phase === "installing") {
    status = t("update.installing");
  }
  $("update-status").textContent = status;
  $("update-status").hidden = status === "";
  $("update-status").classList.toggle("error", Boolean(error));

  $("update-progress").hidden = phase !== "downloading";
  $("update-bar").style.width = total ? `${((downloaded / total) * 100).toFixed(1)}%` : "0";

  const working = phase === "checking" || phase === "downloading" || phase === "installing";
  $("update-check").disabled = working;
  $("update-download").hidden = !(phase === "available" && state.app.installed);
  $("update-install").hidden = phase !== "ready";
  $("update-releases").hidden = !(phase === "available" && !state.app.installed);
  // A new version is waiting: say so on the header button.
  $("update-dot").hidden = !["available", "downloading", "ready"].includes(phase);
}

function setUpdate(changes) {
  state.update = { ...state.update, error: null, ...changes };
  renderAbout();
}

async function openAbout() {
  state.app = await invoke("app_info");
  renderAbout();
  $("about-dialog").showModal();
}

/** `automatic` is the daily check: silent unless it finds a new version. */
async function checkForUpdates(automatic) {
  const busy = ["checking", "downloading", "ready", "installing"].includes(state.update.phase);
  if (automatic && busy) return;
  if (!automatic) setUpdate({ phase: "checking" });
  try {
    const result = await invoke("update_check", { automatic });
    if (result.status === "available") {
      setUpdate({ phase: "available", version: result.version });
    } else if (result.status === "current" && !automatic) {
      setUpdate({ phase: "current", version: null });
    }
  } catch (err) {
    if (!automatic) setUpdate({ phase: "idle", error: updateError(err) });
  }
}

/** The identifier of an update problem, as the interface words it. */
function updateError(err) {
  const code = String(err) === "busy" ? "update_busy" : String(err);
  return I18N.en[`err.${code}`] ? code : "update_failed";
}

async function downloadUpdate() {
  // A job on screen must end first; the app checks this again on its side.
  if (!$("working").hidden) {
    setUpdate({ error: "update_busy" });
    return;
  }
  setUpdate({ phase: "downloading", downloaded: 0, total: null });
  try {
    await invoke("update_download");
    setUpdate({ phase: "ready" });
  } catch (err) {
    setUpdate({ phase: "available", error: updateError(err) });
  }
}

async function installUpdate() {
  if (!$("working").hidden) {
    setUpdate({ error: "update_busy" });
    return;
  }
  setUpdate({ phase: "installing" });
  try {
    // Does not come back when it works: the app closes as the installer starts.
    await invoke("update_install");
  } catch (err) {
    setUpdate({ phase: "available", error: updateError(err) });
  }
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
$("show-outputs").addEventListener("click", async () => {
  try {
    await invoke("show_outputs");
  } catch (err) {
    $("outputs-note").textContent = I18N.en[`err.${err}`] ? t(`err.${err}`) : String(err);
    $("outputs-note").classList.add("error");
    $("outputs-note").hidden = false;
  }
});

$("open-about").addEventListener("click", openAbout);
$("about-close").addEventListener("click", () => $("about-dialog").close());
for (const button of document.querySelectorAll("[data-link]")) {
  button.addEventListener("click", () => invoke("open_link", { link: button.dataset.link }));
}
$("update-releases").addEventListener("click", () => invoke("open_link", { link: "releases" }));
$("update-check").addEventListener("click", () => checkForUpdates(false));
$("update-download").addEventListener("click", downloadUpdate);
$("update-install").addEventListener("click", installUpdate);
$("daily-check").addEventListener("change", async () => {
  const enabled = $("daily-check").checked;
  try {
    await invoke("set_daily_check", { enabled });
    state.app.daily_check = enabled;
    // Switched on: the first daily check is due now.
    if (enabled) checkForUpdates(true);
  } catch {
    $("daily-check").checked = state.app.daily_check;
  }
});

document.addEventListener("keydown", (event) => {
  const idle = !$("setup").hidden && !$("recovery-dialog").open && !$("about-dialog").open;
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
listen("update-progress", (event) => {
  if (state.update.phase !== "downloading") return;
  state.update = { ...state.update, ...event.payload };
  renderAbout();
});
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
invoke("app_info").then((info) => {
  state.app = info;
  renderAbout();
});
// The daily check, when it is switched on: once now, then whenever a day has passed
// while the app stays open. The app decides whether one is due.
checkForUpdates(true);
setInterval(() => checkForUpdates(true), 60 * 60 * 1000);
invoke("launch_request").then((request) => {
  if (request) openRequest(request);
});
