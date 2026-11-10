"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

const COPY = {
  encrypt: {
    verb: "Encrypt",
    working: "Encrypting…",
    done: "encrypted",
    deleteLabel: "Delete the originals after encrypting",
    deleteNote:
      "Each encrypted file is decrypted back and checked before its original is removed. " +
      "This is a normal delete, not a secure wipe.",
    empty: "No files to encrypt in this selection.",
  },
  decrypt: {
    verb: "Decrypt",
    working: "Decrypting…",
    done: "decrypted",
    deleteLabel: "Delete the .topal files after decrypting",
    deleteNote: "Each .topal file is removed only after its content is fully restored.",
    empty: "No .topal files in this selection.",
  },
};

const state = {
  mode: "encrypt",
  paths: [],
  scan: null, // { files, bytes, warnings } for the current paths and mode
  scanToken: 0,
  startedAt: 0,
};

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(value < 10 ? 2 : 1)} ${units[unit]}`;
}

function plural(count, word) {
  return `${count.toLocaleString()} ${word}${count === 1 ? "" : "s"}`;
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

function render() {
  const copy = COPY[state.mode];
  const encrypting = state.mode === "encrypt";
  $("mode-encrypt").setAttribute("aria-selected", String(encrypting));
  $("mode-decrypt").setAttribute("aria-selected", String(!encrypting));
  $("confirm-field").hidden = !encrypting;
  $("no-recovery").hidden = !encrypting;
  $("delete-label").textContent = copy.deleteLabel;
  $("delete-note").textContent = copy.deleteNote;
  $("drop-title").textContent = encrypting
    ? "Drop files or folders here"
    : "Drop .topal files or folders here";

  $("selection").hidden = state.paths.length === 0;
  const list = $("paths");
  list.replaceChildren(
    ...state.paths.map((path) => {
      const item = document.createElement("li");
      const label = document.createElement("span");
      // Shown right-to-left so a long path is cut at its start, keeping the file name.
      label.textContent = `‎${path}`;
      label.title = path;
      const remove = document.createElement("button");
      remove.textContent = "×";
      remove.title = "Remove";
      remove.addEventListener("click", () => setPaths(state.paths.filter((p) => p !== path)));
      item.append(label, remove);
      return item;
    }),
  );

  const scan = state.scan;
  $("scan-summary").textContent = !scan
    ? "Scanning…"
    : scan.files === 0
      ? copy.empty
      : `${plural(scan.files, "file")} · ${formatBytes(scan.bytes)}`;
  const warnings = scan ? scan.warnings : [];
  $("scan-warnings").hidden = warnings.length === 0;
  $("scan-warnings").textContent =
    warnings.length === 0 ? "" : `${plural(warnings.length, "item")} could not be read and will be left out.`;

  const password = $("password").value;
  $("strength").hidden = !encrypting || password.length === 0;
  if (encrypting && password.length > 0) {
    const level = strength(password);
    $("strength-bar").className = `s${level}`;
    $("strength-label").textContent = ["", "Weak", "Fair", "Good", "Strong"][level];
  }

  const ready = scan && scan.files > 0;
  $("start").textContent = ready ? `${copy.verb} ${plural(scan.files, "file")}` : copy.verb;
  $("start").disabled = !ready || password.length === 0;
}

async function setPaths(paths) {
  state.paths = [...new Set(paths)];
  state.scan = null;
  $("error").hidden = true;
  const token = ++state.scanToken;
  render();
  if (state.paths.length === 0) return;
  const scan = await invoke("scan", { mode: state.mode, paths: state.paths });
  if (token === state.scanToken) {
    state.scan = scan;
    render();
  }
}

function setMode(mode) {
  if (mode === state.mode) return;
  state.mode = mode;
  $("delete-source").checked = false;
  setPaths(state.paths);
}

function fail(message) {
  $("error").textContent = message;
  $("error").hidden = false;
}

async function start() {
  const password = $("password").value;
  if (state.mode === "encrypt" && password !== $("confirm").value) {
    fail("The two passwords do not match.");
    return;
  }
  $("error").hidden = true;
  $("working-title").textContent = COPY[state.mode].working;
  $("progress-bar").style.width = "0";
  $("progress-percent").textContent = "0%";
  $("progress-detail").textContent = "Preparing key…";
  $("cancel").disabled = false;
  $("cancel").textContent = "Cancel";
  state.startedAt = performance.now();
  show("working");

  try {
    const summary = await invoke("start", {
      mode: state.mode,
      paths: state.paths,
      password,
      deleteSource: $("delete-source").checked,
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
    `${files.toLocaleString()} / ${totalFiles.toLocaleString()} files · ` +
    `${formatBytes(bytes)} of ${formatBytes(totalBytes)}${speed}`;
}

function showResult(summary) {
  const copy = COPY[state.mode];
  // Every file refusing the password is one problem, not hundreds: say so plainly.
  const wrongPassword =
    summary.done === 0 &&
    summary.failed > 0 &&
    summary.failures.every(({ reason }) => reason.startsWith("wrong password"));
  if (wrongPassword) summary.failures = [];
  $("result-title").textContent = summary.cancelled
    ? "Cancelled"
    : wrongPassword
      ? "Wrong password"
      : summary.failed > 0
        ? "Finished with problems"
        : "All done";
  $("result-done").textContent = summary.done.toLocaleString();
  $("result-done-label").textContent = copy.done;
  $("result-skipped").textContent = summary.skipped.toLocaleString();
  $("result-failed").textContent = summary.failed.toLocaleString();
  $("result-failed").parentElement.classList.toggle("bad", summary.failed > 0);

  const notes = [];
  if (summary.skipped > 0) notes.push("Skipped files already had an output next to them.");
  if (summary.cancelled) notes.push("Files that were not finished were left untouched.");
  if (wrongPassword) {
    notes.push("None of the files could be opened with this password. Nothing was changed.");
  } else if (summary.failed > summary.failures.length) {
    notes.push(`Showing the first ${summary.failures.length} failures.`);
  }
  $("result-note").hidden = notes.length === 0;
  $("result-note").textContent = notes.join(" ");

  $("failures").hidden = summary.failures.length === 0;
  $("failures").replaceChildren(
    ...summary.failures.map(({ path, reason }) => {
      const item = document.createElement("li");
      const why = document.createElement("span");
      why.textContent = reason;
      const where = document.createElement("code");
      where.textContent = path;
      item.append(why, where);
      return item;
    }),
  );
  show("result");
}

function reset() {
  $("password").value = "";
  $("confirm").value = "";
  $("delete-source").checked = false;
  setPaths([]);
  show("setup");
}

$("mode-encrypt").addEventListener("click", () => setMode("encrypt"));
$("mode-decrypt").addEventListener("click", () => setMode("decrypt"));
$("add-files").addEventListener("click", async () => {
  setPaths([...state.paths, ...(await invoke("pick_files"))]);
});
$("add-folders").addEventListener("click", async () => {
  setPaths([...state.paths, ...(await invoke("pick_folders"))]);
});
$("clear").addEventListener("click", () => setPaths([]));
$("password").addEventListener("input", render);
$("toggle-password").addEventListener("click", () => {
  const reveal = $("password").type === "password";
  $("password").type = reveal ? "text" : "password";
  $("confirm").type = reveal ? "text" : "password";
  $("toggle-password").textContent = reveal ? "Hide" : "Show";
});
$("start").addEventListener("click", start);
$("cancel").addEventListener("click", () => {
  $("cancel").disabled = true;
  $("cancel").textContent = "Cancelling…";
  invoke("cancel");
});
$("again").addEventListener("click", reset);
document.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !$("setup").hidden && !$("start").disabled) start();
});

listen("progress", (event) => onProgress(event.payload));
listen("tauri://drag-enter", () => $("drop").classList.add("over"));
listen("tauri://drag-leave", () => $("drop").classList.remove("over"));
listen("tauri://drag-drop", (event) => {
  $("drop").classList.remove("over");
  if (!$("setup").hidden) setPaths([...state.paths, ...event.payload.paths]);
});

render();
