use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use topal_core::batch::{self, Job, Mode, Options, Progress, Unlock};
use topal_core::recovery::RecoveryKey;
use topal_core::{Error, KdfParams};

const FAST: KdfParams = KdfParams { memory_kib: 1024, passes: 1, lanes: 1 };

fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().is_file())
        .map(|e| (e.path().strip_prefix(dir).unwrap().to_owned(), fs::read(e.path()).unwrap()))
        .collect()
}

fn make_tree(dir: &Path) {
    fs::create_dir_all(dir.join("nested/مجلد")).unwrap();
    fs::write(dir.join("empty.bin"), b"").unwrap();
    fs::write(dir.join("notes.txt"), b"hello").unwrap();
    fs::write(dir.join("nested/photo one.jpg"), vec![7u8; 300_000]).unwrap();
    fs::write(dir.join("nested/مجلد/فيديو.mp4"), vec![9u8; (1 << 20) + 17]).unwrap();
}

fn encrypt(password: &str) -> Job<'_> {
    Job::Encrypt { password, recovery: None }
}

fn decrypt(password: &str) -> Job<'_> {
    Job::Decrypt(Unlock::Password(password))
}

fn run_paths(job: &Job, paths: &[PathBuf], options: &Options) -> batch::Summary {
    let scan = batch::scan(job.mode(), paths, options);
    assert!(scan.warnings.is_empty(), "{:?}", scan.warnings);
    let progress = Progress::default();
    let summary = batch::run(job, &scan.items, FAST, options, &progress).unwrap();
    assert_eq!(progress.bytes.load(Ordering::Relaxed), scan.total_bytes());
    summary
}

fn run(job: &Job, dir: &Path, options: &Options) -> batch::Summary {
    run_paths(job, &[dir.to_owned()], options)
}

fn counts(summary: &batch::Summary) -> (usize, usize, usize) {
    (summary.done, summary.skipped, summary.failures.len())
}

fn delete() -> Options {
    Options { delete_source: true, ..Options::default() }
}

#[test]
fn folder_roundtrip_with_source_deletion() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    let original = snapshot(dir.path());

    let summary = run(&encrypt("pw"), dir.path(), &delete());
    assert_eq!(counts(&summary), (4, 0, 0));
    let sealed = snapshot(dir.path());
    assert_eq!(sealed.len(), 4);
    assert!(sealed.keys().all(|p| p.extension().unwrap() == "topal"));

    let summary = run(&decrypt("pw"), dir.path(), &delete());
    assert_eq!(counts(&summary), (4, 0, 0));
    assert_eq!(snapshot(dir.path()), original);
}

#[test]
fn rerun_skips_finished_files_and_keeps_sources() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());

    let summary = run(&encrypt("pw"), dir.path(), &Options::default());
    assert_eq!(summary.done, 4);
    assert_eq!(snapshot(dir.path()).len(), 8, "sources are kept by default");

    let summary = run(&encrypt("pw"), dir.path(), &Options::default());
    assert_eq!(counts(&summary), (0, 4, 0));
}

#[test]
fn wrong_password_fails_every_file_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    run(&encrypt("pw"), dir.path(), &delete());
    let sealed = snapshot(dir.path());

    let summary = run(&decrypt("other"), dir.path(), &delete());
    assert_eq!(counts(&summary), (0, 0, 4));
    assert!(summary.failures.iter().all(|(_, err)| matches!(err, Error::WrongPassword)));
    assert_eq!(snapshot(dir.path()), sealed, "no outputs, no temp files, sources intact");
}

#[test]
fn cancelled_batch_leaves_no_partial_files() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    let before = snapshot(dir.path());

    let options = Options::default();
    let scan = batch::scan(Mode::Encrypt, &[dir.path().to_owned()], &options);
    let progress = Progress::default();
    progress.cancel.store(true, Ordering::Relaxed);
    let summary = batch::run(&encrypt("pw"), &scan.items, FAST, &options, &progress).unwrap();
    assert!(summary.cancelled);
    assert_eq!(counts(&summary), (0, 0, 0));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn original_name_survives_renaming_the_encrypted_file() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("صورة.jpg"), b"pixels").unwrap();
    run(&encrypt("pw"), dir.path(), &delete());
    fs::rename(dir.path().join("صورة.jpg.topal"), dir.path().join("a1.topal")).unwrap();

    let summary = run(&decrypt("pw"), dir.path(), &delete());
    assert_eq!(counts(&summary), (1, 0, 0));
    let files = snapshot(dir.path());
    assert_eq!(files.len(), 1);
    assert_eq!(files[Path::new("صورة.jpg")], b"pixels");
}

#[test]
fn version_1_files_still_decrypt() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let dir = tempfile::tempdir().unwrap();
    // Renamed on purpose: version 1 has no recorded name, so the output is named after
    // the encrypted file.
    fs::copy(fixtures.join("v1-sample.txt.topal"), dir.path().join("old.txt.topal")).unwrap();

    let summary = run(&Job::Verify(Unlock::Password("topal-test")), dir.path(), &Options::default());
    assert_eq!(counts(&summary), (1, 0, 0));
    let summary = run(&decrypt("topal-test"), dir.path(), &Options::default());
    assert_eq!(counts(&summary), (1, 0, 0));
    assert_eq!(
        fs::read(dir.path().join("old.txt")).unwrap(),
        fs::read(fixtures.join("v1-sample.txt")).unwrap()
    );
}

#[test]
fn hidden_names_pack_a_folder_into_one_file_and_restore_it() {
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("صور العطلة");
    make_tree(&folder);
    fs::create_dir(folder.join("empty folder")).unwrap();
    let original = snapshot(&folder);
    let loose = root.path().join("loose.txt");
    fs::write(&loose, b"loose").unwrap();

    let options = Options { hide_names: true, delete_source: true, ..Options::default() };
    let summary = run_paths(&encrypt("pw"), &[folder.clone(), loose], &options);
    assert_eq!(counts(&summary), (2, 0, 0));
    assert!(!folder.exists(), "the packed folder is removed");

    let sealed = snapshot(root.path());
    assert_eq!(sealed.len(), 2, "one file for the folder, one for the loose file");
    for (name, bytes) in &sealed {
        let name = name.to_string_lossy();
        assert_eq!(name.len(), "0123456789abcdef.topal".len(), "{name}");
        assert!(!bytes.windows(5).any(|w| w == b"notes"), "names are encrypted");
    }

    let summary = run(&decrypt("pw"), root.path(), &delete());
    assert_eq!(counts(&summary), (2, 0, 0));
    assert_eq!(snapshot(&folder), original);
    assert!(folder.join("empty folder").is_dir());
    assert_eq!(fs::read(root.path().join("loose.txt")).unwrap(), b"loose");
    assert_eq!(snapshot(root.path()).len(), original.len() + 1, "nothing else is left");
}

#[test]
fn a_packed_folder_is_never_unpacked_over_an_existing_one() {
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("docs");
    make_tree(&folder);
    let options = Options { hide_names: true, ..Options::default() };
    run_paths(&encrypt("pw"), &[folder.clone()], &options);

    let force = Options { force: true, ..Options::default() };
    let summary = run(&decrypt("pw"), root.path(), &force);
    assert_eq!(counts(&summary), (0, 1, 0), "the folder still exists, so it is skipped");
}

#[test]
fn output_folder_keeps_the_structure_and_leaves_sources_alone() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("photos");
    make_tree(&source);
    let original = snapshot(&source);
    let sealed_dir = root.path().join("sealed");
    let plain_dir = root.path().join("plain");

    let to_sealed = Options { output_dir: Some(sealed_dir.clone()), ..Options::default() };
    let summary = run(&encrypt("pw"), &source, &to_sealed);
    assert_eq!(counts(&summary), (4, 0, 0));
    assert_eq!(snapshot(&source), original, "nothing is written beside the sources");
    assert!(sealed_dir.join("photos/nested/مجلد/فيديو.mp4.topal").is_file());

    let to_plain = Options { output_dir: Some(plain_dir.clone()), ..Options::default() };
    let summary = run(&decrypt("pw"), &sealed_dir.join("photos"), &to_plain);
    assert_eq!(counts(&summary), (4, 0, 0));
    assert_eq!(snapshot(&plain_dir.join("photos")), original);
}

#[test]
fn same_name_from_two_places_does_not_silently_lose_one() {
    let root = tempfile::tempdir().unwrap();
    for (dir, content) in [("a", "first"), ("b", "second")] {
        fs::create_dir(root.path().join(dir)).unwrap();
        fs::write(root.path().join(dir).join("report.txt"), content).unwrap();
    }
    let out = root.path().join("out");
    let options = Options { output_dir: Some(out.clone()), ..Options::default() };
    let paths = [root.path().join("a/report.txt"), root.path().join("b/report.txt")];
    let summary = run_paths(&encrypt("pw"), &paths, &options);
    assert_eq!(counts(&summary), (1, 0, 1));
    assert!(matches!(summary.failures[0], (ref path, Error::OutputExists) if *path == paths[1]));
    assert_eq!(snapshot(&out).len(), 1);
}

#[test]
fn verify_reports_damage_and_wrong_passwords_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    run(&encrypt("pw"), dir.path(), &delete());

    let verify = |password| run(&Job::Verify(Unlock::Password(password)), dir.path(), &Options::default());
    assert_eq!(counts(&verify("pw")), (4, 0, 0));
    assert_eq!(counts(&verify("nope")), (0, 0, 4));

    let victim = dir.path().join("nested/مجلد/فيديو.mp4.topal");
    let mut bytes = fs::read(&victim).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(&victim, bytes).unwrap();
    let before = snapshot(dir.path());

    let summary = verify("pw");
    assert_eq!(counts(&summary), (3, 0, 1));
    assert!(matches!(summary.failures[0], (ref path, Error::Corrupted) if *path == victim));
    assert_eq!(snapshot(dir.path()), before, "verifying writes nothing");
}

#[test]
fn password_change_keeps_content_and_drops_the_old_password() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    let original = snapshot(dir.path());
    run(&encrypt("old"), dir.path(), &delete());
    let sizes = |dir: &Path| -> Vec<usize> { snapshot(dir).values().map(Vec::len).collect() };
    let before = sizes(dir.path());

    let wrong = Job::ChangePassword { unlock: Unlock::Password("bad"), new_password: "new" };
    assert_eq!(counts(&run(&wrong, dir.path(), &Options::default())), (0, 0, 4));

    let change = Job::ChangePassword { unlock: Unlock::Password("old"), new_password: "new" };
    assert_eq!(counts(&run(&change, dir.path(), &Options::default())), (4, 0, 0));
    assert_eq!(sizes(dir.path()), before, "files keep their size: only headers change");

    assert_eq!(counts(&run(&decrypt("old"), dir.path(), &Options::default())), (0, 0, 4));
    assert_eq!(counts(&run(&decrypt("new"), dir.path(), &delete())), (4, 0, 0));
    assert_eq!(snapshot(dir.path()), original);
}

#[test]
fn recovery_key_decrypts_and_resets_a_forgotten_password() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    let original = snapshot(dir.path());
    let key = RecoveryKey::generate();
    let job = Job::Encrypt { password: "forgotten", recovery: Some(key.public()) };
    run(&job, dir.path(), &delete());

    let stranger = RecoveryKey::generate();
    let summary = run(&Job::Verify(Unlock::RecoveryKey(&stranger)), dir.path(), &Options::default());
    assert_eq!(counts(&summary), (0, 0, 4));
    assert!(summary.failures.iter().all(|(_, err)| matches!(err, Error::WrongRecoveryKey)));

    let reset = Job::ChangePassword { unlock: Unlock::RecoveryKey(&key), new_password: "fresh" };
    assert_eq!(counts(&run(&reset, dir.path(), &Options::default())), (4, 0, 0));
    assert_eq!(counts(&run(&decrypt("fresh"), dir.path(), &Options::default())), (4, 0, 0));
    fs::remove_file(dir.path().join("notes.txt")).unwrap();

    // The key itself still opens everything, here cleaning up after the run above.
    let summary = run(&Job::Decrypt(Unlock::RecoveryKey(&key)), dir.path(), &delete());
    assert_eq!(counts(&summary), (4, 0, 0));
    assert_eq!(snapshot(dir.path()), original);
}

#[test]
fn resuming_with_deletion_cleans_up_what_an_interrupted_run_left() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    let original = snapshot(dir.path());

    // An interrupted run: everything encrypted, no original deleted yet.
    run(&encrypt("pw"), dir.path(), &Options::default());
    // One original changed afterwards, so its encrypted copy no longer matches.
    fs::write(dir.path().join("notes.txt"), b"edited later").unwrap();

    let summary = run(&encrypt("pw"), dir.path(), &delete());
    assert_eq!(counts(&summary), (3, 1, 0));
    let left = snapshot(dir.path());
    assert_eq!(left.len(), 5, "three originals removed, the edited one and its copy kept");
    assert_eq!(left[Path::new("notes.txt")], b"edited later");

    // With another password nothing matches, so nothing is deleted.
    let summary = run(&encrypt("other"), dir.path(), &delete());
    assert_eq!(counts(&summary), (0, 1, 0));
    assert_eq!(snapshot(dir.path()), left);

    // The same on the way back: outputs exist, so only the matching sources go.
    fs::remove_file(dir.path().join("notes.txt")).unwrap();
    run(&decrypt("pw"), dir.path(), &Options::default());
    assert_eq!(snapshot(dir.path()).len(), 8);
    let summary = run(&decrypt("pw"), dir.path(), &delete());
    assert_eq!(counts(&summary), (4, 0, 0));
    assert_eq!(snapshot(dir.path()), original);
}

#[test]
fn a_folder_with_a_long_non_latin_name_comes_back_after_its_original_is_deleted() {
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("docs");
    fs::create_dir(&folder).unwrap();
    // Legal on Windows (134 UTF-16 units) although it is 264 bytes of UTF-8.
    let name = format!("{}.txt", "ص".repeat(130));
    fs::write(folder.join(&name), b"important").unwrap();
    let original = snapshot(&folder);

    let options = Options { hide_names: true, delete_source: true, ..Options::default() };
    assert_eq!(counts(&run_paths(&encrypt("pw"), &[folder.clone()], &options)), (1, 0, 0));
    assert!(!folder.exists());

    assert_eq!(counts(&run(&decrypt("pw"), root.path(), &delete())), (1, 0, 0));
    assert_eq!(snapshot(&folder), original);
}

#[cfg(windows)]
#[test]
fn a_folder_that_could_not_be_unpacked_is_not_packed_and_nothing_is_deleted() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("docs");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("fine.txt"), b"fine").unwrap();
    // Two names that differ only in an unpaired surrogate: valid on NTFS, but neither
    // can be written down as text, and both would turn into the same replacement.
    for unit in [0xD800u16, 0xD801] {
        let wide: Vec<u16> = "a".encode_utf16().chain([unit]).chain(".txt".encode_utf16()).collect();
        fs::write(folder.join(OsString::from_wide(&wide)), b"x").unwrap();
    }
    let before = fs::read_dir(&folder).unwrap().count();

    let options = Options { hide_names: true, delete_source: true, ..Options::default() };
    let summary = run_paths(&encrypt("pw"), &[folder.clone()], &options);
    assert_eq!(counts(&summary), (0, 0, 1));
    assert!(matches!(summary.failures[0].1, Error::UnsupportedName(_)), "{:?}", summary.failures);
    assert_eq!(fs::read_dir(&folder).unwrap().count(), before, "the folder is untouched");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1, "no output was written");
}

#[test]
fn verify_fails_for_a_folder_that_could_not_be_unpacked() {
    let root = tempfile::tempdir().unwrap();
    let archive = |rel: &str| {
        let mut out = vec![1u8];
        out.extend_from_slice(&(rel.len() as u16).to_le_bytes());
        out.extend_from_slice(rel.as_bytes());
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(b"x\0");
        out
    };
    let encryptor = topal_core::Encryptor::new("pw", FAST).unwrap();
    for (file, rel) in [("good.topal", "a/b.txt"), ("bad.topal", "a/../../b.txt")] {
        let out = fs::File::create(root.path().join(file)).unwrap();
        encryptor.encrypt(topal_core::Kind::Folder, "docs", &archive(rel)[..], out).unwrap();
    }
    let summary = run(&Job::Verify(Unlock::Password("pw")), root.path(), &Options::default());
    assert_eq!(counts(&summary), (1, 0, 1));
    assert!(summary.failures[0].0.ends_with("bad.topal"));
    assert!(matches!(summary.failures[0].1, Error::UnsafePath));
}

#[test]
fn forced_decryption_never_overwrites_an_output_of_the_same_run() {
    let root = tempfile::tempdir().unwrap();
    for (dir, content) in [("x", "content of x"), ("y", "content of y")] {
        fs::create_dir(root.path().join(dir)).unwrap();
        fs::write(root.path().join(dir).join("report.txt"), content).unwrap();
    }
    let plain = [root.path().join("x/report.txt"), root.path().join("y/report.txt")];
    assert_eq!(counts(&run_paths(&encrypt("pw"), &plain, &delete())), (2, 0, 0));
    let sealed = [root.path().join("x/report.txt.topal"), root.path().join("y/report.txt.topal")];

    // Both decrypt to `out/report.txt`. An older file of that name may be replaced...
    let out = root.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("report.txt"), b"from an earlier run").unwrap();
    let options =
        Options { force: true, delete_source: true, output_dir: Some(out.clone()), ..Options::default() };
    let summary = run_paths(&decrypt("pw"), &sealed, &options);

    // ...but only one of the two takes its place, and the other keeps its source.
    assert_eq!(counts(&summary), (1, 0, 1));
    assert!(matches!(summary.failures[0].1, Error::OutputExists));
    let kept = &summary.failures[0].0;
    assert!(kept.exists(), "the source that lost the name is not deleted");
    let (won, lost) = if kept == &sealed[0] { ("content of y", &sealed[1]) } else { ("content of x", &sealed[0]) };
    assert!(!lost.exists(), "the source that was decrypted is deleted");
    assert_eq!(fs::read_to_string(out.join("report.txt")).unwrap(), won);
}

/// Writes an encrypted file called `file` whose stored original name is `stored`.
fn seal_as(dir: &Path, file: &str, stored: &str, content: &[u8]) -> PathBuf {
    let path = dir.join(file);
    topal_core::Encryptor::new("pw", FAST)
        .unwrap()
        .encrypt(topal_core::Kind::File, stored, content, fs::File::create(&path).unwrap())
        .unwrap();
    path
}

#[test]
fn force_only_overwrites_the_output_the_file_name_shows() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("important.docx"), b"the user's own document").unwrap();
    fs::write(root.path().join("notes.txt"), b"an older copy").unwrap();
    // Looks like notes.txt, but the name stored inside points at another file.
    let disguised = seal_as(root.path(), "notes.txt.topal", "important.docx", b"replaced");
    let force = Options { force: true, delete_source: true, ..Options::default() };
    let summary = run_paths(&decrypt("pw"), &[disguised.clone()], &force);
    assert_eq!(counts(&summary), (0, 1, 0), "skipped, not overwritten");
    assert_eq!(fs::read(root.path().join("important.docx")).unwrap(), b"the user's own document");
    assert!(disguised.exists());

    // The honest case still overwrites.
    let honest = seal_as(root.path(), "notes.txt.topal", "notes.txt", b"a newer copy");
    assert_eq!(counts(&run_paths(&decrypt("pw"), &[honest], &force)), (1, 0, 0));
    assert_eq!(fs::read(root.path().join("notes.txt")).unwrap(), b"a newer copy");
}

#[test]
fn a_program_hidden_behind_another_name_is_pointed_out() {
    let root = tempfile::tempdir().unwrap();
    seal_as(root.path(), "holiday-photo.jpg.topal", "viewer.cmd", b"rem harmless test content");
    seal_as(root.path(), "tool.cmd.topal", "tool.cmd", b"rem harmless test content");
    seal_as(root.path(), "a1b2.topal", "photo.jpg", b"not a program");
    let summary = run(&decrypt("pw"), root.path(), &Options::default());
    assert_eq!(counts(&summary), (3, 0, 0));
    assert_eq!(summary.program_outputs, [root.path().join("viewer.cmd")]);
}

#[test]
fn a_stored_name_that_would_display_reversed_is_not_used() {
    let root = tempfile::tempdir().unwrap();
    // Would be shown as "invoiceexe.pdf" while really ending in ".exe".
    seal_as(root.path(), "invoice.pdf.topal", "invoice\u{202E}fdp.exe", b"harmless test content");
    let summary = run(&decrypt("pw"), root.path(), &Options::default());
    assert_eq!(counts(&summary), (1, 0, 0));
    assert!(summary.program_outputs.is_empty());
    assert_eq!(fs::read(root.path().join("invoice.pdf")).unwrap(), b"harmless test content");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2, "only the expected name was written");
}

#[cfg(windows)]
#[test]
fn outputs_inherit_the_download_mark_of_the_encrypted_file() {
    let mark = b"[ZoneTransfer]\r\nZoneId=3\r\n";
    let stream = |path: &Path| {
        let mut name = path.as_os_str().to_owned();
        name.push(":Zone.Identifier");
        PathBuf::from(name)
    };
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("docs");
    make_tree(&folder);
    fs::write(root.path().join("single.txt"), b"single").unwrap();
    let options = Options { hide_names: true, delete_source: true, ..Options::default() };
    run_paths(&encrypt("pw"), &[folder.clone(), root.path().join("single.txt")], &options);

    // As if both encrypted files had been downloaded.
    let sealed: Vec<PathBuf> = fs::read_dir(root.path()).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(sealed.len(), 2);
    for path in &sealed {
        fs::write(stream(path), mark).unwrap();
    }
    assert_eq!(counts(&run(&decrypt("pw"), root.path(), &Options::default())), (2, 0, 0));
    assert_eq!(fs::read(stream(&root.path().join("single.txt"))).unwrap(), mark);
    assert_eq!(fs::read(stream(&folder.join("notes.txt"))).unwrap(), mark);
    assert_eq!(fs::read(stream(&folder.join("nested/photo one.jpg"))).unwrap(), mark);

    // A file that was never marked produces unmarked outputs.
    let local = seal_as(root.path(), "local.txt.topal", "local.txt", b"local");
    run_paths(&decrypt("pw"), &[local], &Options::default());
    assert!(fs::read(stream(&root.path().join("local.txt"))).is_err());
}

#[test]
fn cancelling_stops_a_folder_that_is_being_unpacked() {
    let root = tempfile::tempdir().unwrap();
    // A small file that asks for a great many folders: all of it is read at once, so
    // only a check between entries can stop it.
    let mut archive = Vec::new();
    for index in 0..200_000u32 {
        let rel = format!("{index:x}");
        archive.push(2u8);
        archive.extend_from_slice(&(rel.len() as u16).to_le_bytes());
        archive.extend_from_slice(rel.as_bytes());
    }
    archive.push(0);
    let sealed = root.path().join("many.topal");
    topal_core::Encryptor::new("pw", FAST)
        .unwrap()
        .encrypt(topal_core::Kind::Folder, "many", &archive[..], fs::File::create(&sealed).unwrap())
        .unwrap();

    let options = Options::default();
    let scan = batch::scan(Mode::Decrypt, &[sealed.clone()], &options);
    let progress = Progress::default();
    let started = std::time::Instant::now();
    let summary = std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(300));
            progress.cancel.store(true, Ordering::Relaxed);
        });
        batch::run(&decrypt("pw"), &scan.items, FAST, &options, &progress).unwrap()
    });
    assert!(summary.cancelled);
    assert_eq!(counts(&summary), (0, 0, 0), "{:?} after {:?}", summary.failures, started.elapsed());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1, "nothing is left but the source");
}

fn change(old: &'static str, new: &'static str) -> Job<'static> {
    Job::ChangePassword { unlock: Unlock::Password(old), new_password: new }
}

fn backup_of(sealed: &Path) -> PathBuf {
    let mut name = sealed.as_os_str().to_owned();
    name.push(".header-backup");
    PathBuf::from(name)
}

#[test]
fn a_password_change_cut_short_is_repaired_from_the_saved_header() {
    let root = tempfile::tempdir().unwrap();
    let sealed = seal_as(root.path(), "a.txt.topal", "a.txt", b"precious");

    // An ordinary change leaves nothing beside the file.
    assert_eq!(counts(&run_paths(&change("pw", "second"), &[sealed.clone()], &Options::default())), (1, 0, 0));
    assert!(!backup_of(&sealed).exists());

    // As if the next change had been cut off mid-write: the old header was saved, and
    // the one in the file is half old, half new, opening with no password at all.
    let mut bytes = fs::read(&sealed).unwrap();
    fs::write(backup_of(&sealed), &bytes[..210.min(bytes.len())]).unwrap();
    for byte in &mut bytes[60..100] {
        *byte ^= 0x5a;
    }
    fs::write(&sealed, &bytes).unwrap();
    let verify = |password: &'static str| {
        counts(&run_paths(&Job::Verify(Unlock::Password(password)), &[sealed.clone()], &Options::default()))
    };
    assert_eq!(verify("second"), (0, 0, 1), "the damaged file opens with nothing");

    assert_eq!(counts(&run_paths(&change("second", "third"), &[sealed.clone()], &Options::default())), (1, 0, 0));
    assert!(!backup_of(&sealed).exists(), "the saved header is removed once the change is complete");
    assert_eq!(verify("third"), (1, 0, 0));
    assert_eq!(counts(&run_paths(&decrypt("third"), &[sealed], &Options::default())), (1, 0, 0));
    assert_eq!(fs::read(root.path().join("a.txt")).unwrap(), b"precious");
}

#[test]
fn a_saved_header_from_another_file_is_never_applied() {
    let root = tempfile::tempdir().unwrap();
    let target = seal_as(root.path(), "target.topal", "target.txt", b"target");
    let other = seal_as(root.path(), "other.topal", "other.txt", b"other");
    // The target's header no longer opens, and beside it lies the header of a
    // different file that the same password does open.
    let mut bytes = fs::read(&target).unwrap();
    for byte in &mut bytes[60..100] {
        *byte ^= 0x5a;
    }
    fs::write(&target, &bytes).unwrap();
    fs::write(backup_of(&target), &fs::read(&other).unwrap()[..130]).unwrap();

    let summary = run_paths(&change("pw", "new"), &[target.clone()], &Options::default());
    assert_eq!(counts(&summary), (0, 0, 1));
    assert_eq!(fs::read(&target).unwrap(), bytes, "the file is left exactly as it was");
}

#[cfg(windows)]
#[test]
fn leftovers_of_a_killed_run_are_removed_but_a_running_one_is_left_alone() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("plain.txt"), b"plain").unwrap();
    // What a killed decryption leaves: a half-written file, and a half-filled folder
    // whose lock file nobody holds any more.
    fs::write(root.path().join(".topal-tmp-AbC123"), b"half-written plaintext").unwrap();
    let dead = root.path().join(".topal-tmp-dEaD00");
    fs::create_dir_all(dead.join("content")).unwrap();
    fs::write(dead.join("lock"), b"").unwrap();
    fs::write(dead.join("content/secret.txt"), b"plaintext").unwrap();
    // What another run that is still going has: files it keeps open.
    let live_file = root.path().join(".topal-tmp-LiVe01");
    let _held = fs::File::create(&live_file).unwrap();
    let live_dir = root.path().join(".topal-tmp-LiVe02");
    fs::create_dir(&live_dir).unwrap();
    let _lock = fs::File::create(live_dir.join("lock")).unwrap();
    // And a file of the user's that merely looks similar.
    fs::write(root.path().join(".topal-tmp-notes.txt"), b"mine").unwrap();

    let summary = run_paths(&encrypt("pw"), &[root.path().join("plain.txt")], &Options::default());
    assert_eq!(counts(&summary), (1, 0, 0));
    assert!(!root.path().join(".topal-tmp-AbC123").exists(), "stale file removed");
    assert!(!dead.exists(), "stale folder removed");
    assert!(live_file.exists() && live_dir.exists(), "a running job's files are untouched");
    assert!(root.path().join(".topal-tmp-notes.txt").exists(), "not one of ours");
}

#[test]
fn a_failure_before_cancelling_is_still_reported() {
    let root = tempfile::tempdir().unwrap();
    let broken = root.path().join("a-broken.topal");
    fs::write(&broken, b"this is not an encrypted file").unwrap();
    let mut archive = Vec::new();
    for index in 0..200_000u32 {
        let rel = format!("{index:x}");
        archive.push(2u8);
        archive.extend_from_slice(&(rel.len() as u16).to_le_bytes());
        archive.extend_from_slice(rel.as_bytes());
    }
    archive.push(0);
    let slow = root.path().join("b-slow.topal");
    topal_core::Encryptor::new("pw", FAST)
        .unwrap()
        .encrypt(topal_core::Kind::Folder, "slow", &archive[..], fs::File::create(&slow).unwrap())
        .unwrap();

    // One worker, so the broken file is finished before the slow one starts.
    let options = Options { jobs: Some(1), ..Options::default() };
    let scan = batch::scan(Mode::Decrypt, &[broken.clone(), slow], &options);
    let progress = Progress::default();
    let summary = std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(300));
            progress.cancel.store(true, Ordering::Relaxed);
        });
        batch::run(&decrypt("pw"), &scan.items, FAST, &options, &progress).unwrap()
    });
    assert!(summary.cancelled);
    assert_eq!(summary.failures.len(), 1, "{:?}", summary.failures);
    assert_eq!(summary.failures[0].0, broken);
    assert!(matches!(summary.failures[0].1, Error::NotTopal));
}
