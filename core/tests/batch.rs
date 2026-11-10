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
