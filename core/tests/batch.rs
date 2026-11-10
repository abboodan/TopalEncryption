use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use topal_core::batch::{self, Mode, Options, Progress};
use topal_core::KdfParams;

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

fn run(mode: Mode, dir: &Path, password: &str, options: Options) -> batch::Summary {
    let scan = batch::scan(mode, &[dir.to_owned()]);
    assert!(scan.warnings.is_empty());
    let progress = Progress::default();
    let summary = batch::run(mode, &scan.files, password, FAST, options, &progress).unwrap();
    assert_eq!(progress.bytes.load(Ordering::Relaxed), scan.total_bytes());
    summary
}

#[test]
fn folder_roundtrip_with_source_deletion() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    let original = snapshot(dir.path());
    let delete = Options { delete_source: true, ..Options::default() };

    let summary = run(Mode::Encrypt, dir.path(), "pw", delete);
    assert_eq!((summary.done, summary.skipped, summary.failures.len()), (4, 0, 0));
    let sealed = snapshot(dir.path());
    assert_eq!(sealed.len(), 4);
    assert!(sealed.keys().all(|p| p.extension().unwrap() == "topal"));

    let summary = run(Mode::Decrypt, dir.path(), "pw", delete);
    assert_eq!((summary.done, summary.skipped, summary.failures.len()), (4, 0, 0));
    assert_eq!(snapshot(dir.path()), original);
}

#[test]
fn rerun_skips_finished_files_and_keeps_sources() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());

    let summary = run(Mode::Encrypt, dir.path(), "pw", Options::default());
    assert_eq!(summary.done, 4);
    assert_eq!(snapshot(dir.path()).len(), 8, "sources are kept by default");

    let summary = run(Mode::Encrypt, dir.path(), "pw", Options::default());
    assert_eq!((summary.done, summary.skipped), (0, 4));
}

#[test]
fn wrong_password_fails_every_file_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    let delete = Options { delete_source: true, ..Options::default() };
    run(Mode::Encrypt, dir.path(), "pw", delete);
    let sealed = snapshot(dir.path());

    let summary = run(Mode::Decrypt, dir.path(), "other", delete);
    assert_eq!((summary.done, summary.failures.len()), (0, 4));
    assert_eq!(snapshot(dir.path()), sealed, "no outputs, no temp files, sources intact");
}

#[test]
fn cancelled_batch_leaves_no_partial_files() {
    let dir = tempfile::tempdir().unwrap();
    make_tree(dir.path());
    let before = snapshot(dir.path());

    let scan = batch::scan(Mode::Encrypt, &[dir.path().to_owned()]);
    let progress = Progress::default();
    progress.cancel.store(true, Ordering::Relaxed);
    let summary =
        batch::run(Mode::Encrypt, &scan.files, "pw", FAST, Options::default(), &progress).unwrap();
    assert!(summary.cancelled);
    assert_eq!((summary.done, summary.failures.len()), (0, 0));
    assert_eq!(snapshot(dir.path()), before);
}
