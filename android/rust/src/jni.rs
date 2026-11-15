//! The functions of `io.github.abboodan.topalencryption.core.Native`.
//!
//! Handles are pointers to boxed values, passed to Kotlin as `long`. Kotlin owns them and
//! frees each one exactly once, after every call that uses it has returned.
//!
//! File descriptors are passed in detached (`ParcelFileDescriptor.detachFd`): each call
//! takes ownership and closes them, whatever the outcome.
//!
//! Errors reach Kotlin as a `TopalException` whose message is `code|detail`.

use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;

use jni::objects::{JObject, JString, JValue};
use jni::sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use topal_core::archive::{self, Sink};
use topal_core::{Decryptor, Encryptor, Error};
use zeroize::Zeroizing;

use crate::{Control, Meter, Output};

const EXCEPTION: &str = "io/github/abboodan/topalencryption/core/TopalException";

type Outcome<T> = std::result::Result<T, Error>;

/// A Java exception is pending, or the JVM refused a call.
fn jni_failed(err: jni::errors::Error) -> io::Error {
    io::Error::other(err.to_string())
}

/// Runs `body`, turning an error or a panic into a Java exception and a default result.
fn guard<'local, T: Default>(
    env: &mut JNIEnv<'local>,
    body: impl FnOnce(&mut JNIEnv<'local>) -> Outcome<T>,
) -> T {
    let message = match catch_unwind(AssertUnwindSafe(|| body(env))) {
        Ok(Ok(value)) => return value,
        Ok(Err(err)) => format!("{}|{err}", crate::code(&err)),
        Err(_) => "internal|the native library failed unexpectedly".to_owned(),
    };
    // An exception thrown by a Kotlin callback is already on its way: leave it alone.
    if !env.exception_check().unwrap_or(false) {
        let _ = env.throw_new(EXCEPTION, message);
    }
    T::default()
}

fn text(env: &mut JNIEnv, value: &JString) -> Outcome<Zeroizing<String>> {
    let chars = env.get_string(value).map_err(jni_failed)?;
    Ok(Zeroizing::new(chars.into()))
}

fn optional_text(env: &mut JNIEnv, value: &JString) -> Outcome<Option<Zeroizing<String>>> {
    if value.as_raw().is_null() {
        Ok(None)
    } else {
        text(env, value).map(Some)
    }
}

fn boxed<T>(value: T) -> jlong {
    Box::into_raw(Box::new(value)) as jlong
}

/// # Safety
/// `handle` came from [`boxed`] with the same `T` and has not been freed.
unsafe fn borrow<'a, T>(handle: jlong) -> &'a T {
    &*(handle as *const T)
}

/// # Safety
/// As for [`borrow`], and nothing uses the handle afterwards.
unsafe fn free<T>(handle: jlong) {
    if handle != 0 {
        drop(Box::from_raw(handle as *mut T));
    }
}

/// Takes ownership of a detached descriptor.
fn owned(fd: jint) -> Outcome<File> {
    if fd < 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid file descriptor").into());
    }
    // SAFETY: Kotlin detached this descriptor and hands it over to us to close.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_newEncryptor<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    password: JString<'local>,
) -> jlong {
    guard(&mut env, |env| {
        let password = text(env, &password)?;
        Ok(boxed(crate::encryptor(&password)?))
    })
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_freeEncryptor(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) {
    // SAFETY: Kotlin frees each handle once, after its last use.
    unsafe { free::<Encryptor>(handle) }
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_newDecryptor<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    password: JString<'local>,
    recovery_key: JString<'local>,
) -> jlong {
    guard(&mut env, |env| {
        let password = text(env, &password)?;
        let recovery_key = optional_text(env, &recovery_key)?;
        Ok(boxed(crate::decryptor(&password, recovery_key.as_ref().map(|key| key.as_str()))?))
    })
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_freeDecryptor(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) {
    // SAFETY: Kotlin frees each handle once, after its last use.
    unsafe { free::<Decryptor>(handle) }
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_newControl(
    _env: JNIEnv,
    _this: JObject,
) -> jlong {
    boxed(Control::default())
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_controlBytes(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jlong {
    // SAFETY: the handle is alive until Kotlin frees it.
    unsafe { borrow::<Control>(handle) }.bytes.load(Ordering::Relaxed) as jlong
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_controlCancel(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) {
    // SAFETY: the handle is alive until Kotlin frees it.
    unsafe { borrow::<Control>(handle) }.cancel.store(true, Ordering::Relaxed);
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_freeControl(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) {
    // SAFETY: Kotlin frees each handle once, after its last use.
    unsafe { free::<Control>(handle) }
}

/// Flushes a finished output to storage. Best effort: some document providers hand out
/// pipes, which cannot be synced, and nothing is deleted on the strength of this.
fn sync(file: &File) {
    let _ = file.sync_all();
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_encrypt<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    encryptor: jlong,
    control: jlong,
    input: jint,
    output: jint,
    name: JString<'local>,
    size: jlong,
) -> jlong {
    let (input, output) = (owned(input), owned(output));
    guard(&mut env, |env| {
        let (input, output) = (input?, output?);
        let name = text(env, &name)?;
        // SAFETY: both handles are alive for the whole call.
        let (encryptor, control) = unsafe { (borrow::<Encryptor>(encryptor), borrow::<Control>(control)) };
        let meter = Meter::new(control, size.max(0) as u64);
        let written = crate::encrypt(encryptor, &name, input, &output, &meter)?;
        sync(&output);
        Ok(written as jlong)
    })
}

/// A Kotlin `DecryptSink`, called on the thread that is decrypting.
struct JavaSink<'a, 'local> {
    env: &'a mut JNIEnv<'local>,
    sink: &'a JObject<'local>,
}

impl JavaSink<'_, '_> {
    /// Calls `sink.method(String?)` and returns its result as an `int`.
    fn call(&mut self, method: &str, signature: &str, argument: Option<&str>) -> io::Result<jint> {
        let sink = self.sink;
        // Entries can number in the thousands: release the local references of each call.
        self.env
            .with_local_frame(8, |env| -> jni::errors::Result<jint> {
                let argument = match argument {
                    Some(value) => JObject::from(env.new_string(value)?),
                    None => JObject::null(),
                };
                let result = env.call_method(sink, method, signature, &[JValue::Object(&argument)])?;
                if signature.ends_with('Z') {
                    Ok(jint::from(result.z()?))
                } else if signature.ends_with('V') {
                    Ok(0)
                } else {
                    result.i()
                }
            })
            .map_err(jni_failed)
    }
}

impl Sink for JavaSink<'_, '_> {
    type File = File;

    fn dir(&mut self, rel: &str) -> io::Result<()> {
        self.call("dir", "(Ljava/lang/String;)V", Some(rel)).map(drop)
    }

    fn file(&mut self, rel: &str) -> io::Result<File> {
        let fd = self.call("file", "(Ljava/lang/String;)I", Some(rel))?;
        owned(fd).map_err(io::Error::from)
    }

    fn finish(&mut self, file: File) -> io::Result<()> {
        sync(&file);
        Ok(())
    }
}

impl Output for JavaSink<'_, '_> {
    fn begin_file(&mut self, name: Option<&str>) -> io::Result<Option<File>> {
        let fd = self.call("beginFile", "(Ljava/lang/String;)I", name)?;
        if fd < 0 {
            return Ok(None);
        }
        owned(fd).map(Some).map_err(io::Error::from)
    }

    fn begin_folder(&mut self, name: Option<&str>) -> io::Result<bool> {
        Ok(self.call("beginFolder", "(Ljava/lang/String;)Z", name)? != 0)
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_decrypt<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    decryptor: jlong,
    control: jlong,
    input: jint,
    size: jlong,
    sink: JObject<'local>,
) -> jboolean {
    let input = owned(input);
    let written = guard(&mut env, |env| {
        let input = input?;
        // SAFETY: both handles are alive for the whole call.
        let (decryptor, control) = unsafe { (borrow::<Decryptor>(decryptor), borrow::<Control>(control)) };
        let meter = Meter::new(control, size.max(0) as u64);
        let mut output = JavaSink { env, sink: &sink };
        crate::decrypt(decryptor, input, &mut output, &meter)
    });
    if written {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_verify<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    decryptor: jlong,
    control: jlong,
    input: jint,
    size: jlong,
) {
    let input = owned(input);
    guard(&mut env, |_| {
        let input = input?;
        // SAFETY: both handles are alive for the whole call.
        let (decryptor, control) = unsafe { (borrow::<Decryptor>(decryptor), borrow::<Control>(control)) };
        crate::verify(decryptor, input, &Meter::new(control, size.max(0) as u64))
    })
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_generatePassphrase<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
) -> jstring {
    guard(&mut env, |env| {
        let phrase = crate::generate_passphrase();
        Ok(env.new_string(phrase.as_str()).map_err(jni_failed)?.into_raw())
    })
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_isRecoveryKey<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    value: JString<'local>,
) -> jboolean {
    let valid = guard(&mut env, |env| Ok(crate::is_recovery_key(&text(env, &value)?)));
    jboolean::from(valid)
}

#[no_mangle]
pub extern "system" fn Java_io_github_abboodan_topalencryption_core_Native_isSafeName<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    name: JString<'local>,
) -> jboolean {
    let safe = guard(&mut env, |env| Ok(archive::is_safe_name(&text(env, &name)?)));
    jboolean::from(safe)
}
