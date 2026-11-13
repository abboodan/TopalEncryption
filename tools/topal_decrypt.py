"""Independent reader for .topal files (format versions 1 and 2).

Shares no code with Topal Encryption: Argon2 comes from the reference C implementation
(argon2-cffi), XChaCha20-Poly1305 and X25519 from libsodium (PyNaCl), HKDF from the
Python standard library. If this opens the files, the app really does what its format
description says.
"""

import base64
import hashlib
import hmac
import struct

from argon2.low_level import Type, hash_secret_raw
from nacl import bindings as sodium

TAG = 16


def xchacha_open(key, nonce, ciphertext, aad):
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)


def hkdf_sha256(salt, ikm, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def parse_recovery_key(text):
    compact = "".join(c for c in text.upper() if c not in "- \t\r\n")
    assert compact.startswith("TOPALKEY"), "not a recovery key"
    body = compact[len("TOPALKEY"):]
    raw = base64.b32decode(body + "=" * (-len(body) % 8))
    secret, check = raw[:32], raw[32:]
    assert check == hashlib.sha256(b"TOPAL-KEY" + secret).digest()[:2], "bad checksum"
    return secret


def read_file(data, password=None, recovery_key=None):
    """Returns (kind, name, content). kind is "file" or "folder"; name may be None."""
    assert data[:5] == b"TOPAL", "not a Topal file"
    version = data[5]
    if version == 1:
        flags, at = 0, 6
    elif version == 2:
        flags, at = data[6], 7
    else:
        raise ValueError("unsupported version")
    memory, passes, lanes = struct.unpack_from("<III", data, at)
    salt = data[at + 12:at + 28]
    (chunk_size,) = struct.unpack_from("<I", data, at + 28)
    prefix = data[at + 32:at + 51]
    aad_end = at + 51
    wrap_nonce = data[aad_end:aad_end + 24]
    wrapped = data[aad_end + 24:aad_end + 72]
    body = aad_end + 72

    slot = None
    if flags & 2:
        slot = (data[body:body + 32], data[body + 32:body + 80])
        body += 80

    if recovery_key is not None:
        assert slot is not None, "no recovery slot"
        secret = parse_recovery_key(recovery_key)
        ephemeral, sealed = slot
        shared = sodium.crypto_scalarmult(secret, ephemeral)
        recipient = sodium.crypto_scalarmult_base(secret)
        wrap_key = hkdf_sha256(ephemeral + recipient, shared, b"topal recovery key wrap v2")
        slot_aad = b"TOPAL recovery slot" + bytes([version, flags]) + struct.pack("<I", chunk_size) + prefix
        file_key = xchacha_open(wrap_key, bytes(24), sealed, slot_aad)
    else:
        kek = hash_secret_raw(
            password.encode(), salt, time_cost=passes, memory_cost=memory,
            parallelism=lanes, hash_len=32, type=Type.ID,
        )
        file_key = xchacha_open(kek, wrap_nonce, wrapped, data[:aad_end])

    # STREAM: nonce = 19-byte prefix, 32-bit big-endian counter, 1 on the last chunk.
    plain = bytearray()
    sealed_chunk = chunk_size + TAG
    chunks = [data[i:i + sealed_chunk] for i in range(body, len(data), sealed_chunk)]
    assert chunks, "no content"
    for counter, chunk in enumerate(chunks):
        last = counter == len(chunks) - 1
        nonce = prefix + struct.pack(">I", counter) + bytes([1 if last else 0])
        plain += xchacha_open(file_key, nonce, chunk, b"")

    name = None
    if version >= 2:
        (name_len,) = struct.unpack_from("<H", plain, 0)
        name = plain[2:2 + name_len].decode() or None
        plain = plain[2 + name_len:]
    return ("folder" if flags & 1 else "file"), name, bytes(plain)


def read_archive(content):
    """Returns {relative path: bytes, or None for a folder}."""
    entries, at = {}, 0
    while True:
        kind = content[at]
        at += 1
        if kind == 0:
            assert at == len(content), "data after the end marker"
            return entries
        (path_len,) = struct.unpack_from("<H", content, at)
        path = content[at + 2:at + 2 + path_len].decode()
        at += 2 + path_len
        if kind == 2:
            entries[path] = None
        else:
            (size,) = struct.unpack_from("<Q", content, at)
            entries[path] = content[at + 8:at + 8 + size]
            at += 8 + size
