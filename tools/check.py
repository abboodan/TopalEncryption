"""Cross-checks files made by the real topal-cli against the independent reader.

usage: check.py <work dir> <recovery key> <v1 fixture .topal> <v1 fixture plain>
Run it through check.sh, which prepares the work dir with the real topal-cli.

"""

import pathlib
import sys

from nacl.exceptions import CryptoError

from topal_decrypt import read_archive, read_file

work, recovery_key, v1_sealed, v1_plain = sys.argv[1:5]
work = pathlib.Path(work)
results = []


def check(label, ok):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + label)


def rejects(label, **kwargs):
    try:
        read_file(**kwargs)
        check(label, False)
    except CryptoError:
        check(label, True)


big = (work / "plain" / "big.bin").read_bytes()
small = (work / "plain" / "صورة.jpg").read_bytes()

# 1. Plain files, password only, several chunks and a single chunk.
sealed_big = (work / "by-password" / "big.bin.topal").read_bytes()
kind, name, content = read_file(sealed_big, password="pass-one")
check("multi-chunk file: content, name and kind", (kind, name, content) == ("file", "big.bin", big))
sealed_small = (work / "by-password" / "صورة.jpg.topal").read_bytes()
kind, name, content = read_file(sealed_small, password="pass-one")
check("Arabic-named file: content and name", (name, content) == ("صورة.jpg", small))
check("header has no recovery slot when none is active", sealed_small[6] == 0)
rejects("wrong password is refused", data=sealed_small, password="pass-two")

# 2. With a recovery key active: both the password and the key open it.
sealed = (work / "with-recovery" / "big.bin.topal").read_bytes()
check("recovery flag is set", sealed[6] == 2)
check("password opens a file that has a recovery slot", read_file(sealed, password="pass-one")[2] == big)
check("recovery key opens it without the password", read_file(sealed, recovery_key=recovery_key)[2] == big)

# 3. After a password change: new password and recovery key work, old password does not.
changed = (work / "changed" / "big.bin.topal").read_bytes()
check("only the header changed", changed[210:] == sealed[210:] and changed != sealed)
check("new password opens it", read_file(changed, password="pass-new")[2] == big)
check("recovery key still opens it", read_file(changed, recovery_key=recovery_key)[2] == big)
rejects("old password is refused after the change", data=changed, password="pass-one")

# 4. Hidden names: one container per folder, names only inside.
containers = list((work / "hidden").glob("*.topal"))
check("folder became exactly one file", len(containers) == 1)
container = containers[0].read_bytes()
check("no file name appears in the container", b"big.bin" not in container and "صورة".encode() not in container)
kind, name, content = read_file(container, password="pass-one")
entries = read_archive(content)
expected = {"big.bin": big, "صورة.jpg": small, "sub": None, "sub/empty dir": None, "sub/note.txt": b"note\n"}
check("container: kind, folder name and every entry", (kind, name, entries) == ("folder", "plain", expected))

# 5. A file made by version 0.1.0.
v1 = pathlib.Path(v1_sealed).read_bytes()
kind, name, content = read_file(v1, password="topal-test")
check("version 1 file", (v1[5], kind, name, content) == (1, "file", None, pathlib.Path(v1_plain).read_bytes()))

# 6. Tampering is caught by the independent reader too.
for label, at in [("flags byte", 6), ("salt", 20), ("stream prefix", 40), ("wrapped key", 90), ("content", len(sealed_small) - 20)]:
    bad = bytearray(sealed_small)
    bad[at] ^= 1
    rejects(f"flipped bit in {label} is refused", data=bytes(bad), password="pass-one")

print(f"\n{sum(results)} of {len(results)} checks passed")
sys.exit(0 if all(results) else 1)
