# Encrypted RAR5 final-block lookahead regression

Investigated on 2026-09-20 against fork `4eaf9c1d`, using CommonCrypto on
macOS arm64. The early-return condition originated in `77f482de`.

`rar5_fill_data_decryption()` rejected a request larger than the buffered
plaintext plus unread ciphertext. Compressed blocks request four extra
lookahead bytes, but `read_ahead()` only supplied its bounded zero extension
after all ciphertext had been consumed. With unread ciphertext and less than
four bytes of AES alignment padding, valid final blocks could therefore be
reported as EOF. The reproducer requested 32554 bytes with 27896 buffered and
4656 still encrypted: only two lookahead bytes were missing.

The EOF propagated without validating the unpacked length. The disk writer
extended the partially written file to its declared size, and
`archive_read_extract()` returned success. A 771809-byte dictionary lost its
last 230334 bytes. This affects particular compressed/encrypted block layouts,
not all large files; an original synthetic file of 131060 bytes reproduces it.

The fix drains real ciphertext before applying the existing non-consumable
lookahead extension. A second check rejects EOF when output is shorter than
the declared size. Checksum, password and buffer limits remain in force.

`test_read_format_rar5_encrypted_lookahead` checks block reads, stream reads and
disk extraction against independently generated expected bytes. The fixture
contains no private data: xorshift32 seeded with 0x12345678 emits its low byte
as lowercase hex, truncated to 131060 bytes. It was packed using RAR 7.23 with
`-ma5 -m3 -md32m -s- -ppassword`. The generation algorithm and file name are in
the test source. `test_read_format_rar5_encrypted_truncated_data` cuts into the
final ciphertext and requires a fatal error instead of successful EOF.

Both new tests fail against the original static library. After the fix, the
78 selected RAR5/RAR4/encryption tests report no failures; the Windows-only
RAR5 Unicode test is skipped on macOS.

Independent unrar 7.23 comparisons verified every file's length and SHA-256:

- A private real archive: 2049 files, 1101510405 bytes, zero differences after
  the fix. The old reader truncated 20 files, including images, audio and JSON.
- Five 30-file matrices: plain RAR5, encrypted compressed, encrypted filenames,
  encrypted stored and encrypted solid. The old compressed encrypted variants
  reproduce corruption; all 150 fixed outputs match unrar. Sizes range from
  1 KiB to 4 MiB with binary, hex text and repetitive content.
- An isolated real-MZ Camp package with an original valid JSON dictionary:
  62 files match unrar after the fix; the old reader damages that dictionary.

On macOS, unrar emits some decomposed Unicode path names. Comparisons match
canonical NFC paths, reject normalization collisions, and hash original file
bytes. They do not compare only exit statuses or nominal lengths.

No claim is made for all compression settings, iOS/WASM runtime validation or
updated application artifacts. The caller's packaged library remains separate
from this source change.

The complete local game corpus was subsequently checked: 19 archives (13 7z,
5 ZIP, 1 RAR), 57612 files and 15104974063 unpacked bytes all matched independent
references. RAR used unrar; 17 other archives used 7zz. One legacy ZIP required
the application's existing GB18030 filename setting. macOS 7zz could not create
two of its filenames even with code page 936, so Python's independent zipfile
decoder verified that archive's CRC32 and all 1628 file hashes. The initial
18-pass/1-failure run and the successful retry were both retained. This required
no changes to product ZIP handling. All temporary extraction directories were
removed after verification; reports and per-file hashes were retained locally.
