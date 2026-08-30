# libarchive-password-wasm

This package exposes libarchive's active encryption detection and full
passphrase validation APIs through WebAssembly. It supports ZIP (including
Traditional PKWARE and WinZip AES), 7z, RAR4, and RAR5 archives.

```js
import {
  createArchivePasswordChecker,
  EncryptionStatus,
  PassphraseStatus,
} from "libarchive-password-wasm";

const archive = await createArchivePasswordChecker();
const bytes = new Uint8Array(await file.arrayBuffer());

if (archive.detectEncryption(bytes).code === EncryptionStatus.PRESENT) {
  const result = archive.validatePassphrase(bytes, password);
  if (result.code !== PassphraseStatus.VALID) {
    throw new Error(result.error ?? result.status);
  }
}
```

Both operations consume a fresh native libarchive reader internally. The JS
wrapper accepts an `ArrayBuffer` or any typed-array view and owns the temporary
copy placed in WebAssembly memory.

For large browser `File` or `Blob` objects, run the module in a Web Worker and
mount the object with Emscripten WorkerFS. Then call `detectPath` and
`validatePath`; this avoids copying the entire package into WebAssembly memory:

```js
const archive = await createArchivePasswordChecker();
archive.FS.mkdir("/upload");
archive.FS.mount(
  archive.FS.filesystems.WORKERFS,
  { blobs: [{ name: "game.7z", data: file }] },
  "/upload",
);

const detection = archive.detectPath("/upload/game.7z");
const validation = archive.validatePath("/upload/game.7z", password);
archive.FS.unmount("/upload");
```

`INVALID_OR_DAMAGED` is intentionally a combined status. Several archive
formats cannot reliably distinguish an incorrect password from corrupted
ciphertext after authentication or checksum verification fails.

## Build and test

Install Emscripten, CMake, Node.js/npm, curl, and `uudecode`, then run:

```sh
./wasm/build.sh
./wasm/test.sh
```

The build pins XZ Utils 5.8.3 and Mbed TLS 3.6.7 and verifies both SHA-256
digests before compiling liblzma and the required cryptographic primitives.
zlib and bzip2 come from the active Emscripten toolchain. Generated files are
placed in `wasm/dist/`; they are not committed.
