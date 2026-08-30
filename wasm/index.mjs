import createCoreModule from "./maou-libarchive-core.mjs";

export const EncryptionStatus = Object.freeze({
  UNSUPPORTED: -2,
  DONT_KNOW: -1,
  NONE: 0,
  PRESENT: 1,
});

export const PassphraseStatus = Object.freeze({
  UNSUPPORTED: -2,
  DONT_KNOW: -1,
  NOT_NEEDED: 0,
  REQUIRED: 1,
  VALID: 2,
  INVALID_OR_DAMAGED: 3,
});

const encryptionNames = new Map([
  [EncryptionStatus.UNSUPPORTED, "unsupported"],
  [EncryptionStatus.DONT_KNOW, "unknown"],
  [EncryptionStatus.NONE, "not-encrypted"],
  [EncryptionStatus.PRESENT, "encrypted"],
]);

const passphraseNames = new Map([
  [PassphraseStatus.UNSUPPORTED, "unsupported"],
  [PassphraseStatus.DONT_KNOW, "unknown"],
  [PassphraseStatus.NOT_NEEDED, "not-needed"],
  [PassphraseStatus.REQUIRED, "required"],
  [PassphraseStatus.VALID, "valid"],
  [PassphraseStatus.INVALID_OR_DAMAGED, "invalid-or-damaged"],
]);

function normalizeBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new TypeError("Archive input must be an ArrayBuffer or typed array");
}

export async function createMaouArchive(options = {}) {
  const core = await createCoreModule(options);
  const detectMemory = core.cwrap("maou_archive_detect_encryption", "number", [
    "number",
    "number",
  ]);
  const validateMemory = core.cwrap(
    "maou_archive_validate_passphrase",
    "number",
    ["number", "number", "string"],
  );
  const detectPathCore = core.cwrap(
    "maou_archive_detect_encryption_path",
    "number",
    ["string"],
  );
  const validatePathCore = core.cwrap(
    "maou_archive_validate_passphrase_path",
    "number",
    ["string", "string"],
  );
  const lastErrorPointer = core.cwrap("maou_archive_last_error", "number", []);
  const versionPointer = core.cwrap("maou_archive_version", "number", []);

  function result(code, names) {
    const errorPointer = lastErrorPointer();
    const error = errorPointer === 0 ? "" : core.UTF8ToString(errorPointer);
    return Object.freeze({
      code,
      status: names.get(code) ?? "unknown-code",
      error: error || null,
    });
  }

  function withBytes(input, operation) {
    const bytes = normalizeBytes(input);
    if (bytes.byteLength === 0) return operation(0, 0);

    const pointer = core._malloc(bytes.byteLength);
    if (pointer === 0) throw new Error("Could not allocate WASM archive buffer");
    try {
      core.HEAPU8.set(bytes, pointer);
      return operation(pointer, bytes.byteLength);
    } finally {
      core._free(pointer);
    }
  }

  return Object.freeze({
    version: core.UTF8ToString(versionPointer()),
    detectEncryption(input) {
      return withBytes(input, (pointer, size) =>
        result(detectMemory(pointer, size), encryptionNames),
      );
    },
    validatePassphrase(input, passphrase = null) {
      return withBytes(input, (pointer, size) =>
        result(validateMemory(pointer, size, passphrase), passphraseNames),
      );
    },
    detectPath(path) {
      return result(detectPathCore(path), encryptionNames);
    },
    validatePath(path, passphrase = null) {
      return result(validatePathCore(path, passphrase), passphraseNames);
    },
    FS: core.FS,
  });
}
