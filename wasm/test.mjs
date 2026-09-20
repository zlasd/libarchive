import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  createArchivePasswordChecker,
  EncryptionStatus,
  PassphraseStatus,
} from "./dist/package/index.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const fixtureDirectory = join(scriptDirectory, "build", "fixtures");

const fixture = async (name) => readFile(join(fixtureDirectory, name));
const archive = await createArchivePasswordChecker();

assert.match(archive.version, /^libarchive 3\.8\.9/);

for (const name of [
  "test_read_format_zip_mac_metadata.zip",
  "test_read_format_7zip_copy.7z",
  "test_read_format_rar.rar",
  "test_read_format_rar5_stored.rar",
]) {
  const bytes = await fixture(name);
  assert.equal(
    archive.detectEncryption(bytes).code,
    EncryptionStatus.NONE,
    `${name} should be detected as unencrypted`,
  );
  assert.equal(
    archive.validatePassphrase(bytes).code,
    PassphraseStatus.NOT_NEEDED,
    `${name} should not require a password`,
  );
}

const encryptedFixtures = [
  ["test_read_format_zip_traditional_encryption_data.zip", "12345678"],
  ["test_read_format_zip_winzip_aes128.zip", "password"],
  ["test_read_format_zip_winzip_aes256_stored.zip", "password"],
  ["test_read_format_7zip_encryption.7z", "12345678"],
  ["test_read_format_7zip_encryption_header.7z", "12345678"],
  ["test_read_format_rar4_encrypted_filenames.rar", "password"],
  ["test_read_format_rar5_encrypted_filenames.rar", "password"],
  ["test_read_format_rar5_encrypted_quickopen.rar", "密碼🔒"],
  ["test_read_format_rar5_encrypted_blake2.rar", "password"],
];

for (const [name, password] of encryptedFixtures) {
  const bytes = await fixture(name);
  assert.equal(
    archive.detectEncryption(bytes).code,
    EncryptionStatus.PRESENT,
    `${name} should be detected as encrypted`,
  );
  assert.equal(
    archive.validatePassphrase(bytes).code,
    PassphraseStatus.REQUIRED,
    `${name} should require a password`,
  );
  assert.equal(
    archive.validatePassphrase(bytes, password).code,
    PassphraseStatus.VALID,
    `${name} should accept its password`,
  );
  assert.equal(
    archive.validatePassphrase(bytes, "definitely-wrong").code,
    PassphraseStatus.INVALID_OR_DAMAGED,
    `${name} should reject a wrong password`,
  );
}

const invalid = archive.detectEncryption(new Uint8Array([1, 2, 3, 4]));
assert.equal(invalid.code, EncryptionStatus.DONT_KNOW);
assert.ok(invalid.error);

const path = "/encrypted.7z";
const pathFixture = await fixture("test_read_format_7zip_encryption.7z");
archive.FS.writeFile(path, pathFixture);
assert.equal(archive.detectPath(path).code, EncryptionStatus.PRESENT);
assert.equal(
  archive.validatePath(path, "12345678").code,
  PassphraseStatus.VALID,
);
assert.deepEqual(archive.listPath(path, "12345678").entries, ["bar.txt"]);
archive.FS.unlink(path);

const encryptedHeaderPath = "/encrypted-header.7z";
archive.FS.writeFile(
  encryptedHeaderPath,
  await fixture("test_read_format_7zip_encryption_header.7z"),
);
assert.equal(archive.listPath(encryptedHeaderPath).ok, false);
assert.deepEqual(
  archive.listPath(encryptedHeaderPath, "12345678").entries,
  ["bar.txt"],
);
archive.FS.unlink(encryptedHeaderPath);

const padded = new Uint8Array(pathFixture.byteLength + 8);
padded.set(pathFixture, 4);
assert.equal(
  archive.validatePassphrase(
    padded.subarray(4, 4 + pathFixture.byteLength),
    "12345678",
  ).code,
  PassphraseStatus.VALID,
);

const damaged = new Uint8Array(
  await fixture("test_read_format_rar5_encrypted_blake2.rar"),
);
damaged[200] ^= 1;
assert.equal(
  archive.validatePassphrase(damaged, "password").code,
  PassphraseStatus.INVALID_OR_DAMAGED,
);

for (let iteration = 0; iteration < 25; iteration += 1) {
  assert.equal(
    archive.validatePassphrase(pathFixture, "12345678").code,
    PassphraseStatus.VALID,
  );
}

console.log(
  `WASM validation passed for ${encryptedFixtures.length} encrypted fixtures`,
);
