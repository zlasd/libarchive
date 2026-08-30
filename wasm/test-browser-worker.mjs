import {
  createMaouArchive,
  EncryptionStatus,
  PassphraseStatus,
} from "./dist/package/index.mjs";

try {
  postMessage({ progress: "fetching fixture" });
  const response = await fetch(
    "./build/fixtures/test_read_format_7zip_encryption.7z",
  );
  if (!response.ok) throw new Error(`Fixture request failed: ${response.status}`);

  const blob = await response.blob();
  postMessage({ progress: "loading WebAssembly" });
  const archive = await createMaouArchive();
  const mountPoint = "/upload";
  const archivePath = `${mountPoint}/encrypted.7z`;

  archive.FS.mkdir(mountPoint);
  archive.FS.mount(
    archive.FS.filesystems.WORKERFS,
    { blobs: [{ name: "encrypted.7z", data: blob }] },
    mountPoint,
  );

  postMessage({ progress: "checking WorkerFS archive" });
  const detected = archive.detectPath(archivePath);
  const accepted = archive.validatePath(archivePath, "12345678");
  const rejected = archive.validatePath(archivePath, "wrong");
  archive.FS.unmount(mountPoint);

  if (
    detected.code !== EncryptionStatus.PRESENT ||
    accepted.code !== PassphraseStatus.VALID ||
    rejected.code !== PassphraseStatus.INVALID_OR_DAMAGED
  ) {
    throw new Error(
      `Unexpected results: ${JSON.stringify({ detected, accepted, rejected })}`,
    );
  }

  postMessage({ ok: true });
} catch (error) {
  postMessage({
    ok: false,
    error: error instanceof Error ? error.stack ?? error.message : String(error),
  });
}
