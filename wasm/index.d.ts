export declare const EncryptionStatus: Readonly<{
  UNSUPPORTED: -2;
  DONT_KNOW: -1;
  NONE: 0;
  PRESENT: 1;
}>;

export declare const PassphraseStatus: Readonly<{
  UNSUPPORTED: -2;
  DONT_KNOW: -1;
  NOT_NEEDED: 0;
  REQUIRED: 1;
  VALID: 2;
  INVALID_OR_DAMAGED: 3;
}>;

export interface ArchiveCheckResult {
  readonly code: number;
  readonly status: string;
  readonly error: string | null;
}

export interface ArchiveListResult {
  readonly ok: boolean;
  readonly entries: readonly string[];
  readonly error: string | null;
}

export type ArchiveBytes = ArrayBuffer | ArrayBufferView;

export interface ArchivePasswordChecker {
  readonly version: string;
  detectEncryption(input: ArchiveBytes): ArchiveCheckResult;
  validatePassphrase(
    input: ArchiveBytes,
    passphrase?: string | null,
  ): ArchiveCheckResult;
  detectPath(path: string): ArchiveCheckResult;
  validatePath(path: string, passphrase?: string | null): ArchiveCheckResult;
  listPath(path: string, passphrase?: string | null): ArchiveListResult;
  readonly FS: unknown;
}

export interface ArchivePasswordCheckerOptions {
  locateFile?: (path: string, prefix: string) => string;
  wasmBinary?: ArrayBufferView;
  [key: string]: unknown;
}

export declare function createArchivePasswordChecker(
  options?: ArchivePasswordCheckerOptions,
): Promise<ArchivePasswordChecker>;
