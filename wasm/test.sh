#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
FIXTURE_DIR="$SCRIPT_DIR/build/fixtures"

if [ ! -f "$SCRIPT_DIR/dist/package/maou-libarchive-core.wasm" ]; then
	echo "error: run ./wasm/build.sh before testing" >&2
	exit 1
fi

cmake -E remove_directory "$FIXTURE_DIR"
cmake -E make_directory "$FIXTURE_DIR"

for name in \
	test_read_format_zip_mac_metadata.zip \
	test_read_format_7zip_copy.7z \
	test_read_format_rar.rar \
	test_read_format_rar5_stored.rar \
	test_read_format_zip_traditional_encryption_data.zip \
	test_read_format_zip_winzip_aes128.zip \
	test_read_format_zip_winzip_aes256_stored.zip \
	test_read_format_7zip_encryption.7z \
	test_read_format_7zip_encryption_header.7z \
	test_read_format_rar4_encrypted_filenames.rar \
	test_read_format_rar5_encrypted_filenames.rar \
	test_read_format_rar5_encrypted_quickopen.rar \
	test_read_format_rar5_encrypted_blake2.rar
do
	uudecode -o "$FIXTURE_DIR/$name" \
		"$SOURCE_ROOT/libarchive/test/$name.uu"
done

node "$SCRIPT_DIR/test.mjs"
node "$SCRIPT_DIR/test-browser.mjs"
