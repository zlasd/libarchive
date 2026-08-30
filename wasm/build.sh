#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BUILD_ROOT=${LIBARCHIVE_PASSWORD_WASM_BUILD_ROOT:-"$SCRIPT_DIR/build"}
DIST_ROOT=${LIBARCHIVE_PASSWORD_WASM_DIST_ROOT:-"$SCRIPT_DIR/dist"}

XZ_VERSION=5.8.3
XZ_ARCHIVE="xz-$XZ_VERSION.tar.gz"
XZ_URL="https://github.com/tukaani-project/xz/releases/download/v$XZ_VERSION/$XZ_ARCHIVE"
XZ_SHA256=3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0
MBEDTLS_VERSION=3.6.7
MBEDTLS_ARCHIVE="mbedtls-$MBEDTLS_VERSION.tar.bz2"
MBEDTLS_URL="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$MBEDTLS_VERSION/$MBEDTLS_ARCHIVE"
MBEDTLS_SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
ZLIB_VERSION=1.3.2
BZIP2_VERSION=1.0.6

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "error: required command not found: $1" >&2
		exit 1
	fi
}

require_command cmake
require_command curl
require_command emcc
require_command embuilder
require_command emcmake
require_command npm
require_command shasum
require_command tar
require_command uudecode

# Some packaged Emscripten installations invoke the first python3 in PATH.
# Select a supported interpreter only when the toolchain cannot start as-is.
if ! emcc --version >/dev/null 2>&1; then
	for candidate in python3.14 python3.13 python3.12 python3.11 python3.10; do
		if command -v "$candidate" >/dev/null 2>&1; then
			EMSDK_PYTHON=$(command -v "$candidate")
			export EMSDK_PYTHON
			break
		fi
	done
fi

if ! emcc --version >/dev/null 2>&1; then
	echo "error: Emscripten requires Python 3.10 or newer" >&2
	exit 1
fi

CACHE_ROOT="$SCRIPT_DIR/.cache"
XZ_DOWNLOAD="$CACHE_ROOT/$XZ_ARCHIVE"
XZ_SOURCE="$BUILD_ROOT/xz-source"
XZ_BUILD="$BUILD_ROOT/xz-build"
XZ_INSTALL="$BUILD_ROOT/xz-install"
MBEDTLS_DOWNLOAD="$CACHE_ROOT/$MBEDTLS_ARCHIVE"
MBEDTLS_SOURCE="$BUILD_ROOT/mbedtls-source"
MBEDTLS_BUILD="$BUILD_ROOT/mbedtls-build"
MBEDTLS_INSTALL="$BUILD_ROOT/mbedtls-install"
ARCHIVE_BUILD="$BUILD_ROOT/libarchive"
PACKAGE_DIR="$DIST_ROOT/package"
LICENSE_DIR="$PACKAGE_DIR/licenses"

cmake -E make_directory "$CACHE_ROOT" "$BUILD_ROOT" "$DIST_ROOT"

if [ ! -f "$XZ_DOWNLOAD" ]; then
	curl --fail --location --show-error "$XZ_URL" --output "$XZ_DOWNLOAD"
fi

ACTUAL_XZ_SHA256=$(shasum -a 256 "$XZ_DOWNLOAD" | awk '{print $1}')
if [ "$ACTUAL_XZ_SHA256" != "$XZ_SHA256" ]; then
	echo "error: unexpected SHA-256 for $XZ_DOWNLOAD" >&2
	echo "expected: $XZ_SHA256" >&2
	echo "actual:   $ACTUAL_XZ_SHA256" >&2
	exit 1
fi

cmake -E remove_directory "$XZ_SOURCE"
cmake -E remove_directory "$XZ_BUILD"
cmake -E remove_directory "$XZ_INSTALL"
cmake -E make_directory "$XZ_SOURCE"
tar -xzf "$XZ_DOWNLOAD" --strip-components=1 -C "$XZ_SOURCE"

emcmake cmake -Wno-dev \
	-S "$XZ_SOURCE" \
	-B "$XZ_BUILD" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX="$XZ_INSTALL" \
	-DBUILD_SHARED_LIBS=OFF \
	-DBUILD_TESTING=OFF \
	-DXZ_THREADS=no \
	-DXZ_NLS=OFF \
	-DXZ_TOOL_XZ=OFF \
	-DXZ_TOOL_XZDEC=OFF \
	-DXZ_TOOL_LZMADEC=OFF \
	-DXZ_TOOL_LZMAINFO=OFF \
	-DXZ_DOC=OFF
cmake --build "$XZ_BUILD" --target install --parallel

if [ ! -f "$MBEDTLS_DOWNLOAD" ]; then
	curl --fail --location --show-error "$MBEDTLS_URL" \
		--output "$MBEDTLS_DOWNLOAD"
fi

ACTUAL_MBEDTLS_SHA256=$(shasum -a 256 "$MBEDTLS_DOWNLOAD" | awk '{print $1}')
if [ "$ACTUAL_MBEDTLS_SHA256" != "$MBEDTLS_SHA256" ]; then
	echo "error: unexpected SHA-256 for $MBEDTLS_DOWNLOAD" >&2
	echo "expected: $MBEDTLS_SHA256" >&2
	echo "actual:   $ACTUAL_MBEDTLS_SHA256" >&2
	exit 1
fi

cmake -E remove_directory "$MBEDTLS_SOURCE"
cmake -E remove_directory "$MBEDTLS_BUILD"
cmake -E remove_directory "$MBEDTLS_INSTALL"
cmake -E make_directory "$MBEDTLS_SOURCE"
tar -xjf "$MBEDTLS_DOWNLOAD" --strip-components=1 -C "$MBEDTLS_SOURCE"

emcmake cmake -Wno-dev \
	-S "$MBEDTLS_SOURCE" \
	-B "$MBEDTLS_BUILD" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX="$MBEDTLS_INSTALL" \
	-DENABLE_PROGRAMS=OFF \
	-DENABLE_TESTING=OFF \
	-DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
	-DUSE_STATIC_MBEDTLS_LIBRARY=ON
cmake --build "$MBEDTLS_BUILD" --target install --parallel

embuilder build zlib bzip2
EM_CACHE_ROOT=$(em-config CACHE)
EM_SYSROOT="$EM_CACHE_ROOT/sysroot"
ZLIB_ARCHIVE=$(emcc --print-file-name=libz.a)
BZIP2_ARCHIVE=$(emcc --print-file-name=libbz2.a)

cmake -E remove_directory "$ARCHIVE_BUILD"
emcmake cmake -Wno-dev \
	-S "$SOURCE_ROOT" \
	-B "$ARCHIVE_BUILD" \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_SHARED_LIBS=OFF \
	-DENABLE_TEST=OFF \
	-DENABLE_INSTALL=OFF \
	-DENABLE_TAR=OFF \
	-DENABLE_CPIO=OFF \
	-DENABLE_CAT=OFF \
	-DENABLE_UNZIP=OFF \
	-DENABLE_OPENSSL=OFF \
	-DENABLE_MBEDTLS=ON \
	-DENABLE_NETTLE=OFF \
	-DENABLE_LIBB2=OFF \
	-DENABLE_LZ4=OFF \
	-DENABLE_LZO=OFF \
	-DENABLE_ZSTD=OFF \
	-DENABLE_LIBXML2=OFF \
	-DENABLE_EXPAT=OFF \
	-DENABLE_PCREPOSIX=OFF \
	-DENABLE_PCRE2POSIX=OFF \
	-DENABLE_LIBGCC=OFF \
	-DENABLE_XATTR=OFF \
	-DENABLE_ACL=OFF \
	-DENABLE_ICONV=OFF \
	-DZLIB_INCLUDE_DIR="$EM_SYSROOT/include" \
	-DZLIB_LIBRARY="$ZLIB_ARCHIVE" \
	-DBZIP2_INCLUDE_DIR="$EM_SYSROOT/include" \
	-DBZIP2_LIBRARIES="$BZIP2_ARCHIVE" \
	-DLIBLZMA_INCLUDE_DIR="$XZ_INSTALL/include" \
	-DLIBLZMA_LIBRARY="$XZ_INSTALL/lib/liblzma.a" \
	-DMBEDTLS_INCLUDE_DIRS="$MBEDTLS_INSTALL/include" \
	-DMBEDTLS_LIBRARY="$MBEDTLS_INSTALL/lib/libmbedtls.a" \
	-DMBEDX509_LIBRARY="$MBEDTLS_INSTALL/lib/libmbedx509.a" \
	-DMBEDCRYPTO_LIBRARY="$MBEDTLS_INSTALL/lib/libmbedcrypto.a" \
	-DCMAKE_C_FLAGS="--use-port=zlib --use-port=bzip2" \
	-DCMAKE_EXE_LINKER_FLAGS="--use-port=zlib --use-port=bzip2"
cmake --build "$ARCHIVE_BUILD" --target archive_static --parallel

cmake -E remove_directory "$PACKAGE_DIR"
cmake -E make_directory "$PACKAGE_DIR" "$LICENSE_DIR"

emcc -O3 -flto --no-entry \
	-I"$SOURCE_ROOT/libarchive" \
	"$SCRIPT_DIR/libarchive_password_wasm.c" \
	"$ARCHIVE_BUILD/libarchive/libarchive.a" \
	"$XZ_INSTALL/lib/liblzma.a" \
	"$MBEDTLS_INSTALL/lib/libmbedcrypto.a" \
	--use-port=zlib \
	--use-port=bzip2 \
	-lworkerfs.js \
	-sSTRICT=1 \
	-sMODULARIZE=1 \
	-sEXPORT_ES6=1 \
	-sEXPORT_NAME=createLibarchivePasswordCore \
	-sENVIRONMENT=web,worker,node \
	-sFILESYSTEM=1 \
	-sALLOW_MEMORY_GROWTH=1 \
	-sINITIAL_MEMORY=16777216 \
	-sMAXIMUM_MEMORY=2147483648 \
	-sSTACK_SIZE=1048576 \
	-sASSERTIONS=1 \
	"-sEXPORTED_FUNCTIONS=['_malloc','_free','_libarchive_password_detect_encryption','_libarchive_password_validate_passphrase','_libarchive_password_detect_encryption_path','_libarchive_password_validate_passphrase_path','_libarchive_password_last_error','_libarchive_password_version']" \
	"-sEXPORTED_RUNTIME_METHODS=['ccall','cwrap','UTF8ToString','FS','HEAPU8']" \
	-o "$PACKAGE_DIR/libarchive-password-core.mjs"

cmake -E copy "$SCRIPT_DIR/index.mjs" "$PACKAGE_DIR/index.mjs"
cmake -E copy "$SCRIPT_DIR/index.d.ts" "$PACKAGE_DIR/index.d.ts"
cmake -E copy "$SCRIPT_DIR/package.json" "$PACKAGE_DIR/package.json"
cmake -E copy "$SCRIPT_DIR/README.md" "$PACKAGE_DIR/README.md"
cmake -E copy "$SCRIPT_DIR/THIRD_PARTY_NOTICES.md" \
	"$PACKAGE_DIR/THIRD_PARTY_NOTICES.md"
cmake -E copy "$SOURCE_ROOT/COPYING" "$PACKAGE_DIR/COPYING"
cmake -E copy "$XZ_SOURCE/COPYING.0BSD" \
	"$LICENSE_DIR/xz-$XZ_VERSION-0BSD.txt"
cmake -E copy "$MBEDTLS_SOURCE/LICENSE" \
	"$LICENSE_DIR/mbedtls-$MBEDTLS_VERSION-Apache-2.0.txt"
cmake -E copy \
	"$EM_CACHE_ROOT/ports/zlib/zlib-$ZLIB_VERSION/LICENSE" \
	"$LICENSE_DIR/zlib-$ZLIB_VERSION.txt"
cmake -E copy \
	"$EM_CACHE_ROOT/ports/bzip2/bzip2-$BZIP2_VERSION/LICENSE" \
	"$LICENSE_DIR/bzip2-$BZIP2_VERSION.txt"

cmake -E remove -f "$DIST_ROOT/libarchive-password-wasm-0.1.0.tgz"
(cd "$PACKAGE_DIR" && npm pack --pack-destination "$DIST_ROOT")

echo "WASM package: $PACKAGE_DIR"
echo "npm archive:  $DIST_ROOT/libarchive-password-wasm-0.1.0.tgz"
