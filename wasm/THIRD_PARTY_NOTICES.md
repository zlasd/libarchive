# Third-party notices

This package contains WebAssembly code linked from:

- libarchive, under the licenses in `COPYING`.
- liblzma from XZ Utils 5.8.3. The library code is in the public domain under
  the 0BSD license; see <https://tukaani.org/xz/>.
- Mbed TLS 3.6.7, under the Apache License 2.0. Only the required objects from
  its `mbedcrypto` static library are linked into the WebAssembly module.
- zlib 1.3.2, under the zlib license.
- bzip2 1.0.6, under its BSD-style license.

The build script downloads the pinned XZ Utils and Mbed TLS source archives and
verifies their SHA-256 digests before compiling them. zlib and bzip2 are
supplied by the active Emscripten toolchain used for the build. Their complete
license texts are included in the package's `licenses/` directory.
