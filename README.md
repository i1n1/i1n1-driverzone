# i1n1-driverzone

Driver zone: simulated NVMe/xHCI devices, VMX root-mode skeleton and driver RPC shim.

Experimental, build-only source release: sources, headers and CMake files for the libraries and tools
of this module. No tests, firmware, Apple software or guest images are included, and no complete guest
boot is claimed.

## Dependencies

- `i1n1-core` — https://github.com/i1n1/i1n1-core.git
- `i1n1-platform` — https://github.com/i1n1/i1n1-platform.git

Transitive (through the dependencies above): `i1n1-engine`.

Dependencies are resolved by `cmake/i1n1_deps.cmake`: pass `-DI1N1_<NAME>_SOURCE_DIR=<checkout>`
(`CORE`, `ENGINE`, `PLATFORM`) or build through the `https://github.com/i1n1/i1n1.git` superbuild.

## Build

```sh
cmake -S i1n1-driverzone -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DI1N1_CORE_SOURCE_DIR=<path> -DI1N1_PLATFORM_SOURCE_DIR=<path>
cmake --build build
```

## Supported hosts and limitations

- Verified build environment: macOS on arm64, Apple clang 21, CMake 4.4, Ninja, C11, `BUILD_TESTING=OFF`.
  Other hosts and compilers have not been verified for this release.
- Warnings are errors by default (`-DI1N1_WARNINGS_AS_ERRORS=OFF` relaxes this for other compilers).
- Unsupported instructions, registers or devices are reported as deterministic stops by the source, not
  emulated; this release is a build of that source, not evidence of a working guest.

## License

GPL-2.0-only for project-authored material; see `COPYING` and `LICENSE`.
