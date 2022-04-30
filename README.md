# Attestation Server

![Static Build](https://github.com/greg7mdp/attestation_server/workflows/Build/badge.svg)

Attestation Server for XRPL sidechains

## Requirements

* `C++20 compiler` 
* [`cmake`](https://cmake.org) 3.16+
* [`conan`](https://conan.io) 1.47+
* [`doctest`](https://github.com/doctest/doctest)
* [`boost`](https://www.boost.org/) 1.78+

## Optional:

* `cppcheck`
* `clang-format`

## Features



## Available CMake Options

* BUILD_TESTING     - builds the tests (requires `doctest`)
* BUILD_SHARED_LIBS - enables or disables the generation of shared libraries
* BUILD_WITH_MT - valid only for MSVC, builds libraries as MultiThreaded DLL
* RUN_CPPCHECK_WHEN_BUILDING - is set, and cppcheck is installed, runs cppcheck when building 

If you enable `BUILD_TESTING`, you'll need to run`conan install` to fetch the `doctest` dependency. Another dependency (OpenSSL) is used in this project as a demonstration of including a third-party library in the process, but is not used.

## How to build from command line

The project can be built using the following commands:

```shell
cd /path/to/this/project
mkdir -p build # md build (on Windows)
cd build 
conan install .. --install-folder cmake-build-release --build=missing
cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake-build-release/conan_toolchain.cmake
cmake --build .
```

optional commands:

```
cmake --build . --target format
cmake --build . --target package
```

## Acknowledgements

- [project template](https://github.com/madduci/moderncpp-project-template/blob/master/CMakeLists.txt) from (c) Michele Adduci <adduci@tutanota.com> used under MIT license
