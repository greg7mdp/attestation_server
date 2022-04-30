# Attestation Server

![Static Build](https://github.com/greg7mdp/attestation_server/workflows/Build/badge.svg)

Attestation Server for XRPL sidechains

## Requirements

* `C++20 compiler` recent, with coroutine support (g++-11, )
* [`cmake`](https://cmake.org) 3.16+
* [`conan`](https://conan.io) 1.47+
* [`doctest`](https://github.com/doctest/doctest) 2.4.6+
* [`boost`](https://www.boost.org/) 1.78+

## Optional:

* `cppcheck`
* `clang-format`

## Features



## Available CMake Options

* BUILD_TESTING     - builds the tests
* BUILD_SHARED_LIBS - enables or disables the generation of shared libraries
* BUILD_WITH_MT - valid only for MSVC, builds libraries as MultiThreaded DLL
* RUN_CPPCHECK_WHEN_BUILDING - is set, and cppcheck is installed, runs cppcheck when building 

## How to build from command line

The project can be built using the following commands:

### linux


#### install recent g++ if needed:


```
sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
sudo apt install -y g++-11
g++-11 --version
```

#### and then build the project


```shell
cd /path/to/this/project
mkdir -p build # md build (on Windows)
cd build 
conan install .. --install-folder cmake-build-release --build=missing -s compiler.cppstd=20
cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake-build-release/conan_toolchain.cmake -DCMAKE_CXX_COMPILER=g++-11
cmake --build .
```

### macos


update xcode if necessary, and then build the project


```shell
cd /path/to/this/project
mkdir -p build # md build (on Windows)
cd build 
conan install .. --install-folder cmake-build-release --build=missing -s compiler.cppstd=20
cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake-build-release/conan_toolchain.cmake -DCMAKE_CXX_COMPILER=g++
cmake --build .
```

### Windows


```shell
cd /path/to/this/project
mkdir -p build # md build (on Windows)
cd build 
conan install .. --install-folder cmake-build --output-folder cmake-build --build=missing -s compiler.cppstd=20
cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake-build/conan_toolchain.cmake
cmake --build .  --config Release
```


### optional targets:

```
cmake --build . --target format
cmake --build . --target package
```

## Acknowledgements

- [project template](https://github.com/madduci/moderncpp-project-template/blob/master/CMakeLists.txt) from (c) Michele Adduci <adduci@tutanota.com> used under MIT license
