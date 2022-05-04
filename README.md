# Attestation Server

![Static Build](https://github.com/greg7mdp/attestation_server/workflows/Build/badge.svg)

Attestation Server for XRPL sidechains

## Requirements

* `C++20 compiler` recent, with coroutine support (g++-11, clang 13.1.6 on macos, vs 2022 on windows)
* [`cmake`](https://cmake.org) 3.16+
* [`conan`](https://conan.io) 1.47+

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

#### build additional packages

```
sudo apt-get install libtool
cd conan_pkg/secp256k1
conan create . demo/testing
```


#### and then build the project


```shell
cd /path/to/this/project
mkdir build
cd build 
conan install .. --install-folder cmake-build-release --build=missing -s compiler.cppstd=20
cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake-build-release/conan_toolchain.cmake -DCMAKE_CXX_COMPILER=g++-11
cmake --build .
```

### macos

install conan and cmake if necessary using brew:

```
brew install conan
brew install cmake
```

Update xcode command line tools if necessary. I have verified that the project builds fine with Apple clang version 13.1.6. To update the xcode command line tool you may do:

```
sudo rm -rf /Library/Developer/CommandLineTools
xcode-select --install
```

Once you have a recent version of clang installed, build as usual:


```shell
cd /path/to/this/project
mkdir build
cd build 
conan install .. --install-folder cmake-build-release --build=missing -s compiler.cppstd=20
cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake-build-release/conan_toolchain.cmake -DCMAKE_CXX_COMPILER=g++
cmake --build .
```

### Windows


```shell
cd /path/to/this/project
mkdir build 
cd build 
conan install .. --install-folder cmake-build --output-folder cmake-build --build=missing -s compiler.cppstd=20 -s build_type=Release
conan install .. --install-folder cmake-build --output-folder cmake-build --build=missing -s compiler.cppstd=20 -s build_type=Debug
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
