#####################################
# Define Project-Wide Settings
#####################################
cmake_minimum_required(VERSION 3.16.0 FATAL_ERROR)

cmake_policy(SET CMP0063 NEW) # Enables the Visibility Property on all target types
cmake_policy(SET CMP0091 NEW) # Enables the MSVC_RUNTIME_LIBRARY property on targets

project(attestation_server LANGUAGES CXX C DESCRIPTION "Sidechain Attestation Server")

set(CMAKE_PROJECT_VERSION_MAJOR 1)
set(CMAKE_PROJECT_VERSION_MINOR 0)
set(CMAKE_PROJECT_VERSION_PATCH 0)
set(CMAKE_PROJECT_VERSION ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_PATCH})

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE) # Generate the compile_commands.json file

set(CMAKE_VERBOSE_MAKEFILE 1)

# Set the Relative Path Configurations
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Configure the visibility of symbols in targets
#set(CMAKE_CXX_VISIBILITY_PRESET hidden)
#set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

# Define installation folder and the module path (this one required by conan)
set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install)
set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR} ${CMAKE_MODULE_PATH})
set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR} ${CMAKE_PREFIX_PATH})

# Specify where all the binaries go
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

#####################################
# Define Options
#####################################
option(BUILD_SHARED_LIBS "Build shared libraries" TRUE)
option(BUILD_WITH_MT "Build libraries as MultiThreaded DLL (Windows Only)" TRUE)
option(RUN_CPPCHECK_WHEN_BUILDING FALSE)

#####################################
# Define CMake Module Imports
#####################################
include(CTest)       # creates a BUILD_TESTING option that selects whether to enable testing support (ON by default)

find_package(fmt)
find_package(Boost)
find_package(doctest REQUIRED)
#find_package(secp256k1)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(InstallRequiredSystemLibraries)
include(GenerateExportHeader)
include(${CMAKE_SOURCE_DIR}/cmake/clang_format.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/compiler_options.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/cpack.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/cppcheck.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/dependencies.cmake)

#####################################
# GMP
#####################################
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
if(MSVC)
  find_library(GMP_LIBRARY mpir)
else()
  find_library(GMP_LIBRARY gmp)
endif()
if(GMP_LIBRARY MATCHES ${CMAKE_SHARED_LIBRARY_SUFFIX})
  set(gmp_library_type SHARED)
else()
  set(gmp_library_type STATIC)
endif()
message(STATUS "GMP: ${GMP_LIBRARY}, ${GMP_INCLUDE_DIR}")
add_library(gmp ${gmp_library_type} IMPORTED)
set_target_properties(
  gmp PROPERTIES
  IMPORTED_LOCATION ${GMP_LIBRARY}
  INTERFACE_INCLUDE_DIRECTORIES ${GMP_INCLUDE_DIR}
)

#####################################
# secp256k1
#####################################
add_library(secp256k1 STATIC third_party/secp256k1/src/secp256k1.c
                      third_party/secp256k1/src/precomputed_ecmult.c
                      third_party/secp256k1/src/precomputed_ecmult_gen.c)

if(MSVC)

  target_link_libraries(secp256k1 PRIVATE gmp)
  target_compile_definitions(secp256k1 PUBLIC USE_NUM_GMP USE_FIELD_INV_NUM USE_SCALAR_INV_NUM)
  target_compile_definitions(secp256k1 PUBLIC USE_FIELD_10X26 USE_SCALAR_8X32)

  target_compile_options(secp256k1 PRIVATE /w) # Not much we can do about warnings

else()

  target_compile_definitions(secp256k1 PUBLIC USE_NUM_NONE USE_FIELD_INV_BUILTIN USE_SCALAR_INV_BUILTIN)
  target_compile_definitions(secp256k1 PUBLIC USE_FIELD_5X52 USE_SCALAR_4X64 HAVE___INT128)

  target_compile_options(secp256k1 PRIVATE -fPIC)

endif()

target_compile_definitions(secp256k1 PUBLIC ECMULT_WINDOW_SIZE=15 ECMULT_GEN_PREC_BITS=4 USE_ENDOMORPHISM)
target_compile_definitions(secp256k1 PUBLIC ENABLE_MODULE_RECOVERY)
target_include_directories(secp256k1 PRIVATE secp256k1 INTERFACE third_party/secp256k1/include)

#####################################
# Define Targets
#####################################
add_subdirectory(libxrpl)
add_subdirectory(server)

#####################################
# Define Install Targets
#####################################
install(TARGETS libxrpl attestation_server
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION bin
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include
)

install(FILES ${CMAKE_SOURCE_DIR}/libxrpl/lib1.h 
        DESTINATION include/libxrpl)

install(FILES ${CMAKE_SOURCE_DIR}/LICENSE
        DESTINATION .)
