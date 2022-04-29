#####################################
# Define Project-Wide Settings
#####################################
cmake_minimum_required(VERSION 3.16.0 FATAL_ERROR)

# Enables the Visibility Property on all target types
cmake_policy(SET CMP0063 NEW)

# Enables the MSVC_RUNTIME_LIBRARY property on targets
cmake_policy(SET CMP0091 NEW)

# Define the Project Name and Description
project(attestation_server LANGUAGES CXX DESCRIPTION "Sidechain Attestation Server")

# Set Project version (used for library versioning and for CPack)
set(CMAKE_PROJECT_VERSION_MAJOR 1)
set(CMAKE_PROJECT_VERSION_MINOR 0)
set(CMAKE_PROJECT_VERSION_PATCH 0)
set(CMAKE_PROJECT_VERSION ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_PATCH})

# Set required C++ Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

# Generate the compile_commands.json file
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

# Set the Relative Path Configurations
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Configure the visibility of symbols in targets
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

# Define installation folder and the module path (this one required by conan)
set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install)
set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR} ${CMAKE_MODULE_PATH})
set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR} ${CMAKE_PREFIX_PATH})

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
#find_package(doctest REQUIRED)
#include_directories(${DOCTEST_INCLUDE_DIR})

find_package(fmt)
find_package(Boost)
find_package(doctest REQUIRED)

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

install(FILES ${CMAKE_SOURCE_DIR}/lib/lib1.h 
        DESTINATION include/lib1)

install(FILES ${CMAKE_SOURCE_DIR}/LICENSE
        DESTINATION .)
