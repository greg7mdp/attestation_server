#####################################
# Define Target Information
#####################################
set(TARGET_NAME libxrpl)
set(TARGET_INCLUDE_FOLDER ${CMAKE_CURRENT_SOURCE_DIR})
set(TARGET_SOURCES Base58.cpp Common.cpp Digest.cpp PublicKey.cpp SecretKey.cpp Seed.cpp ed25519.c)

# temporary adding stub for ed25519 with ed25519.c file above
set_source_files_properties(ed25519.c PROPERTIES COMPILE_FLAGS -Wno-unused-parameter)

#####################################
# Support IDE Visualization
#####################################
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${TARGET_SOURCES})

#####################################
# Define Target according to options
##################################### 
if(BUILD_SHARED_LIBS)
  add_library(${TARGET_NAME} SHARED ${TARGET_SOURCES})
else()
  add_library(${TARGET_NAME} STATIC ${TARGET_SOURCES})
endif()

#####################################
# Define Target Properties and Optional OpenSSL Dependency
#####################################

# generate an export header to expose symbols when using the library
generate_export_header(${TARGET_NAME} EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/exports/${TARGET_NAME}_export.h)

# add target properties such as debug postfix, MSVC Runtime and library version
set_target_properties(${TARGET_NAME} PROPERTIES 
                                      DEBUG_POSTFIX "-d" 
                                      MSVC_RUNTIME_LIBRARY "${MSVC_RUNTIME_TYPE}" 
                                      VERSION ${CMAKE_PROJECT_VERSION}
                                      SOVERSION ${CMAKE_PROJECT_VERSION})

# set target compile options as defined in the cmake/compiler_options.cmake Module
target_compile_options(${TARGET_NAME} PRIVATE ${compiler_options})

# add compiler definition WITH_OPENSSL, if found
target_compile_definitions(${TARGET_NAME} PRIVATE ${compiler_definitions} $<$<BOOL:${OPENSSL_FOUND}>:WITH_OPENSSL>)

# set target link options as defined in the cmake/compiler_options.cmake Module
target_link_options(${TARGET_NAME} PRIVATE ${linker_flags})

target_link_libraries(${TARGET_NAME} PRIVATE doctest::doctest boost::boost fmt::fmt openssl::openssl secp256k1::secp256k1)

# include all the necessary directories
target_include_directories(${TARGET_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/exports>
  PRIVATE 
    ${TARGET_INCLUDE_FOLDER}
)

