# Activate Testing, if given
if(BUILD_TESTING)
  enable_testing()
endif()

#####################################
# Define Targets
#####################################
add_subdirectory(main)
add_subdirectory(lib1)

#####################################
# Define Install Targets
#####################################
install(TARGETS
  lib1
  attestation_server
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include
)

install(
  FILES 
    ${CMAKE_SOURCE_DIR}/src/lib1/lib1.h 
    ${CMAKE_BINARY_DIR}/exports/lib1_export.h
  DESTINATION 
    include/lib1)

install(FILES  
  ${CMAKE_SOURCE_DIR}/LICENSE
  
DESTINATION .)
