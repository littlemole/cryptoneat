set(PACKAGE_VERSION "0.0.15")
if(NOT "${PACKAGE_FIND_VERSION}" VERSION_GREATER "0.0.15")
  set(PACKAGE_VERSION_COMPATIBLE 1) # compatible with older
  if("${PACKAGE_FIND_VERSION}" VERSION_EQUAL "0.0.15")
    set(PACKAGE_VERSION_EXACT 1) # exact match for this version
  endif()
endif()
