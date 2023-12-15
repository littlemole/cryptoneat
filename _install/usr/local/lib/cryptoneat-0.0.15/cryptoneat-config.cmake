# Compute installation prefix relative to this file.
get_filename_component(_dir "${CMAKE_CURRENT_LIST_FILE}" PATH)
get_filename_component(_prefix "${_dir}/../.." ABSOLUTE)

# Import the targets.
include("${_prefix}/lib/cryptoneat-0.0.15/cryptoneat-targets.cmake")

# Report other information.
set(cryptoneat_INCLUDE_DIRS "${_prefix}/include/")
#set(cryptoneat_LIBRARIES cryptoneat;/usr/lib/x86_64-linux-gnu/libssl.so;/usr/lib/x86_64-linux-gnu/libcrypto.so pthread;uuid "${_prefix}/lib/libcryptoneat.a")
