
if not exist "out" mkdir out
cd out
if not exist "build" mkdir build
cd build
if not exist "x64-Debug" mkdir "x64-Debug"
if not exist "x64-Release" mkdir "x64-Release"
cd ..
cd ..


set CMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake
echo CMAKE_TOOLCHAIN_FILE=%CMAKE_TOOLCHAIN_FILE%

cmd /C win\build.bat

