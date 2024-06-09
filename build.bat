@echo off
@REM Remove the build directory if it exists
if exist build rmdir /s /q build

@REM Create the build directory
mkdir build

@REM Change to the build directory
cd build

@REM Run CMake to generate the build files
cmake -G "Visual Studio 17 2022" -A Win32 ..

@REM Build the project
cmake --build . --config Release