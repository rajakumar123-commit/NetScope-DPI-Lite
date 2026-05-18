@echo off
REM ============================================================================
REM run_tests.bat — Compile and run all unit tests for NetScope DPI Lite
REM ============================================================================

echo.
echo  ==========================================
echo   NetScope DPI Lite - Running Unit Tests
echo  ==========================================
echo.

if not exist build mkdir build

echo [INFO] Compiling PacketParser tests...
g++ -std=c++17 -Iinclude tests/test_parser.cpp src/packet_parser.cpp src/types.cpp -o build/test_parser.exe
if errorlevel 1 (
    echo [ERROR] Failed to compile test_parser.cpp
    exit /b 1
)

echo [INFO] Compiling SNIExtractor tests...
g++ -std=c++17 -Iinclude tests/test_sni.cpp src/sni_extractor.cpp src/types.cpp -o build/test_sni.exe
if errorlevel 1 (
    echo [ERROR] Failed to compile test_sni.cpp
    exit /b 1
)

echo.
echo --- Running test_parser.exe ---
.\build\test_parser.exe
if errorlevel 1 (
    echo [ERROR] test_parser failed!
    exit /b 1
)

echo.
echo --- Running test_sni.exe ---
.\build\test_sni.exe
if errorlevel 1 (
    echo [ERROR] test_sni failed!
    exit /b 1
)

echo.
echo  ==========================================
echo   ALL TESTS PASSED SUCCESSFULLY!
echo  ==========================================
echo.
pause
