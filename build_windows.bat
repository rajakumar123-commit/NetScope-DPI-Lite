@echo off
REM ============================================================================
REM build_windows.bat — Build NetScope DPI Lite on Windows
REM Requires: MSYS2 with GCC 13 (mingw-w64-ucrt-x86_64-gcc)
REM
REM MSYS2 Install steps:
REM   1. Download from https://www.msys2.org/
REM   2. Install to C:\msys64
REM   3. Open "MSYS2 UCRT64" terminal and run:
REM      pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake --noconfirm
REM   4. Add C:\msys64\ucrt64\bin to your Windows PATH
REM   5. Re-open this terminal and run this script
REM ============================================================================

echo.
echo  ==========================================
echo   NetScope DPI Lite - Windows Build Script
echo  ==========================================
echo.

REM Auto-add MSYS2 to PATH if installed in default location
if exist "C:\msys64\ucrt64\bin\g++.exe" (
    set "PATH=C:\msys64\ucrt64\bin;%PATH%"
    echo [INFO] Found MSYS2 GCC at C:\msys64\ucrt64\bin
)

REM Check g++ version
g++ --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] g++ not found.
    echo.
    echo Please install MSYS2:
    echo   1. Download: https://www.msys2.org/
    echo   2. Open MSYS2 UCRT64 terminal, run:
    echo      pacman -S mingw-w64-ucrt-x86_64-gcc --noconfirm
    echo   3. Add C:\msys64\ucrt64\bin to PATH
    echo   4. Re-run this script
    pause
    exit /b 1
)

echo [INFO] Compiler:
g++ --version | findstr /i "g++"

REM Create output directories
if not exist build  mkdir build
if not exist output mkdir output
if not exist logs   mkdir logs
if not exist pcaps  mkdir pcaps

echo.
echo [INFO] Compiling 11 source files...
echo.

set INCLUDES=-Iinclude
set CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -Wpedantic -static -static-libgcc -static-libstdc++
set SOURCES=src/main.cpp src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/connection_tracker.cpp src/rule_manager.cpp src/load_balancer.cpp src/fast_path.cpp src/metrics.cpp src/logger.cpp

REM Winsock2 for the metrics server HTTP socket
set LIBS=-lws2_32

g++ %CXXFLAGS% %INCLUDES% %SOURCES% -o build/netscope_dpi.exe %LIBS%

if errorlevel 1 (
    echo.
    echo [ERROR] Build FAILED. See errors above.
    pause
    exit /b 1
)

echo.
echo  ==========================================
echo   BUILD OK:  build\netscope_dpi.exe
echo  ==========================================
echo.
echo  Next steps:
echo.
echo  1. Generate test PCAP:
echo     python tests\generate_test_pcap.py
echo.
echo  2. Run the engine (no metrics):
echo     build\netscope_dpi.exe --pcap pcaps\test_dpi.pcap --rules rules.conf --no-metrics
echo.
echo  3. Run with Prometheus (Docker):
echo     cd docker ^&^& docker-compose up --build
echo.
pause
