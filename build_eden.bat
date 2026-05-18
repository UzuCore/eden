@echo off
chcp 65001 > nul

set SOURCE_DIR=D:\NSW.dev\eden
set BIN_DIR=%SOURCE_DIR%\build\bin\Release
set RELEASE_DIR=%SOURCE_DIR%\release
set SEVENZIP=C:\Program Files\7-Zip\7z.exe
set "PATH=C:\Program Files\CMake\bin;%PATH%"
for /d %%i in ("C:\VulkanSDK\*") do set "PATH=%%i\Bin;%PATH%"

if not exist "%SEVENZIP%" (
    echo 7-Zip not found at:
    echo   %SEVENZIP%
    echo Please install 7-Zip or edit SEVENZIP path in this script.
    pause
    exit /b 1
)

set /p CLEAN=Clean build? (y/N): 
if /i "%CLEAN%"=="Y" (
    echo Removing build folder...
    rmdir /s /q "%SOURCE_DIR%\build"
)

echo [1/4] Loading MSVC environment...
powershell -ExecutionPolicy Bypass -File "%SOURCE_DIR%\tools\windows\load-msvc-env.ps1"
if %errorlevel% neq 0 ( echo FAILED & pause & exit /b 1 )

if not exist "%SOURCE_DIR%\build" (
    echo [2/4] CMake configure...
    cmake -S "%SOURCE_DIR%" -B "%SOURCE_DIR%\build" -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DYUZU_TESTS=OFF -DYUZU_USE_BUNDLED_QT=ON -DYUZU_USE_CPM=ON -DENABLE_LTO=ON -DYUZU_CMD=OFF -DYUZU_ROOM=ON -DYUZU_USE_BUNDLED_FFMPEG=ON -DENABLE_QT_TRANSLATION=ON -DYUZU_STATIC_BUILD=ON -DYUZU_USE_BUNDLED_OPENSSL=ON
    if %errorlevel% neq 0 ( echo FAILED & pause & exit /b 1 )
) else (
    echo [2/4] CMake configure skipped
)

echo [3/4] Building...
cmake --build "%SOURCE_DIR%\build" --config Release --parallel 4
if %errorlevel% neq 0 ( echo FAILED & pause & exit /b 1 )

echo [4/4] Copying and zipping...
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyMMdd"') do set DATE=%%i

set ZIP_FILE=%RELEASE_DIR%\eden_windows_%DATE%.zip

if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"
if exist "%ZIP_FILE%" del /q "%ZIP_FILE%"

copy "%BIN_DIR%\eden.exe" "%RELEASE_DIR%\eden.exe"
if %errorlevel% neq 0 ( echo Copy FAILED & pause & exit /b 1 )

copy "%BIN_DIR%\eden-room.exe" "%RELEASE_DIR%\eden-room.exe"
if %errorlevel% neq 0 ( echo Copy FAILED & pause & exit /b 1 )

"%SEVENZIP%" a -tzip -mx10 "%ZIP_FILE%" "%RELEASE_DIR%\eden.exe" "%RELEASE_DIR%\eden-room.exe" > nul
if %errorlevel% neq 0 ( echo ZIP FAILED & pause & exit /b 1 )

echo.
echo Done: %ZIP_FILE%
pause
