echo off
chcp 65001 > nul
 
set SOURCE_DIR=D:\NSW.dev\eden
set PATH=C:\Program Files\CMake\bin;%PATH%
for /d %%i in ("C:\VulkanSDK\*") do set PATH=%%i\Bin;%PATH%
 
set /p CLEAN="클린빌드? (y/N): "
if /i "%CLEAN%"=="Y" (
    echo build 폴더 삭제 중...
    rmdir /s /q "%SOURCE_DIR%\build"
)
 
echo [1/3] MSVC 환경 로드...
powershell -ExecutionPolicy Bypass -File "%SOURCE_DIR%\tools\windows\load-msvc-env.ps1"
if %errorlevel% neq 0 ( echo 실패 & pause & exit /b 1 )
 
if not exist "%SOURCE_DIR%\build" (
    echo [2/3] CMake 구성 중...
    cmake -S "%SOURCE_DIR%" -B "%SOURCE_DIR%\build" -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DYUZU_TESTS=OFF -DYUZU_USE_BUNDLED_QT=ON -DYUZU_USE_CPM=ON -DENABLE_LTO=ON -DYUZU_CMD=OFF -DYUZU_ROOM=ON -DYUZU_USE_BUNDLED_FFMPEG=ON
    if %errorlevel% neq 0 ( echo 실패 & pause & exit /b 1 )
) else (
    echo [2/3] CMake 구성 생략 (build 폴더 존재)
)
 
echo [3/3] 빌드...
cmake --build "%SOURCE_DIR%\build" --config Release --parallel
if %errorlevel% neq 0 ( echo 실패 & pause & exit /b 1 )
 
echo.
echo 완료: %SOURCE_DIR%\build\bin\Release\eden.exe
pause
