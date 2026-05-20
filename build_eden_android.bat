@echo off
chcp 65001 > nul

set SOURCE_DIR=D:\Github\eden
set ANDROID_DIR=%SOURCE_DIR%\src\android
set RELEASE_DIR=%SOURCE_DIR%\release
set "JAVA_HOME=C:\Program Files\Microsoft\jdk-17.0.19.10-hotspot"
set "PATH=%JAVA_HOME%\bin;C:\msys64\mingw64\bin;%PATH%"

set ANDROID_KEYSTORE_FILE=%SOURCE_DIR%\eden.keystore
set ANDROID_KEYSTORE_PASS=4865012k
set ANDROID_KEY_ALIAS=eden

set /p CLEAN=Clean build? (y/N): 
if /i "%CLEAN%"=="Y" (
    echo Removing build folders...
    rmdir /s /q "%ANDROID_DIR%\app\build"
    rmdir /s /q "%ANDROID_DIR%\app\.cxx"
)

echo [1/3] Select flavor:
echo   1) mainline  - Default (arm64)
echo   2) legacy    - Old GPU compatible (arm64)
echo   3) chromeOS  - Chromebook (x86_64)
echo   4) all       - Build all flavors
set /p FLAVOR=Select (1/2/3/4, default 1): 

cd /d "%ANDROID_DIR%"

if "%FLAVOR%"=="4" (
    echo [2/3] Building all flavors...
    call gradlew.bat assembleRelease --no-daemon
    if %errorlevel% neq 0 ( echo FAILED & goto :end )

    echo [3/3] Copying APKs...
    for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyMMdd"') do set DATE=%%i
    if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"

    copy "%ANDROID_DIR%\app\build\outputs\apk\mainline\release\app-mainline-release.apk" "%RELEASE_DIR%\eden_mainline_%DATE%.apk"
    copy "%ANDROID_DIR%\app\build\outputs\apk\legacy\release\app-legacy-release.apk" "%RELEASE_DIR%\eden_legacy_%DATE%.apk"
    copy "%ANDROID_DIR%\app\build\outputs\apk\chromeOS\release\app-chromeOS-release.apk" "%RELEASE_DIR%\eden_chromeOS_%DATE%.apk"
    goto :end
)

if "%FLAVOR%"=="2" (
    set TASK=assembleLegacyRelease
    set FLAVOR_NAME=legacy
    set FOLDER_NAME=legacy
) else if "%FLAVOR%"=="3" (
    set TASK=assembleChromeOSRelease
    set FLAVOR_NAME=chromeOS
    set FOLDER_NAME=chromeOS
) else (
    set TASK=assembleMainlineRelease
    set FLAVOR_NAME=mainline
    set FOLDER_NAME=mainline
)

echo [2/3] Building %TASK%...
call gradlew.bat %TASK% --no-daemon
if %errorlevel% neq 0 ( echo FAILED & goto :end )

echo [3/3] Copying APK...
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyMMdd"') do set DATE=%%i

if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"

copy "%ANDROID_DIR%\app\build\outputs\apk\%FOLDER_NAME%\release\app-%FLAVOR_NAME%-release.apk" "%RELEASE_DIR%\eden_%FLAVOR_NAME%_%DATE%.apk"
if %errorlevel% neq 0 ( echo Copy FAILED & goto :end )

echo.
echo Done: %RELEASE_DIR%\eden_%FLAVOR_NAME%_%DATE%.apk

:end
echo.
echo Press any key to exit...
pause > nul
