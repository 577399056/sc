@echo off
REM ============================================================
REM Build sing-box with CNS outbound for Android
REM Requires: Go 1.24+, Android NDK (for CGO cross-compile), or 
REM use CGO_ENABLED=0 for pure-Go build without CGO features.
REM ============================================================

setlocal enabledelayedexpansion

REM --- Configuration ---
set "ANDROID_API=21"
set "BUILD_TAGS=with_gvisor,with_quic,with_utls,with_clash_api,with_ccm,with_ocm,badlinkname,tfogo_checklinkname0"
set "LDFLAGS=-s -w -buildid= -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0"
set "OUTPUT_DIR=output"

REM --- Build for each Android ABI ---
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM arm64 (64-bit, most modern devices)
echo [1/4] Building for android/arm64...
set GOOS=android
set GOARCH=arm64
set CGO_ENABLED=0
go build -v -trimpath -tags "%BUILD_TAGS%" -ldflags "%LDFLAGS%" -o "%OUTPUT_DIR%/sing-box-arm64" ./cmd/sing-box
if %ERRORLEVEL% neq 0 (
    echo ERROR: arm64 build failed!
goto :error
)

REM arm (32-bit, older devices)
echo [2/4] Building for android/arm...
set GOOS=android
set GOARCH=arm
set GOARM=7
set CGO_ENABLED=0
go build -v -trimpath -tags "%BUILD_TAGS%" -ldflags "%LDFLAGS%" -o "%OUTPUT_DIR%/sing-box-arm" ./cmd/sing-box
if %ERRORLEVEL% neq 0 (
    echo ERROR: arm build failed!
    goto :error
)

REM amd64 (x86_64, emulators/chromebooks)
echo [3/4] Building for android/amd64...
set GOOS=android
set GOARCH=amd64
set CGO_ENABLED=0
go build -v -trimpath -tags "%BUILD_TAGS%" -ldflags "%LDFLAGS%" -o "%OUTPUT_DIR%/sing-box-amd64" ./cmd/sing-box
if %ERRORLEVEL% neq 0 (
    echo ERROR: amd64 build failed!
    goto :error
)

REM 386 (x86_32, emulators)
echo [4/4] Building for android/386...
set GOOS=android
set GOARCH=386
set CGO_ENABLED=0
go build -v -trimpath -tags "%BUILD_TAGS%" -ldflags "%LDFLAGS%" -o "%OUTPUT_DIR%/sing-box-386" ./cmd/sing-box
if %ERRORLEVEL% neq 0 (
    echo ERROR: 386 build failed!
    goto :error
)

echo.
echo ==========================================
echo BUILD SUCCESS!
echo Output files in: %OUTPUT_DIR%
echo ==========================================
echo.
echo To deploy:
echo   adb push output/sing-box-arm64 /data/local/tmp/sing-box
echo   adb shell chmod 755 /data/local/tmp/sing-box
echo   adb shell /data/local/tmp/sing-box run -c /path/to/config.json
echo.

goto :end

:error
echo Build failed!
exit /b 1

:end
endlocal
