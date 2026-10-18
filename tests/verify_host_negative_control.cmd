@echo off
rem Verify the host_check negative-control path against the explicit
rem contract:
rem   1. exit code is exactly 1 (not any non-zero, not zero)
rem   2. the line "[negative-control] FAIL: expected pointer width 4 byte(s), got 8"
rem      appears verbatim somewhere in the program's combined output
rem
rem Both checks are required. The driver returns 0 only when BOTH hold.

setlocal
set "EXE=%~1"
if "%EXE%"=="" (
    echo verify_host_negative_control: missing executable argument 1>&2
    exit /b 2
)
if not exist "%EXE%" (
    echo verify_host_negative_control: executable not found: "%EXE%" 1>&2
    exit /b 2
)

set "TMPOUT=%TEMP%\host_check_neg_%RANDOM%%RANDOM%.txt"
"%EXE%" --negative-control > "%TMPOUT%" 2>&1
set "RC=%ERRORLEVEL%"

if not "%RC%"=="1" (
    echo verify_host_negative_control: WRONG, expected exit code 1, got %RC% 1>&2
    type "%TMPOUT%" 1>&2
    del "%TMPOUT%" 2>nul
    exit /b 1
)

rem /L = literal (no regex), /X = match the entire line. Together these
rem require the literal string to appear as a complete line, not as a
rem partial substring of some other diagnostic.
findstr /L /X /C:"[negative-control] FAIL: expected pointer width 4 byte(s), got 8" "%TMPOUT%" >nul
if errorlevel 1 (
    echo verify_host_negative_control: WRONG, expected exact diagnostic line not present 1>&2
    type "%TMPOUT%" 1>&2
    del "%TMPOUT%" 2>nul
    exit /b 1
)

echo verify_host_negative_control: OK, host_check --negative-control returned exit code %RC% with the contracted diagnostic line 1>&2
del "%TMPOUT%" 2>nul
exit /b 0
