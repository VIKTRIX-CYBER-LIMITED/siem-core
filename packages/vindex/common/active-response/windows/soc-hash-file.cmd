@echo off
REM Windows AR entrypoint: read-only SHA-256 of a path from STDIN JSON.
REM Not containment — no copy/delete/isolate/kill. Keep stdin/stdout attached.
REM https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
REM
REM wazuh-agent is 32-bit: System32\WindowsPowerShell is WOW64-redirected to
REM SysWOW64. Sysnative reaches the real 64-bit PowerShell; fall back to
REM System32 when Sysnative is absent (already-64-bit host / non-WOW64).
set "PS64=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS64%" set "PS64=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
"%PS64%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0soc-hash-file.ps1"
exit /b %ERRORLEVEL%
