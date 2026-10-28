@echo off
REM Windows AR entrypoint for the HMAC overlay. Not a Python script: Wazuh
REM docs require .cmd/.exe on Windows, and Local System has PowerShell.
REM Keep stdin/stdout attached — execd's check_keys handshake deadlocks otherwise.
REM https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0soc-block-ip.ps1"
exit /b %ERRORLEVEL%
