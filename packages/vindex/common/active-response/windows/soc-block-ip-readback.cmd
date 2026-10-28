@echo off
REM Stateless read-only verification for policy-bound block_ip executions.
REM It shares parsing/signing code with the apply/expiry wrapper but the
REM -Readback path never invokes netsh add/delete or any firewall mutator.
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0soc-block-ip.ps1" -Readback
exit /b %ERRORLEVEL%
