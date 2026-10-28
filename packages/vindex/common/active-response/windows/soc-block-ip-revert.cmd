@echo off
REM Spec 819: analyst revert of a policy-bound block_ip before its TTL. Stateless entry point
REM (registered as soc-block-ip-revert with timeout 0); the -Revert path removes only the exact
REM SOC-block-<execution_id> rule and sends a lease-bound signed reverted/failed ack.
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0soc-block-ip.ps1" -Revert
exit /b %ERRORLEVEL%
