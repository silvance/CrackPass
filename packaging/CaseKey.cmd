@echo off
rem ============================================================================
rem CaseKey turnkey launcher (full bundle).
rem
rem Makes the bundled Python (needed by the John *2john extraction scripts, e.g.
rem office2john) and the bundled engines discoverable, then starts the GUI.
rem Everything stays inside THIS folder -- nothing is installed system-wide and
rem no network access is used. You can also run casekey.exe directly if you have
rem a Python interpreter on your PATH already.
rem ============================================================================
setlocal
set "HERE=%~dp0"
set "PATH=%HERE%runtime\python;%HERE%tools\hashcat;%HERE%tools\john\run;%HERE%tools\bkcrack;%PATH%"
start "" "%HERE%casekey.exe" %*
endlocal
