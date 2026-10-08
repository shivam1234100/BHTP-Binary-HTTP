@echo off
rem Runs bcurl.py with the Python launcher if present, else python.
where py >nul 2>nul || goto nopy
py -3 "%~dp0bcurl.py" %*
exit /b %errorlevel%
:nopy
python "%~dp0bcurl.py" %*
exit /b %errorlevel%
