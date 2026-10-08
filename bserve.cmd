@echo off
rem Runs bserve.py with the Python launcher if present, else python.
where py >nul 2>nul || goto nopy
py -3 "%~dp0bserve.py" %*
exit /b %errorlevel%
:nopy
python "%~dp0bserve.py" %*
exit /b %errorlevel%
