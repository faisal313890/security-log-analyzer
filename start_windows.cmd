@echo off
cd /d "%~dp0"
py -3.12 server.py
if errorlevel 1 pause
