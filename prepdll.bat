@ECHO OFF

NetClone\\NetClone.exe --target Bin\\hijack_x64.dll --reference C:\\Windows\\System32\\%1.dll -o Bin\\%1.dll