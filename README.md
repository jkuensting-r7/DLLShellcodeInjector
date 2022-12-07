This is shamelessly stolen/modified code from a variety of sources intended to streamline the process of weaponizing DLL sideload/DLL proxying for red team operations. 

I know, it's a mess. It works, though.

Prerequisites: You'll need to be on a x64 Windows platform with Developer Tools installed, and you'll also need Python.

Usage:
 
1. Determine which DLL you'd like to clone/hijack. 

2. Generate 64-bit shellcode you'd like to inject into the process into which you are going to be sideloading. Save it as "payload_x64.bin" in the "Bin" directory.

3. Change encryption password in both AES.py and DllProxyTemplate.cpp. The shellcode will be encrypted using that password as a key and embedded in the compiled DLL as an RCDATA resource. It will then be retrieved, decrypted, and injected at runtime. 

4. Compile your DLL by executing "compile64.bat". You'll need to do this from an x64 Developer Command Prompt on Windows to have the proper tools at hand. Shellcode will be automatically encrypted using the Python script as illustrated above.

5. Your DLL can now be found in the "Bin" directory as "hijack_x64.dll" and is now ready to be weaponized. "NetClone.exe" from the "Koppeling" project is used for this. Execute `prepdll.bat <name of target DLL to clone>`. You should now find your appropriately named and weaponized DLL in the "Bin" folder.

6. You're good to go. Deliver to the target and execute.