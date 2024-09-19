gendef.exe c:\windows\system32\crypt32.dll
gendef.exe c:\windows\system32\cryptui.dll
gendef.exe c:\windows\system32\bcrypt.dll
gendef.exe c:\windows\system32\ncrypt.dll

dlltool --dllname c:\windows\system32\crypt32.dll --def crypt32.def --output-lib libcrypt32.a -k
dlltool --dllname c:\windows\system32\cryptui.dll --def cryptui.def --output-lib libcryptui.a -k
dlltool --dllname c:\windows\system32\bcrypt.dll --def bcrypt.def --output-lib libbcrypt.a -k
dlltool --dllname c:\windows\system32\ncrypt.dll --def ncrypt.def --output-lib libncrypt.a -k

del crypt32.def
del cryptui.def
del bcrypt.def
del ncrypt.def
