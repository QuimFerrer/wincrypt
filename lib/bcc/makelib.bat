impdef crypt32.def c:\windows\system32\crypt32.dll
impdef cryptui.def c:\windows\system32\cryptui.dll
impdef bcrypt.def c:\windows\system32\bcrypt.dll
impdef ncrypt.def c:\windows\system32\ncrypt.dll

implib crypt32.lib crypt32.def
implib cryptui.lib cryptui.def
implib bcrypt.lib bcrypt.def
implib ncrypt.lib ncrypt.def

del crypt32.def
del cryptui.def
del bcrypt.def
del ncrypt.def