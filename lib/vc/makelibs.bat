@echo off
@echo --------------------------------------------------------------------------
@echo -               Libreria de importacion bcrypt.dll                       -
@echo -               Libreria de importacion cryp32.dll                       -
@echo -               Libreria de importacion cryptui.dll                       -
@echo --------------------------------------------------------------------------

@call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
@call vc_dll2lib.bat 32 bcrypt.dll
@call vc_dll2lib.bat 32 crypt32.dll
@call vc_dll2lib.bat 32 cryptui.dll