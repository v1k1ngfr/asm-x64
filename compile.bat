del x64.obj
del x64.exe
"C:\Program Files\NASM\nasm.exe" -f win64 x64_MessageBoxA.asm -o x64.obj
"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.14.26428\bin\Hostx64\x64\link.exe" /ENTRY:main /MACHINE:X64 /NODEFAULTLIB /SUBSYSTEM:CONSOLE x64.obj
