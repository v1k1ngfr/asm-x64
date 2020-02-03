del x64_MessageBoxA.obj
del x64_MessageBoxA.exe
"C:\Program Files\NASM\nasm.exe" -f win64 x64_MessageBoxA.asm -o x64_MessageBoxA.obj
"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.14.26428\bin\Hostx64\x64\link.exe" /ENTRY:main /MACHINE:X64 /NODEFAULTLIB /SUBSYSTEM:CONSOLE x64_MessageBoxA.obj
"C:\Program Files\NASM\ndisasm.exe" -b 64 x64.obj > x64_MessageBoxA_disasm.txt
x64_MessageBoxA.exe
