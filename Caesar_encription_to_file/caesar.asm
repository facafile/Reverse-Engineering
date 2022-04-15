.386
.model flat, stdcall
option casemap :none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc

includelib \masm32\lib\user32.lib 
includelib \masm32\lib\kernel32.lib


.data
    textLength    dd 0h
    encryptionKey dd 3h

    fileHandle dd 0h
    fileHandle2 dd 0h
    fileName_read db "Citaj.txt",0h
    fileName_write db "Pisi.txt",0h

    readB dd ?
    writeB dd ?
    bufferAddress dd 0h



.code
start:

    push 0h
    push FILE_ATTRIBUTE_NORMAL 
    push OPEN_EXISTING
    push 0h
    push 0h
    push GENERIC_READ
    push offset fileName_read
    call [CreateFileA]

    mov dword ptr [fileHandle], eax

    push 0h
    push eax
    call [GetFileSize]

    mov dword ptr [textLength],eax

    inc eax


    push PAGE_READWRITE
    push MEM_COMMIT 
    push eax
    push 0h
    call [VirtualAlloc]

    mov dword ptr [bufferAddress],eax

    push 0h
    push offset readB
    push dword ptr [textLength]
    push dword ptr [bufferAddress]
    push dword ptr [fileHandle]
    call [ReadFile]




    mov esi, dword ptr [bufferAddress]
    mov eax, offset encryptionKey
    mov ecx, textLength

encryption_loop:

    mov bl, byte ptr [esi]
    cmp bl, 77h
    jle ceasar
    sub bl, 1Ah

ceasar:
    add bl, byte ptr [eax]
    mov byte ptr [esi], bl

    inc esi
    loop encryption_loop



    push 0h
    push FILE_ATTRIBUTE_NORMAL 
    push CREATE_ALWAYS
    push 0h
    push 0h
    push GENERIC_WRITE
    push offset fileName_write
    call [CreateFileA]

    mov dword ptr [fileHandle2],eax

    push 0h
    push offset writeB
    push dword ptr [textLength]
    push dword ptr [bufferAddress]
    push dword ptr [fileHandle2]
    call [WriteFile]

    push dword ptr [fileHandle2]
    call [CloseHandle]


    push MEM_DECOMMIT
    push 0
    push dword ptr [bufferAddress]
    call [VirtualFree]

    push dword ptr [fileHandle]
    call [CloseHandle]

    ret
end start