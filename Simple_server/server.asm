¸.386
.model flat, stdcall
option casemap :none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\Ws2_32.inc
include \masm32\include\Shlwapi.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\Ws2_32.lib
includelib \masm32\lib\Shlwapi.lib

.data

	wsaData db 10h dup (0h)
	socketHandle dd 0h

	socketPort dw 4D2h
	socketAddress db "127.0.0.1", 0h

	socketParameters db 10h dup (0h)

	storageAddressLength db 10h
	storageAddress db 10h dup (0h)

	connectionHandle dd 0h
	processListHandle dd 0h

	receiveBuffer db 100h dup (0h)
	receivedSize dd 0h

	processInformation db 100h dup (0h)
	startupInformation db 100h dup (0h)
	
	strResult db 10h dup (0h)
	new_line db 0Ah
	

.data?
	pe32 PROCESSENTRY32 <?>


.code
	brisi:
		push ebp
		mov ebp, esp
		mov ecx,dword ptr [ebp + 8h]
		mov ebx, dword ptr [ebp + 0Ch]

		loop_start:
			mov dword ptr [ebx],0h
			add ebx,4h
		loop loop_start

		mov esp,ebp
		pop ebp
	retn 4h

	velicina:
		push ebp
		mov ebp, esp
		mov ebx, dword ptr [ebp + 8h]
		xor eax, eax
		cmp byte ptr [ebx],0h
		je kraj
	loop_1:
		inc eax
		inc ebx
		cmp byte ptr [ebx],0h
		jne loop_1
	kraj:
		mov esp,ebp
		pop ebp
	retn 4h


	broj_u_ascii:
		push ebp
		mov ebp, esp

		mov eax, dword ptr [ebp + 8h]     
    	mov ecx, 10         
    	xor bx, bx          

	divide:
    	xor edx, edx        
    	div ecx             
    	push dx             
    	inc bx              
    	test eax, eax       
    	jnz divide          

    ; POP digits from stack in reverse order

    mov cx, bx          
    lea ebx, strResult   

	next_digit:
    	pop ax
    	add al,'0'         
    	mov [ebx], al      
    	inc ebx
    	loop next_digit

		mov esp,ebp
		pop ebp
		retn 4h
start:
	mov eax, offset wsaData
	push eax
	push 202h
	call [WSAStartup]

	push IPPROTO_TCP
	push SOCK_STREAM
	push AF_INET
	call [socket]
	mov dword ptr [socketHandle], eax

	mov word ptr [socketParameters], AF_INET

	push dword ptr [socketPort]
	call [htons]
	mov dword ptr [socketParameters + 2], eax

	push offset socketAddress
	call [inet_addr]

	mov dword ptr [socketParameters + 4], eax

	push 10h
	push offset socketParameters
	push dword ptr [socketHandle]
	call [bind]

	push 1h
	push dword ptr [socketHandle]
	call [listen]

	push offset storageAddressLength
	push offset storageAddress
	push dword ptr [socketHandle]
	call [accept]
	mov dword ptr [connectionHandle], eax

	receive_command:
		push 0h
		push 100h
		push offset receiveBuffer
		push dword ptr [connectionHandle]
		call [recv]
		mov dword ptr [receivedSize], eax

	parsiranje_komande:
		cmp word ptr [receiveBuffer], 2065h
		je echo_command
		cmp word ptr [receiveBuffer], 2072h
		je run_command
		cmp word ptr [receiveBuffer], 206Bh
		je kill_command
		cmp word ptr [receiveBuffer], 6873h ;sh - terminate server
		je epilog
		cmp dword ptr [receiveBuffer],7473696Ch
		je list_command

	echo_command:
		mov ebx, dword ptr [receivedSize]
		mov byte ptr [receiveBuffer + ebx - 1h], 0h
		mov ecx, offset [receiveBuffer + 2h]
		mov eax, MB_OK

		push eax
		push ecx
		push ecx
		push 0h
		call [MessageBox]

		jmp receive_command

	run_command:
		mov ebx, dword ptr [receivedSize]
		mov byte ptr [receiveBuffer + ebx - 1h], 0h
		mov ecx, offset [receiveBuffer + 2h]

		push offset processInformation
		push offset startupInformation
		push 0h
		push 0h
		push 0h
		push 0h
		push 0h
		push 0h
		push 0h
		push ecx
		call [CreateProcessA]

		jmp receive_command

	kill_command:
		mov ebx, dword ptr [receivedSize]
		mov byte ptr [receiveBuffer + ebx - 1h], 0h
		mov ecx, offset [receiveBuffer + 2h]

		push ecx
		call [StrToIntA]

		push eax
		push 0h
		push PROCESS_TERMINATE
		call [OpenProcess]

		push 0h
		push eax
		call [TerminateProcess]

		jmp receive_command

	list_command:
		mov pe32.dwSize, sizeof PROCESSENTRY32

		push 0h
		push TH32CS_SNAPPROCESS
		call [CreateToolhelp32Snapshot] 
		
		mov dword ptr [processListHandle],eax

		push offset pe32
		push eax
		call [Process32First]

		mov eax, offset pe32.dwSize
		cmp eax,0h
		je kraj_list

		push MSG_DONTROUTE
		push 10h
		push offset pe32.szExeFile
		push dword ptr [connectionHandle]
		call [send]

		push MSG_DONTROUTE
		push 1h
		push offset new_line;
		push dword ptr [connectionHandle]
		call [send]


		petlja_list:
			push offset pe32
			push dword ptr [processListHandle]
			call [Process32Next]

			cmp eax,0h
			je kraj_list

			push offset pe32.szExeFile
			call velicina
			inc eax
			
			push MSG_DONTROUTE
			push eax
			push offset pe32.szExeFile
			push dword ptr [connectionHandle]
			call [send]

			push pe32.th32ProcessID
			call broj_u_ascii

			push MSG_DONTROUTE
			push 10h
			push offset strResult;
			push dword ptr [connectionHandle]
			call [send]

			push offset strResult
			push 4h
			call brisi

			push MSG_DONTROUTE
			push 1h
			push offset new_line
			push dword ptr [connectionHandle]
			call [send]

			push offset pe32.szExeFile
			push 1Ah
			call brisi

			jmp petlja_list
		

		kraj_list:
			jmp receive_command

	epilog:
		push 0h
		call [ExitProcess]

end start