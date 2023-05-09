#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

__inline BOOL CheckDebugger()
{
	__asm {
		mov eax, dword ptr fs : [0x30]
		movzx eax, byte ptr ds : [eax + 0x02]
	}
}

int CheckParentProcess()
{
	HANDLE hProcessSnap = NULL;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() failed.: %lu\n", GetLastError());
		exit (1);
	}
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	int	Pid = GetCurrentProcessId();
	int ParentPid = -1;
	if (Process32First(hProcessSnap, &pe32))
	{
		do {
			if (pe32.th32ProcessID == Pid)
			{
				ParentPid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32));
	}
	CloseHandle(hProcessSnap);
	HANDLE hParentProcess = NULL;
	hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, ParentPid);
	if (!hParentProcess)
	{
		printf("OpenProcess() failed.: %lu\n", GetLastError());
		exit(1);
	}
	CHAR lpFileName[MAX_PATH];

	if (!GetProcessImageFileNameA(hParentProcess, lpFileName, MAX_PATH))
	{
		printf("GetProcessImageFileNameA() failed.: %lu\n", GetLastError());
		exit(1);
	}
	CloseHandle(hParentProcess);
	if (!strcmp(strrchr(lpFileName, '\\') + 1, "Launcher.exe"))
		return (1);
	return (0);
}

int	main(void)
{
	// check mother process
	if (!CheckParentProcess())
	{
		printf("ParentProcess is not Launcher!\n");
		return (1);
	}
	// check debugging
	if (!CheckDebugger())
	{
		printf("Not debugging!!\n");
		return (1);
	}
	
	char buffer[4096];
	while (1)
	{
		scanf_s("%s", buffer, sizeof(buffer));
		if (!strncmp(buffer, "quit", 4) && strlen(buffer) == 4)
		{
			printf("end program.\n");
			break;
		}
		else
			printf("%s\n", buffer);
	}
	return (0);
}
