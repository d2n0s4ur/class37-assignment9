﻿#include <stdio.h>
#include <Windows.h>
#include <signal.h>

#pragma comment (linker, "/INCLUDE:__tls_used") // use TLS
#pragma comment (linker, "/INCLUDE:_pCallBacks") // pCallBacks val to linker

// Launcher Debug Detect
int is_running = 1;
HANDLE hThread = NULL;

// Client Infos
STARTUPINFOA		StartupInfo;
PROCESS_INFORMATION	ProcessInformation;
DEBUG_EVENT         DebugEvent;

__inline BOOL CheckDebugger()
{
    __asm {
        mov eax, dword ptr fs : [0x30]
        movzx eax, byte ptr ds : [eax + 0x02]
    }
}

DWORD WINAPI debug_watchdog(void* arg)
{
    while (is_running)
    {
        if (CheckDebugger())
        {
            printf("Detect Debugger on Launcher!!\n");
            if (ProcessInformation.hProcess)
            {
                CloseHandle(ProcessInformation.hThread);
                CloseHandle(ProcessInformation.hProcess);
            }
            ExitProcess(1);
        }
        Sleep(100);
    }
    ExitThread(0);
}

void NTAPI TLS_CALLBACK1(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    if (Reason) // before main
    {
        // make watchdog thread
        hThread = CreateThread(0, 0, debug_watchdog, &is_running, 0, 0);
    }
    else // end main
        is_running = 0;
}

#pragma data_seg(".CRT$XLX")
extern "C" PIMAGE_TLS_CALLBACK pCallBacks[] = { TLS_CALLBACK1, 0 };
#pragma data_seg()

DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT DebugEv);
DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT DebugEv);
DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT DebugEv);
DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT DebugEv);
DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT DebugEv);
DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT DebugEv);
DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT DebugEv);
DWORD OnRipEvent(const LPDEBUG_EVENT DebugEv);

void EnterDebugLoop(const LPDEBUG_EVENT DebugEv)
{
    DWORD   dwContinueStatus = DBG_CONTINUE; // exception continuation 
    BOOL    isExit = FALSE;

    while (!isExit)
    {
        // Wait for a debugging event to occur. The second parameter indicates
        // that the function does not return until a debugging event occurs. 

        WaitForDebugEvent(DebugEv, INFINITE);

        // Process the debugging event code. 
        
        switch (DebugEv->dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            // Process the exception code. When handling 
            // exceptions, remember to set the continuation 
            // status parameter (dwContinueStatus). This value 
            // is used by the ContinueDebugEvent function. 

            switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                break;

            case EXCEPTION_BREAKPOINT:
                // First chance: Display the current 
                // instruction and register values. 
                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                break;

            case EXCEPTION_SINGLE_STEP:
                // First chance: Update the display of the 
                // current instruction and register values. 
                break;

            case DBG_CONTROL_C:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                break;

            default:
                // Handle other exceptions. 
                break;
            }

            break;

        case CREATE_THREAD_DEBUG_EVENT:
            // As needed, examine or change the thread's registers 
            // with the GetThreadContext and SetThreadContext functions; 
            // and suspend and resume thread execution with the 
            // SuspendThread and ResumeThread functions. 

            dwContinueStatus = OnCreateThreadDebugEvent(DebugEv);
            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            // As needed, examine or change the registers of the
            // process's initial thread with the GetThreadContext and
            // SetThreadContext functions; read from and write to the
            // process's virtual memory with the ReadProcessMemory and
            // WriteProcessMemory functions; and suspend and resume
            // thread execution with the SuspendThread and ResumeThread
            // functions. Be sure to close the handle to the process image
            // file with CloseHandle.

            dwContinueStatus = OnCreateProcessDebugEvent(DebugEv);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            // Display the thread's exit code. 

            dwContinueStatus = OnExitThreadDebugEvent(DebugEv);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            // Display the process's exit code. 

            dwContinueStatus = OnExitProcessDebugEvent(DebugEv);
            isExit = TRUE;
            break;

        case LOAD_DLL_DEBUG_EVENT:
            // Read the debugging information included in the newly 
            // loaded DLL. Be sure to close the handle to the loaded DLL 
            // with CloseHandle.

            dwContinueStatus = OnLoadDllDebugEvent(DebugEv);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            // Display a message that the DLL has been unloaded. 

            dwContinueStatus = OnUnloadDllDebugEvent(DebugEv);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            // Display the output debugging string. 

            dwContinueStatus = OnOutputDebugStringEvent(DebugEv);
            break;

        case RIP_EVENT:
            dwContinueStatus = OnRipEvent(DebugEv);
            isExit = TRUE;
            break;
        }
        
        // Resume executing the thread that reported the debugging event. 

        ContinueDebugEvent(DebugEv->dwProcessId,
            DebugEv->dwThreadId,
            dwContinueStatus);
    }
}

DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT DebugEv)
{
    CREATE_THREAD_DEBUG_INFO* lpDebugInfo = NULL;

    lpDebugInfo = (LPCREATE_THREAD_DEBUG_INFO)DebugEv;
    printf("[log] New Thread Detected. Thread ID: %d\n", lpDebugInfo->hThread);

    return (DBG_CONTINUE);
}

DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT DebugEv)
{
    CREATE_PROCESS_DEBUG_INFO* lpDebugInfo = NULL;

    lpDebugInfo = (LPCREATE_PROCESS_DEBUG_INFO)DebugEv;
    printf("[log] New Process Detected. Process ID: %d\n", lpDebugInfo->hProcess);

    return (DBG_CONTINUE);
}

DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT DebugEv)
{
    EXIT_THREAD_DEBUG_INFO* lpDebugInfo = NULL;

    lpDebugInfo = (LPEXIT_THREAD_DEBUG_INFO)DebugEv;
    printf("[log] Thread Exit Detected. Thread ID: %d\n", lpDebugInfo->dwExitCode);

    return (DBG_CONTINUE);
}

DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT DebugEv)
{
    EXIT_PROCESS_DEBUG_INFO* lpDebugInfo = NULL;

    lpDebugInfo = (LPEXIT_PROCESS_DEBUG_INFO)DebugEv;
    printf("[log] Process Exit Detected. Process ID: %d\n", lpDebugInfo->dwExitCode);

    return (DBG_CONTINUE);
}

DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT DebugEv)
{
    LOAD_DLL_DEBUG_INFO* lpDebugInfo = NULL;

    lpDebugInfo = (LPLOAD_DLL_DEBUG_INFO)DebugEv;
    printf("[log] DLL Loaded. DLL Handle: %d\n", lpDebugInfo->hFile);

    return (DBG_CONTINUE);
}

DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT DebugEv)
{
    UNLOAD_DLL_DEBUG_INFO* lpDebugInfo = NULL;

    lpDebugInfo = (LPUNLOAD_DLL_DEBUG_INFO)DebugEv;
    printf("[log] DLL Unloaded. DLL base address: %d\n", lpDebugInfo->lpBaseOfDll);

    return (DBG_CONTINUE);
}

DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT DebugEv)
{
    OUTPUT_DEBUG_STRING_INFO* lpDebugInfo = NULL;

    lpDebugInfo = (LPOUTPUT_DEBUG_STRING_INFO)DebugEv;
    printf("[log] Debug String: [%s]\n", lpDebugInfo->lpDebugStringData);

    return (DBG_CONTINUE);
}

DWORD OnRipEvent(const LPDEBUG_EVENT DebugEv)
{
    RIP_INFO* lpDebugInfo = NULL;

    lpDebugInfo = (LPRIP_INFO)DebugEv;
    printf("[log] RIP Error: [%d]\n", lpDebugInfo->dwError);

    return (DBG_CONTINUE);
}

int	main(void)
{
	// Exec Client
	char				programPath[] = "C:\\Users\\PC\\source\\repos\\assignment9\\Release\\client.exe";
	char				args[] = "";

    if (CheckDebugger())
    {
        printf("Detect Debugger on Launcher!!\n");
        return (1);
    }

	if (!CreateProcessA(programPath, args, NULL,  NULL, FALSE, 
        NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, 
        NULL, NULL, &StartupInfo, &ProcessInformation))
	{
		printf("CreateProcessA() failed.: %lu\n", GetLastError());
		exit(1);
	}
    DebugActiveProcess(ProcessInformation.dwProcessId);
    EnterDebugLoop(&DebugEvent);

	// end client
	WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
	CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);

	return (0);
}