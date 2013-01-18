#define _WIN32_WINNT 0x0500

#include <windows.h>
#include <winnt.h>
#include <tlhelp32.h>
#include "threadpower.h"

/*
00401140 >  68 11111111                      push 11111111
00401145    60                               pushad
00401146    9C                               pushfd
00401147    68 22222222                      push 22222222
0040114C    BA 33333333                      mov edx,33333333
00401151    FFD2                             call edx
00401153    9D                               popfd
00401154    61                               popad
00401155    C3                               retn
*/

typedef struct {
	char push_ret;
	unsigned long push_ret_value;  //<------执行返回值
	short pushxx;
	char push_arg;
	unsigned long  push_arg_value;   //<-----线程参数
	char mov_edx;
	unsigned long mov_edx_value; 	//<----线程函数入口
	short call_edx;
	short popxx;
	char ret;
}__attribute__ ((packed, aligned(1))) EIP_HOOK_LEADER;

EIP_HOOK_LEADER eip_hook = {0x68, 0x11111111, 0x9c60, 0x68, 0x22222222, 0xba, 0x33333333, 0xd2ff, 0x619d, 0xc3};

void* alloc_execute_mem(void *codebase, size_t codesize)
{
	void *newcodebase = VirtualAlloc (NULL, codesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(newcodebase, codebase, codesize);
	return newcodebase;
}

DWORD get_eip_hook_leader(DWORD eip, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	EIP_HOOK_LEADER* leader = (EIP_HOOK_LEADER*)alloc_execute_mem(&eip_hook, sizeof(eip_hook));
	leader->push_ret_value = eip;
	leader->push_arg_value = (unsigned long)lpParameter;
	leader->mov_edx_value = (unsigned long)lpStartAddress;
	return ((DWORD)leader);
}

BOOL thread_power_stealer(DWORD dwThreadId, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId); 

	if (hThread == NULL)
	{
		DbgPrint("OpenThread error: %d(%d)", dwThreadId, GetLastError());
		goto error_exit;
	}

	if (SuspendThread(hThread) == (DWORD)-1)
	{
		DbgPrint("SuspendThread error: %d(%d)", hThread, GetLastError());
		goto error_exit;
	}

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	if (!GetThreadContext(hThread, &ctx))
	{
		DbgPrint("GetThreadContext error: %d(%d)", dwThreadId, GetLastError());
		goto error_resume;
	}

	ctx.Eip = get_eip_hook_leader(ctx.Eip, lpStartAddress, lpParameter);

	if (!SetThreadContext(hThread, &ctx))
	{
		DbgPrint("SetThreadContext error: %d(%d)", hThread, GetLastError());
		goto error_resume;
	}

	if (ResumeThread(hThread) == (DWORD)-1)
	{
		DbgPrint("ResumeThread error: %d(%d)", hThread, GetLastError());
		goto error_exit;
	}

	CloseHandle(hThread);
	return (1);

error_resume:
	ResumeThread(hThread);

error_exit:
	if (hThread)
	{
		CloseHandle(hThread);
	}
	return (FALSE);
}

typedef DWORD (__stdcall *pfnNtQueryInformationThread) (HANDLE, DWORD, PVOID, ULONG, PULONG);
pfnNtQueryInformationThread NtQueryInformationThread = NULL;

void* get_thread_entry(HANDLE thread_handle)
{
	HMODULE hModule;
	if (NtQueryInformationThread == NULL)
	{
		hModule = LoadLibrary("ntdll.dll");
		NtQueryInformationThread = (pfnNtQueryInformationThread) GetProcAddress(hModule, "NtQueryInformationThread");
		if (NtQueryInformationThread == NULL)
		{
			return NULL;	// failed to get proc address
		}
	}

	void* start_address = NULL;
	if (NtQueryInformationThread(thread_handle, 9, &start_address, sizeof(start_address), NULL) != 0)
	{
		FreeLibrary(hModule);
		return NULL;
	}

	return (start_address);
}

DWORD get_main_thread_id()
{
	DWORD current_tid = GetCurrentThreadId();
	DWORD current_pid = GetCurrentProcessId();
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 

	DbgPrint("my thread id: %d", current_tid);
	FILETIME earlier_time;
	SYSTEMTIME print_time;
	DWORD ret_tid = 0;

	if (hSnapshot != INVALID_HANDLE_VALUE) 
	{ 
		THREADENTRY32 te = {sizeof(te)}; 
		BOOL fOk = Thread32First(hSnapshot, &te); 

		for (; fOk; fOk = Thread32Next(hSnapshot, &te))
		{ 
			if (te.th32OwnerProcessID != current_pid) 
			{
				continue;
			}

			DWORD target_tid = te.th32ThreadID;
			if (target_tid == current_tid)
			{
				continue;
			}

			HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, target_tid); 
			if (hThread == NULL)
			{ 
				continue;
			} 

			FILETIME CreateTime, ExitTime, KernelTime, UserTime;
			if (!GetThreadTimes(hThread, &CreateTime, &ExitTime, &KernelTime, &UserTime))
			{
				goto close_continue;
			}


			if (FileTimeToSystemTime(&CreateTime, &print_time))
			{
				DbgPrint("create tiem[%d]: %u/%u - %u:%u:%u:%u", target_tid, print_time.wMonth, print_time.wDay, 
					print_time.wHour, print_time.wMinute, print_time.wSecond, print_time.wMilliseconds);
			}

			if (ret_tid == 0)
			{
				earlier_time = CreateTime;
				ret_tid = target_tid;
				goto close_continue;
			}

			if (CompareFileTime(&CreateTime, &earlier_time) == -1)
			{
				earlier_time = CreateTime;
				ret_tid = target_tid;
			}

close_continue:
			CloseHandle(hThread);
		} 
		CloseHandle(hSnapshot); 
	} 

	DbgPrint("finaly got: %d", ret_tid);

	return (ret_tid);
}

BOOL main_thread_power(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	DWORD main_tid = get_main_thread_id();
	return thread_power_stealer(main_tid, lpStartAddress, lpParameter);
}
