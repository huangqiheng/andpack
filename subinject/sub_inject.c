/* Header Files */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <wchar.h>
#include <tchar.h>
#include "../log/logclient.h"
#include "../capsule/string_memory.h"
#include "../capsule/injector.h"
#include "../capsule/oep_infect.h"
#include "../capsule/log_print.h"
#include "easy_hook.h"


#define __inline__ inline  __attribute__((always_inline))

__inline__ long get_ebproot_0()
{
	long output = 0;
	asm (
		"movl %%ebp, %0\n"
		:"=r" (output): :
	);
	return output;
}
__inline__ long get_ebproot_1()
{
	long output = 0;
	asm (
		"movl (%%ebp), %0\n"
		:"=r" (output): :
	);
	return output;
}
__inline__ void* get_whocallme(int level)
{
	long ebp_val;
	switch (level)
	{
		case 0:	ebp_val = get_ebproot_0(); break;
		case 1:	ebp_val = get_ebproot_1(); break;
		default: return (NULL);
	}
	return (void*)*((long*)(ebp_val+sizeof(void*)));
}


/*宽字符转换为多字符Unicode - ANSI*/
char* w2m(const wchar_t* wcs)
{
      int len;
      char* buf;
      len =wcstombs(NULL,wcs,0);
      if (len == 0)
          return NULL;
      buf = (char *)malloc(sizeof(char)*(len+1));
      memset(buf, 0, sizeof(char) *(len+1));
      len =wcstombs(buf,wcs,len+1);
      return buf;
}
/*多字符转换为宽字符ANSI - Unicode*/
wchar_t* m2w(const char* mbs)
{
      int len;
      wchar_t* buf;
      len =mbstowcs(NULL,mbs,0);
      if (len == 0)
          return NULL;
      buf = (wchar_t *)malloc(sizeof(wchar_t)*(len+1));
      memset(buf, 0, sizeof(wchar_t) *(len+1));
      len =mbstowcs(buf,mbs,len+1);
      return buf;
}


char * UnicodeToUTF8( const wchar_t* str )
{
	char* result;
	int textlen;
	textlen = WideCharToMultiByte( CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL );
	result =(char *)malloc((textlen+1)*sizeof(char));
	memset(result, 0, sizeof(char) * ( textlen + 1 ) );
	WideCharToMultiByte( CP_UTF8, 0, str, -1, result, textlen, NULL, NULL );
	return result;
}


void* get_plugin_buffer(void* code_addr, long* plugin_size)
{
	/*
	获得整片连续的调用者内存空间
	可以认为，这就是插件dll的完整备份。
	*/
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(code_addr, &mbi, sizeof(mbi)) == 0)
	{
		logmsg(MSGDEBUG, "get_plugin_buffer query memory  error: %x\n", code_addr);
		return (NULL);
	}


	/*
	创建自己的一个备份在堆里
	等待后续的注射用
	*/
	int copy_size = mbi.BaseAddress - mbi.AllocationBase + mbi.RegionSize;
	void* run_result = malloc(copy_size);
	memcpy(run_result, mbi.AllocationBase, copy_size);
	*plugin_size = copy_size;

	//调试信息
	log_hex_block(MSGDEBUG,"plugin memory",  mbi.AllocationBase, 16 * 4);
	return (run_result);
}


#define PLUGINS_SECTION_NAME "plugins"

int is_plugin_patched(void* file_base)
{
	if (*(short*)file_base != 0x5a4d)
	{
		return (0);
	}
	return (get_spectial_section_byname(file_base, PLUGINS_SECTION_NAME))? 1 : 0;
}



typedef
BOOL (__stdcall *lpfn_cpiw)(
		HANDLE hToken,
		const wchar_t* lpApplicationName,       
		wchar_t* lpCommandLine,       
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,       
		BOOL bInheritHandles,       
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,       
		const wchar_t* lpCurrentDirectory,       
		LPSTARTUPINFO lpStartupInfo,       
		LPPROCESS_INFORMATION lpProcessInformation ,
		PHANDLE hNewToken);

void* plugin_base = NULL;
long  plugin_size = 0;
lpfn_cpiw real_cpiw;

BOOL __stdcall Hook_CreateProcessInternalW(
		HANDLE hToken,
		const wchar_t* lpApplicationName,       
		wchar_t* lpCommandLine,       
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,       
		BOOL bInheritHandles,       
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,       
		const wchar_t* lpCurrentDirectory,       
		LPSTARTUPINFO lpStartupInfo,       
		LPPROCESS_INFORMATION lpProcessInformation ,
		PHANDLE hNewToken)
{
	BOOL is_ori_suspend = (dwCreationFlags & CREATE_SUSPENDED);
	wchar_t* app_path = NULL;
	wchar_t* cmd_line = NULL;
	BOOL result = 0;
	int i;
	
	if ((result = real_cpiw(hToken,
		lpApplicationName,       
		lpCommandLine,       
		lpProcessAttributes,
		lpThreadAttributes,       
		bInheritHandles,       
		dwCreationFlags | CREATE_SUSPENDED,
		lpEnvironment,       
		lpCurrentDirectory,       
		lpStartupInfo,       
		lpProcessInformation ,
		hNewToken)) == FALSE)
	{
		logmsg(MSGDEBUG, "CreateProcessInternalW error (%ws)", lpCommandLine);
		goto direct_exit;
	}


	/*
	从命令行中获得程序路径
	如果不能获取路径，那将放弃注射
	*/
	if (lpApplicationName)
	{
		cmd_line = _wcsdup(lpApplicationName);
		DbgPrintW(L"hooker:: child process(appname): %ls", cmd_line);
		if (cmd_line[0] == L'"')
		{
			i = 1;
			while (cmd_line[i])
			{
				if (cmd_line[i] == L'"')
				{
					cmd_line[i] = L'\0';
					app_path = &cmd_line[1]; 
					break;
				}
				i++;
			}
		}
		else
		{
			app_path = cmd_line;
		}
	}
	else
	{
		cmd_line = _wcsdup(lpCommandLine);
		DbgPrintW(L"hooker:: child process(cmdline): %ls", cmd_line);
		int str_len = wcslen(cmd_line);

		if (cmd_line[0] == L'"')
		{
			i = 1;
			while (cmd_line[i])
			{
				if (cmd_line[i] == L'"')
				{
					cmd_line[i] = L'\0';
					app_path = &cmd_line[1]; 
					break;
				}
				i++;
			}
		}
		else
		{
			i = 0;
			while (cmd_line[i])
			{
				if (cmd_line[i] == L' ')
				{
					cmd_line[i] = L'\0';
					app_path = cmd_line; 
					break;
				}
				if (cmd_line[i] == L'\0')
				{
					break;
				}
				i++;
			}
		}
	}


	if (app_path == NULL)
	{
		logmsg(MSGDEBUG, "app_path is NULL, %ws", lpCommandLine);
		goto resume_exit;
	}


	logmsg(MSGDEBUG, "got file: %s\n", UnicodeToUTF8(app_path));


	/*
	检查目标文件，看是否已经被打包
	如果没有，则需要注射
	如果已经有，则直接退出
	*/
	HANDLE exe_file_handle = CreateFileW(app_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (exe_file_handle == 0)
	{
		logmsg(MSGDEBUG, "CreateFile error(%ws)", app_path);
		goto resume_exit;
	}
	long need_file_size = GetFileSize(exe_file_handle, NULL);
	if (need_file_size == -1)
	{
		OutputDebugStringW(app_path);
		logmsg(MSGDEBUG, "GetFileSize (%ws) err:%d.", w2m(app_path), GetLastError());
		goto close_handle_exit;
	}

	const long head_size = 0x1000;
	if (need_file_size > head_size)
	{
		need_file_size = head_size;
	}

	SetFilePointer(exe_file_handle, 0, NULL, FILE_BEGIN);

	void *file_base = (void*)malloc(need_file_size);
	DWORD lpNumberOfBytesRW;
	if (FALSE == ReadFile(exe_file_handle, file_base, need_file_size, &lpNumberOfBytesRW, NULL))
	{
		logmsg(MSGDEBUG, "read file error(%s-%d)", app_path, GetLastError());
		goto free_malloc_exit;
	}

	if (is_plugin_patched(file_base))
	{
		logmsg(MSGDEBUG, "had been patched, ignor!");
		goto free_malloc_exit;
	}

	struct HOOK_ITEM hook_item[2];
	memset(&hook_item, 0, sizeof(hook_item));
	hook_item[0].thread_fun_base = plugin_base;
	hook_item[0].thread_fun_size = plugin_size;
	hook_item[0].thread_fun_param = 0;
	hook_item[1].thread_fun_base = NULL;

	logmsg(MSGDEBUG, "start inject plugin base: 0x%x, size: 0x%x\n", plugin_base, plugin_size);

	if (!run_code_by_thread(lpProcessInformation->hProcess, lpProcessInformation->hThread, &hook_item[0], 0))
	{
		logmsg(MSGDEBUG, "inject error!");
		goto free_malloc_exit;
	}

	logmsg(MSGDEBUG, "inject plugins to sub process succeed!\n");

free_malloc_exit:
	free(file_base);

close_handle_exit:
	CloseHandle(exe_file_handle);

resume_exit:
	if ((result) && (is_ori_suspend == FALSE))
	{
		ResumeThread(lpProcessInformation->hThread);
	}

direct_exit:
	logmsg(MSGDEBUG, "inject finished");
	return (result);
}

char* host_process()
{
	char host_process[MAX_PATH];
	if (GetModuleFileName(NULL, host_process, MAX_PATH))
	{
		return strdup(host_process);
	}
	else
	{
		return NULL;
	}
}

BOOL WINAPI DllMain (HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
	switch(fdwReason) 
	{ 
		case DLL_PROCESS_ATTACH: 
			DbgPrint("subprocess.dll started in: %s", host_process());
			plugin_base = get_plugin_buffer(get_whocallme(1), &plugin_size);
			real_cpiw = (lpfn_cpiw)easy_hook_install("kernel32.dll", "CreateProcessInternalW", &Hook_CreateProcessInternalW);
			break;
		case DLL_PROCESS_DETACH: 
			easy_hook_clean(NULL);
			break;
	}
	SetLastError(0);
	return (TRUE);
}
