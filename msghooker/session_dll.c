#define _WIN32_WINNT 0x0500

#include <windows.h>
#include <stdio.h>
#include <winnt.h>
#include <assert.h>
#include <string.h>
#include <wchar.h>
#include <tchar.h>
#include <tlhelp32.h>
#include "stackar.h"
#include "global.h"
#include "dll_in_section.h"
#include "xml_in_section.h"
#include "dll_loader.h"
#include "threadpower.h"

#define SHARE __attribute__((section(SHARED_SECTION_NAME), shared))
#define share_buffer_max_size 0x1000*4

HHOOK hkKey SHARE = NULL;				
DWORD daemon_process_id SHARE = 0;
DWORD daemon_start_tick SHARE = 0;
long session_counter SHARE = 0;
char share_xml_buffer[share_buffer_max_size] SHARE = {0};

HINSTANCE me_image_handle = NULL;
char* share_mutex_name = NULL;

void init_share_memory()
{
	if (share_mutex_name == NULL)
	{
		STARTUP* startup = (STARTUP*)get_section(me_image_handle, STUB_START_SECTION_NAME);
		char* mutex_name = (char*)STARTUP(startup->share_mutex_name);
		char name_buff[MAX_PATH];
		sprintf(name_buff, "Local\\mutex-%s", mutex_name);
		share_mutex_name = strdup(name_buff);
	}
}


__declspec(dllexport) int __stdcall set_session_sharekey(const char* type, const char* key, const char* value)
{
	init_share_memory();
	HANDLE wait_handle = enter_mutex_process_wait(share_mutex_name);

	char* ori_xml = (strlen(&share_xml_buffer[0]))? share_xml_buffer : NULL;
	const char* new_xml = set_keyvalue(ori_xml, type, key, value);

	int result = 0;
	if (new_xml)
	{
		int new_len = strlen(new_xml);
		if (new_len < share_buffer_max_size)
		{
			strcpy(share_xml_buffer, new_xml);
			result = 1;
		}
	}

	leave_mutex_process(wait_handle);
	return (result);
}

__declspec(dllexport) const char* __stdcall get_session_sharekey(const char* type, const char* key)
{
	init_share_memory();

	HANDLE wait_handle = enter_mutex_process_wait(share_mutex_name);

	char* ori_xml = (strlen(share_xml_buffer))? share_xml_buffer : NULL;
	if (ori_xml == NULL)
	{
		return (NULL);
	}

	const char** values =  get_keyvalue(ori_xml, type, key);
	leave_mutex_process(wait_handle);

	return (values)? values[1] : NULL;
}

LRESULT CALLBACK procCharMsg(int nCode,WPARAM wParam, LPARAM lParam)
{
	return CallNextHookEx(hkKey,nCode,wParam,lParam);
}

__declspec(dllexport) int __stdcall set_hook()
{
	if(hkKey == NULL)
	{
		HINSTANCE hInstHookDll = GetModuleHandleA(SESSION_DLL_NAME);
		hkKey = SetWindowsHookEx(WH_GETMESSAGE,procCharMsg,hInstHookDll,0);

		daemon_process_id = GetCurrentProcessId(); 
		daemon_start_tick = GetTickCount();
	}
	return (int)hkKey;
}

__declspec(dllexport) int __stdcall cls_hook()
{
	int run_result = 0;
	if(hkKey !=NULL)
		if (UnhookWindowsHookEx(hkKey))
			run_result = 1;
	hkKey = NULL;
	return (run_result);
}

__declspec(dllexport) const char** __stdcall get_parameters(HINSTANCE image, const char* catelog_name)
{
	if (image == NULL)
	{
		image = me_image_handle;
	}
	const char* xmlstr = image_to_xmlstr(image, PLUGIN_PARAM_SECTION);
	return (get_catelog(xmlstr, catelog_name));
}

__declspec(dllexport) const char** __stdcall get_parameter(HINSTANCE image, const char* catelog_name, const char* key_name)
{
	if (image == NULL)
	{
		image = me_image_handle;
	}

	const char* xmlstr = image_to_xmlstr(image, PLUGIN_PARAM_SECTION);

	if (xmlstr == NULL)
	{
		return (NULL);
	}

	return (get_keyvalue(xmlstr, catelog_name, key_name));
}


__declspec(dllexport) PACKAGE* __stdcall get_package()
{
	return (PACKAGE*)get_section(me_image_handle, PACKAGE_SECTION_NAME);
}

__declspec(dllexport) STARTUP* __stdcall get_startup()
{
	return (STARTUP*)get_section(me_image_handle, STUB_START_SECTION_NAME);
}

int is_main_exe_thread(HANDLE thread_handle)
{
	HMODULE main_module = GetModuleHandleA(NULL);
	long  image_size = SIZEOFIMAGE(main_module);
	void* start_addr = get_thread_entry(thread_handle);
	DbgPrint("thread entry: %x", start_addr);

	return (VALIDRANGE(start_addr, main_module, image_size))? 1 : 0;
}

Stack suspend_other_thread()
{
	DWORD current_tid = GetCurrentThreadId();
	DWORD current_pid = GetCurrentProcessId();
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
	Stack thread_stack = CreateStack(0x1000);

	DbgPrint("my thread id: %d", current_tid);

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

			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, target_tid); 
			if (hThread == NULL)
			{ 
				continue;
			} 

			if (!is_main_exe_thread(hThread))
			{
				CloseHandle(hThread);
				continue;
			}

			DbgPrint("suspend: %d(%d)", target_tid, (DWORD)hThread);
			SuspendThread(hThread); 
			Push((int)hThread, thread_stack);
		} 
		CloseHandle(hSnapshot); 
	} 

	return (thread_stack);
}

void resume_other_thread(Stack suspended_thread)
{
	while(!IsEmptyStack(suspended_thread))
	{
		HANDLE hThread = (HANDLE)TopAndPop(suspended_thread);
		DbgPrint("resume: %d", (DWORD)hThread);
		ResumeThread(hThread);
		CloseHandle(hThread);
	}
	DisposeStack(suspended_thread);
}

BOOL run_thread(LPTHREAD_START_ROUTINE thread_pro, PVOID param)
{
	DWORD tid;
	HANDLE thread = CreateThread(NULL, 0, thread_pro, param, 0, &tid);
	CloseHandle(thread);
	return (thread != NULL);
}

DWORD WINAPI load_plugin_thread(LPVOID lpParameter)
{
	PACKAGE* package = get_package();
	HANDLE hThread = (HANDLE)lpParameter;

	DWORD exit_code = 0;
	if (package->plugin_dll_dir.length)
	{
		STORE_ITEM* dll_item = (STORE_ITEM*)PACKAGE(package->plugin_dll_dir);

		for (; dll_item->length; dll_item++)
		{
			void* file_base = (void*)PACKAGE(*dll_item);
			
			char* dll_file_name = __GetMemoryFileName(file_base);
			DbgPrint("------> load plugin: %s <------", dll_file_name);
			
			if (LoadPlugin(file_base, NULL))
			{
				exit_code++;
			}
			else
			{
				DbgPrint("<<< fatal error >>>  load plugin dll error");

			}

			DbgPrint("<----- load finish ------>");
		}
	}

	if (hThread)
	{ 
		ResumeThread(hThread);
		CloseHandle(hThread);
	}

	return (exit_code);
}

void run_plugin()
{
	DWORD main_tid = get_main_thread_id();
	DWORD current_tid = GetCurrentThreadId();

	if (main_tid == current_tid)
	{
		if (!load_plugin_thread(NULL))
		{
			DbgPrint("load_plugin_thread error...");
		}
	}
	else
	{
		do
		{
			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, main_tid); 

			if (hThread == NULL)
			{
				DbgPrint("OpenThread main thread error(%d)", main_tid);
				break;
			}

			if (SuspendThread(hThread) == (DWORD)-1)
			{
				DbgPrint("suspend main thread error(%d)", main_tid);
				CloseHandle(hThread);
				break;
			}

			if (!run_thread(load_plugin_thread, hThread))
			{
				DbgPrint("run load_plugin_thread error...");
			}
		} while (FALSE);
	}
}

void run_packer(int async_thread)
{
	DbgPrint("start load packer.dll");
	PACKAGE* package = get_package();
	void* packer_dll = (void*)PACKAGE(package->packer_dll);

	HMODULE load_ret = __LoadLibrary(NULL, packer_dll, me_image_handle);

	if ((DWORD)load_ret < 32)
	{
		DbgPrint("load packer.dll error[%x]", load_ret);
		return;
	}

	typedef void (*lpfn_on_daemon_exit)(long session_counter, int async_thread);
	lpfn_on_daemon_exit on_daemon_exit = (lpfn_on_daemon_exit)__GetProcAddress(load_ret, "on_daemon_exit");

	if (on_daemon_exit == NULL)
	{
		DbgPrint("GetProcAddress on_daemon_exit = NULL");
		return;
	}

	on_daemon_exit(session_counter, async_thread);
}

//判断运行插件与否，要快速退出
void session_init()
{
	STARTUP* startup = get_startup();

	if (startup == NULL)
	{
		return;
	}

	if (is_plugin_process(startup))
	{
		run_plugin();
	}
	else
	{
		DbgPrint("this isn't a plugin exe");
	}
}

//判断是否需要被打包，要快速退出
void session_final(long left_num)
{
	if (is_debuger_process())
	{
		return;
	}

	STARTUP* startup = get_startup();

	if (startup == NULL)
	{
		return;
	}

	int i_need_repack = is_repack_process(startup);
	int i_run_plugin = is_plugin_process(startup);

	//如果是需要被打包的进程，伴随这守护进程的退出，应该尽快退出进程
	if (i_need_repack)
	{
		//如果守护进程已经不在了，就马上退出进程，接受repack。
		//如果守护进程还在，证明了这是repack进程的主动退出，并不需要马上repack。
		//如果强制ExitProcess退出的话，会让这个进程没有机会处理“后事”
		if (is_process_exists(daemon_process_id))
		{
			DbgPrint("daemon.exe is running, i don't ExitProcess(0)");
		}
		else
		{
			DbgPrint("session.dll: exit process for repack");
			//跟着死？只能随着daemon.exe一起死
			ExitProcess(0);
		}
	}
	else
	{
		//启动触发packer.dll的逻辑
		if ((i_run_plugin) && (left_num > 2))
		{
			DbgPrint("i'm running plugin.dll, and has %d other packer left. so ignore packer", left_num);
		}
		else
		{
			if (is_process_exists(daemon_process_id))
			{
				DbgPrint("daemon.exe is running, i can't run packer");
			}
			else
			{
				run_packer(1);
			}
		}
	}
}

char* daemon_msg_name = NULL;

BOOL WINAPI DllMain (HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
	me_image_handle = hinstDll;
	long lock_val;

	switch(fdwReason) 
	{ 
		case DLL_PROCESS_ATTACH: 
			daemon_msg_name = enable_reporter(hinstDll);
			lock_val = InterlockedIncrement(&session_counter);
			DbgPrint("%s(%x) started(%d) in: %s", SESSION_DLL_NAME, hinstDll, lock_val, current_process_name());
			session_init();
			break;
		case DLL_PROCESS_DETACH: 
			lock_val = InterlockedDecrement(&session_counter);
			DbgPrint("%s(%x) finished(%d) in: %s", SESSION_DLL_NAME, hinstDll, lock_val, current_process_name());
			session_final(lock_val);
			DbgPrint("%s(%x) session_final done(%d)", SESSION_DLL_NAME, hinstDll, lock_val);

			disable_reporter(daemon_msg_name);
			break;
	}

	return (TRUE);
}
