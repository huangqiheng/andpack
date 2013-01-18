#include <windows.h>
#include <assert.h>
#include "global.h"
#include "dll_in_section.h"
#include "dll_loader.h"

void* copy_pack(const void* becopy, const int size)
{
	void* run_result = malloc(size);
	memcpy(run_result, becopy, size);
	return (run_result);
}

PACKAGE* __package__ = NULL;
STARTUP* __startup__ = NULL;

void packer_init(void* session_dll)
{
	PACKAGE* package = (PACKAGE*)get_section(session_dll, PACKAGE_SECTION_NAME);
	STARTUP* startup = (STARTUP*)get_section(session_dll, STUB_START_SECTION_NAME);
	assert(package);
	assert(startup);

	__package__ = (PACKAGE*)copy_pack(package, package->size);
	__startup__ = (STARTUP*)copy_pack(startup, startup->size);

}

char* ori_name_mapper(STARTUP* startup, char* check_name)
{
	if (startup->map_file_names.length)
	{
		STORE_ITEM* map_item = (STORE_ITEM*)STARTUP(startup->map_file_names);

		while(map_item->length)
		{
			char* alias_name = strdup((char*)STARTUP(*map_item));
			char* realy_name = strchr(alias_name, ':');

			assert(realy_name);
			*(realy_name++) = '\0';

			DbgPrint("map pair: %s, %s\n", alias_name, realy_name);

			if (stricmp(check_name, alias_name) == 0)
			{
				char* result = strdup(realy_name);
				free(alias_name);
				return (result);
			}

			map_item++;
		}
	}

	return strdup(check_name);
}

char* get_ori_name(PACKAGE* package, STARTUP* startup, char* realy_full_name)
{
	char* root_path = (char*)STARTUP(startup->root_path);
	char* check_name = &realy_full_name[strlen(root_path)];
	char* ori_name = ori_name_mapper(startup, check_name);

	assert(ori_name);

	int index = find_repack_index(package, ori_name);
	return ((index == -1)? NULL : ori_name);
}

int repack_apps(PACKAGE* package, STARTUP* startup)
{
	int error_count = 0;
	long launch_size;
	void* launch_exe = (void*)make_launch(package, &launch_size);

	assert(launch_exe);

	DbgPrint("make launch content succeed: %d\n", launch_size);

	STORE_ITEM* repack_item = (STORE_ITEM*)STARTUP(startup->realy_repack_apps);
	while(repack_item->length)
	{
		char* app_file_name = (char*)STARTUP(*repack_item);
		char* ori_name = get_ori_name(package, startup, app_file_name);

		if (ori_name == NULL)
		{
			DbgPrint("found a error name to pack: %s\n", app_file_name);
			goto repack_continue;
		}

		long output_size;
		void* output_base = (void*)make_repack_app(ori_name, app_file_name, launch_exe, launch_size, &output_size, 0);

		if (output_base == NULL)
		{
			DbgPrint("can't make repack app: %s\n", app_file_name);
			goto repack_continue;
		}

		if (mem_to_file(app_file_name, output_base, output_size) == 0)
		{
			DbgPrint("packer.dll: mem_to_file %s\n", app_file_name);
			error_count++;
		}

		DbgPrint("repack succeed: %s\n", app_file_name);

repack_continue:
		if (ori_name)
			free(ori_name);
		if (output_base)
			free(output_base);
		repack_item++;
	}

	return (error_count);
}

int delete_2_files(STARTUP* startup, long session_counter)
{
	int result = 1;
	char* daemon_file = (char*)STARTUP(startup->daemon_process);
	if (GetFileAttributes(daemon_file) != -1)
	{
		if (DeleteFile(daemon_file))
		{
			DbgPrint("delete daemon.exe succeefully\n");
			unsigned long bsm_apps = BSM_APPLICATIONS;
			BroadcastSystemMessage(BSF_POSTMESSAGE, &bsm_apps, WM_ACTIVATEAPP, 1L, 0L);
		}
		else
		{
			DbgPrint("can't delete daemon.exe[%d]: %s\n", GetLastError(), daemon_file);
			result = 0;
		}
	}

	//只有当最后一个session.dll退出时，才删除session.dll
	if (session_counter < 3)
	{
		if (session_counter == 0)
		{
			DbgPrint("packer.dll: I am the last process containing session.dll\n");
			Sleep(100);
		}

		char* session_file = (char*)STARTUP(startup->session_dll);
		if (GetFileAttributes(session_file) != -1)
		{
			if (DeleteFile(session_file))
			{
				DbgPrint("packer.dll: delete session.dll succeed\n");
			}
			else
			{
				DbgPrint("can't delete[err:%d] session.dll(%d): %s\n", GetLastError(), session_counter, session_file);
				result = 0;
			}
		}
	}

	return (result);
}

DWORD __stdcall repack_routine(void* param)
{
	long session_counter = (long)param;
	HMODULE module = get_module_base();
	DbgPrint("packer.dll: repack routine running [time tick: %d][tofree: %x]\n", GetTickCount(), module);

	PACKAGE* package = __package__;
	STARTUP* startup = __startup__;

	assert(package);
	assert(startup);

	//获取互斥体，得到独占的处理权限
	HANDLE mutex = enter_mutex_process_wait(key_mutex);

	DbgPrint("packer.dll: enter mutex [%d]\n", GetTickCount());

	if (mutex)
	{
		//对repack程序逐个打包
		if (repack_apps(package, startup))
		{
			DbgPrint("not all repack app succeed!\n");
		}

		//尝试删除daemon.exe和session.dll
		delete_2_files(startup, session_counter);

		leave_mutex_process(mutex);
	}

	__FreeLibrary(NULL, module, NULL);
}

__declspec(dllexport) void on_daemon_exit(long session_counter, int async_thread)
{
	if (async_thread)
	{
		DWORD tid;
		HANDLE pack_thread = CreateThread(NULL, 0, repack_routine, (void*)session_counter, 0, &tid);
		if (pack_thread == NULL)
		{
			DbgPrint("packer.dll: process exit? I can't create thread [%d]\n", GetLastError());
		} 
		else
		{
			CloseHandle(pack_thread);
		}
	}
	else
	{
		repack_routine((void*)session_counter);
	}
}

char* daemon_msg_name = NULL;

BOOL WINAPI DllMain (HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
	switch(fdwReason) 
	{ 
		case DLL_PROCESS_ATTACH: 
			daemon_msg_name = enable_reporter(lpReserved);
			DbgPrint("packer.dll(%x) started in: %s\n", hinstDll, current_process_name());
			packer_init(lpReserved);
			break;
		case DLL_PROCESS_DETACH: 
			DbgPrint("packer.dll(%x) finished in: %s\n", hinstDll, current_process_name());
			disable_reporter(daemon_msg_name);
			break;
	}
	return (TRUE);
}
