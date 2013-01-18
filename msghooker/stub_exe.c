/*
   引导程序的任务：
   1）释放daemon.exe和session.dll，将package塞入session.dll中，用作全session传递。
   2）填写runtime参数，并作为节段塞入session.dll中，指明下一步应该启动的程序。
   3）启动daemon.exe
*/
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <tlhelp32.h>
#include "list.h"
#include "global.h"
#include "message_comm.h"
#include "package.h"
#include "dll_in_section.h"
#include "xml_in_section.h"

DWORD new_console(char* file_name, int show_window, int show_maximized)
{
	PROCESS_INFORMATION pi;
	STARTUPINFO   si;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(STARTUPINFO);

	if (show_window)
	{
		si.wShowWindow = show_maximized? SW_SHOWMAXIMIZED : SW_SHOWNORMAL;    
	}
	else
	{
		si.wShowWindow = SW_HIDE;    
	}
	si.dwFlags=STARTF_USESHOWWINDOW;    

	int run_succeed = 0;
	char* file_path = strdup(file_name);
	char* null_set = seek_short_file_name(file_path);
	null_set[0] = '\0';

	if (CreateProcess(NULL, file_name, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, file_path, &si, &pi))
	{
		return (pi.dwProcessId);
	}
	return (0);
}


char* whoiam_realy_fullname(char* realy_me_name, char* current_fullname)
{
	//获取本地路径名称
	char* name_buff = strdup(current_fullname);
	char* null_char = seek_short_file_name(name_buff);
	null_char[0] = '\0';

	//获取“原始”相对文件名
	char* tmp_realy_me_name = strdup(realy_me_name);
	char* launch_short_name = seek_short_file_name(tmp_realy_me_name);

	//获取root路径
	char run_aim_exe[MAX_PATH];
	sprintf(run_aim_exe, "%s%s", name_buff, launch_short_name);

	free(name_buff);
	free(tmp_realy_me_name);
	return strdup(run_aim_exe);
}

/*
int is_right_directory(char* defined_fullname, char* current_fullname, int is_launch)
{
	if (GetFileAttributes(realy_me_fullname) == -1)
	{
		MessageBoxA(0,"please place this exe to correct directory!","directory error 1!",MB_OK | MB_ICONERROR);
		goto error_exit;
	}

	int realy_full_len = strlen(realy_me_fullname);
	int realy_mename_len = strlen(realy_me_name);
	if (strcasecmp(&realy_me_fullname[realy_full_len - realy_mename_len], realy_me_name) != 0)
	{
		char info_buf[MAX_PATH];
		const char *title = "please place this exe to correct directory!";
		sprintf(info_buf, "%s\n%s\n%s", title, &realy_me_fullname[realy_mename_len], realy_me_name);
		MessageBoxA(0, info_buf,"directory error 2!",MB_OK | MB_ICONERROR);
		goto error_exit;
	}
}
*/
typedef int (*lpfn_search_cb)(char* path, char* filename, void* param);

void search_file(char* search_path, const char* search_for, lpfn_search_cb cb, void* param)
{
	WIN32_FIND_DATA FindData;

	char search_str[MAX_PATH];
	sprintf(search_str, "%s*.*", search_path);

	HANDLE find_handle = FindFirstFile(search_str, &FindData);
	if (find_handle == INVALID_HANDLE_VALUE)
		return;

	do
	{
		//DbgPrint("search: %s", FindData.cFileName);

		if ((strcmp(FindData.cFileName, ".") == 0) || (strcmp(FindData.cFileName, "..") == 0))
			continue;

		if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			char sub_search_path[MAX_PATH];
			sprintf(sub_search_path, "%s%s\\", search_path, FindData.cFileName);
			//DbgPrint("sub dir: %s", sub_search_path);
			search_file(sub_search_path, search_for, cb, param);
		}
		else
		{
			int len = strlen(FindData.cFileName);
			int len_s = strlen(search_for);
			if (len > len_s)
			{
				if (stricmp(&FindData.cFileName[len-len_s], search_for) == 0)
				{
					DbgPrint("check: %s%s", search_path, FindData.cFileName);
					if (0 == cb(search_path, FindData.cFileName, param))
						break;
				}
			}
		}
	} while (FindNextFile(find_handle, &FindData));

	FindClose(find_handle);
}

List get_store_item_list(char* root_dir, PACKAGE* package, STORE_ITEM dir_root)
{
	List ret_list = MakeEmptyLst(NULL);
	Position pos = Header(ret_list);
	char full_file_name[MAX_PATH];

	if (dir_root.length)
	{
		STORE_ITEM* array_item = (STORE_ITEM*)PACKAGE(dir_root);

		while (array_item->length)
		{
			char* file_name = (char*)PACKAGE(*array_item);
			sprintf(full_file_name, "%s%s", root_dir, file_name);

			char* add_to_list = strdup(full_file_name);
			Insert((ElementType)add_to_list, ret_list, pos);
			pos = Advance(pos);

			DbgPrint("[make list] filename: %s", full_file_name);
			array_item++;
		}
	}
	return (ret_list);
}

Position is_string_in_list(char* input_str, List list)
{
	Position pos = Header(list);

	if( IsEmptyLst(list) )
	{
		printf("Empty list\n");
		return (NULL);
	}
	else
	{
		do
		{
			pos = Advance( pos );
			ElementType item_val = Retrieve(pos);
			char* item_str = (char*)item_val;

			if (stricmp(item_str, input_str) == 0)
			{
				return (pos);
			}
		} while(!IsLast(pos, list) );
	}
	return (NULL);
}

Position add_string_to_list(char* input_str, List list)
{
	if (is_string_in_list(input_str, list))
	{
		return (NULL);
	}

	input_str = strdup(input_str);
	Position head = Header(list);
	Insert((ElementType)input_str, list, head);
	return (head);
}

#define read_file_size 0x1000

int search_exe_cb(char* path, char* filename, void* param)
{
	SEARCH_PARAM* search_param = (SEARCH_PARAM*)param;
	List repack_list = search_param->repack_list;
	List plugto_list = search_param->plugto_list;
	List map_list = search_param->map_list;
	char* root_dir = search_param->root_dir;

	char real_file[MAX_PATH];
	char check_file[MAX_PATH];
	char map_item[MAX_PATH];
	sprintf(check_file, "%s%s", path, filename);

	void* file_base = NULL;
	void* fullfile = NULL;
	long file_size;
	int has_app_section;
	PACKAGE* package;

	do
	{
		//重重过滤，筛选出需要repack的文件
		if (GetFileAttributes(check_file) == -1) break;
		if ((file_base = mem_from_file_raw(check_file, &file_size, read_file_size, 0)) == NULL) break;
		if (file_size != read_file_size) break;
		if ((has_app_section = is_section_exists(file_base, ORIGIN_APP_SECTION_NAME)) == 0) break;
		DbgPrint("has_app_section: %s", check_file);
		if ((fullfile = mem_from_file(check_file, &file_size, 0)) == NULL) break;
		if ((package = get_section_raw(fullfile, PACKAGE_SECTION_NAME)) == NULL) break;
		DbgPrint("has_package: %s", check_file);

		//将真名取出来
		char* realy_name = whoiam_realy_name(package);
		sprintf(real_file, "%s%s", root_dir, realy_name);
		DbgPrint("has_alais: %s", real_file);

		//检查是不是别名
		if (stricmp(check_file, real_file) == 0) break;

		//记录在map_list中
		//格式是 别名:真名
		sprintf(map_item, "%s:%s", filename, realy_name);
		add_string_to_list(map_item, map_list);

		//如果是别名，需要检查并添加到2个列表中
		Position found;
		if (found = is_string_in_list(real_file, repack_list))
		{
			add_string_to_list(check_file, repack_list);
		}

		if (found = is_string_in_list(real_file, plugto_list))
		{
			add_string_to_list(check_file, plugto_list);
		}

	} while (FALSE);

	if (file_base)
		free(file_base);
	if (fullfile)
		free(fullfile);

	return (1);
}

char* find_root_path(char* realy_me_name, char* realy_fullname)
{
	char* run_aim_exe = strdup(realy_fullname);
	
	int del_len = strlen(realy_me_name);
	int total_len = strlen(run_aim_exe);

	if (strcasecmp(&run_aim_exe[total_len- del_len], realy_me_name) == 0)
	{
		run_aim_exe[total_len - del_len] = '\0';
		return (run_aim_exe);
	}
	return (NULL);
}

DWORD is_session_dll_running(char* root_dir)
{
	char session_dll_name[MAX_PATH];
	sprintf(session_dll_name, "%s%s", root_dir, DAEMON_EXE_NAME);

	DWORD dwRet = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);

	if ( hSnapshot != INVALID_HANDLE_VALUE )
	{
		MODULEENTRY32 pe32;
		pe32.dwSize = sizeof( MODULEENTRY32 );
		Module32First( hSnapshot, &pe32 );
		do
		{
			if (stricmp(pe32.szExePath, session_dll_name) == 0)
			{
				dwRet =(DWORD)pe32.hModule;
				break;
			}
		} while ( Module32Next( hSnapshot, &pe32 ) );
		CloseHandle( hSnapshot );

	}
	return dwRet;
}

char* error_cleanup_scene(char* root_dir)
{
	if (is_session_dll_running(root_dir))
	{
		DbgPrint("fatal error of application flow: session.dll exists!");
		return strdup("session.dll is running.");
	}

	//必须先确认2个守护程序的删除
	char pefile_to_delete[MAX_PATH];
	sprintf(pefile_to_delete, "%s%s", root_dir, DAEMON_EXE_NAME);
	if (GetFileAttributes(pefile_to_delete) != -1)
	{
		if (!DeleteFile(pefile_to_delete))
		{
			DbgPrint("[stub]<<<warning>>> can't delete %s (%d)", pefile_to_delete, GetLastError());
		}
	}
	
	//删除session.dll
	sprintf(pefile_to_delete, "%s%s", root_dir, SESSION_DLL_NAME);
	if (GetFileAttributes(pefile_to_delete) != -1)
	{
		if (!DeleteFile(pefile_to_delete))
		{
			DbgPrint("[stub]<<<warning>>> can't delete %s (%d)", pefile_to_delete, GetLastError());
		}
	}

	return (NULL);
}

int main(void)
{
	DbgPrint("<------- stub.exe start ------->");

	HANDLE mutex = enter_mutex_process(key_mutex);
	if (mutex == NULL)
	{
		DbgPrint("please run stub.exe one by one.");
		MessageBoxA(0, "please run stub.exe one by one.","run flow error!",MB_OK | MB_ICONERROR);
		goto error_exit;
	}


	PACKAGE* package = get_package_section_me();
	assert(package);

	//取必要的目录数据
	char* current_fullname = current_process_name();
	char* realy_me_name = whoiam_realy_name(package); 
	char* realy_me_fullname = whoiam_realy_fullname(realy_me_name, current_fullname);
	int is_launch_exe = (is_section_exists_main(ORIGIN_APP_SECTION_NAME))? 0 : 1;

	assert(realy_me_name);
	DbgPrint("[stub] my name: %s", current_fullname);
	DbgPrint("[stub] who am i: %s [%s]", realy_me_name, is_launch_exe?"launch":"packed");
	DbgPrint("[stub] realy my name: %s", realy_me_fullname);

	char* root_dir;
	if ((root_dir = find_root_path(realy_me_name, realy_me_fullname)) == NULL)
	{
		char info_buf[MAX_PATH];
		const char *title = "please place this exe to correct directory!";
		sprintf(info_buf, "%s\n%s\n%s", title, realy_me_fullname, realy_me_name);
		MessageBoxA(0, info_buf,"directory error 2!",MB_OK | MB_ICONERROR);
		goto error_exit;
	}

	DbgPrint("[stub] root path: %s", root_dir);

	char* error_message;
	if (error_message = error_cleanup_scene(root_dir))
	{
		MessageBoxA(0, error_message, "fatal error!",MB_OK | MB_ICONERROR);
		free(error_message);
		goto error_exit;
	}

	//采集和分析程序目录，适应程序的变化
	List repack_list = get_store_item_list(root_dir, package, package->repack_app_dir);
	List plugto_list = get_store_item_list(root_dir, package, package->plugin_app_dir);
	SEARCH_PARAM search_param;
	search_param.repack_list = repack_list;
	search_param.plugto_list = plugto_list;
	search_param.map_list = MakeEmptyLst(NULL);
	search_param.root_dir = root_dir;

	search_file(root_dir, ".exe", search_exe_cb, &search_param);
	assert(!IsEmptyLst(plugto_list));

	char* new_daemon_to_run;
	if ((new_daemon_to_run = stub_make_session_apps(package, &search_param)) == NULL)
	{
		DbgPrint("[stub]<<<warning>>>  can't make daemon.exe");
		goto error_exit;
	}

	//读取系统运行参数
	void* session_dll = (void*)PACKAGE(package->session_dll);
	const char* xmlstr = file_to_xmlstr(session_dll, PLUGIN_PARAM_SECTION);
	DbgPrint("system parameter:\n%s", xmlstr);

	const char** param_str = get_keyvalue(xmlstr, "system", "daemon_show_console");
	int show_daemon = 0;
	if (param_str)
	{
		if (!stricmp(param_str[1], "true"))
		{
			show_daemon = 1;
		}
	}

	const char** param_strb = get_keyvalue(xmlstr, "system", "daemon_show_maximized");
	int show_maximized = 0;
	if (param_strb)
	{
		if (!stricmp(param_strb[1], "true"))
		{
			show_maximized = 1;
		}
	}

	DbgPrint("create daemon console: show(%d), max(%d)", show_daemon, show_maximized);
	new_console(new_daemon_to_run, show_daemon, show_maximized);

	leave_mutex_process(mutex);
	return (EXIT_SUCCESS);

error_exit:
	leave_mutex_process(mutex);
	return (EXIT_FAILURE);
}
