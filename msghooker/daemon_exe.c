#include <windows.h>
#include <time.h>
#include <stdio.h>
#include <assert.h>
#include "global.h"
#include "message_comm.h"

char* replace_filename_in_cmdline(char* command_line, char* file_name, char* replace_name)
{
	long found_index = -1;
	long file_len = strlen(file_name);
	long cmd_len = strlen(command_line);

	if (file_len == cmd_len)
	{
		return strdup(command_line);
	}

	if (strncasecmp(command_line, file_name, file_len) == 0)
	{
		found_index = 0;
	}
	else if (strncasecmp(&command_line[1], file_name, file_len) == 0)
	{
		found_index = 1;
	}

	if (found_index == -1)
	{
		return strdup(command_line);
	}

	long replace_index = found_index + file_len;
	char* tail = &command_line[replace_index];

	char result[MAX_PATH];
	sprintf(result, "%s%s%s", (found_index == 0)?NULL:"\"", replace_name, tail);
	DbgPrint("make cmdline: %s", result);

	return strdup(result);
}


DWORD new_winapp(char* command_line, char* file_name)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	int run_succeed = 0;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(STARTUPINFO);

	char* file_path = strdup(file_name);
	char* null_set = seek_short_file_name(file_path);
	null_set[0] = '\0';

	if (!is_32bit_pefile(file_name))
	{
		DbgPrint("we can't handle 64bit applications:%s", file_name);
		return (0);
	}

	if (CreateProcess(NULL, command_line, NULL, NULL, FALSE, 0, NULL, file_path, &si, &pi))
	{
		return (pi.dwProcessId);
	}

	return (0);
}

void wait_terminat_process(DWORD pid, DWORD time_out, int times)
{
	HANDLE stub_handle;
	if (stub_handle = OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE, FALSE, pid))
	{
		do
		{
			if (WaitForSingleObject(stub_handle, time_out) == WAIT_OBJECT_0)
			{
				DbgPrint("stub.exe terminated: %d", pid);
				break;
			}
			else
			{
				if (!TerminateProcess(stub_handle, 0))
				{
					DbgPrint("TerminateProcess error: %d", pid);
				}
			}
		} while (--times);

		CloseHandle(stub_handle); 
	}
	else
	{
		DbgPrint("OpenProcess error: %d last_err: %d", pid, GetLastError());
	}	
}

int debug_msg_cb(void* msg_data, int msg_size)
{
	time_t t;
	time(&t);
	struct tm* ptime = localtime(&t);

	char* dbg_msg_buff = (char*)msg_data;

	while (dbg_msg_buff[msg_size] == 0)
	{
		msg_size--;
	}

	if (dbg_msg_buff[msg_size] != '\n')
	{
		dbg_msg_buff[++msg_size] = '\n';
		dbg_msg_buff[++msg_size] = 0;
	}

	printf("[%d:%d:%d]: %s", ptime->tm_hour, ptime->tm_min, ptime->tm_sec, msg_data);
}

void dbg_msg(const char* format, ...)
{       
	static char dbg_msg_buff[0x1000]; 
        if (format)
        {
                va_list args;
                va_start(args, format);
                int len = wvsprintfA(dbg_msg_buff, format, args);
                va_end(args);

                debug_msg_cb(dbg_msg_buff, len+1);
        }
}

void resizeConBufAndWindow(HANDLE hConsole, SHORT xSize, SHORT yWinSize, SHORT yBufSize)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi; /* hold current console buffer info */
	BOOL bSuccess;
	SMALL_RECT srWindowRect; /* hold the new console size */
	COORD coordScreen;

	bSuccess = GetConsoleScreenBufferInfo(hConsole, &csbi);
	/* get the largest size we can size the console window to */
	coordScreen = GetLargestConsoleWindowSize(hConsole);

	/* define the new console window size and scroll position */
	srWindowRect.Right = (SHORT) (min(xSize, coordScreen.X) - 1);
	srWindowRect.Bottom = (SHORT) (min(yWinSize, coordScreen.Y) - 1);
	srWindowRect.Left = srWindowRect.Top = (SHORT) 0;

	/* define the new console buffer size */
	coordScreen.X = xSize;
	coordScreen.Y = yBufSize;

	/* if the current buffer is larger than what we want, resize the */
	/* console window first, then the buffer */
	if ((DWORD) csbi.dwSize.X * csbi.dwSize.Y > (DWORD) xSize * yWinSize)
	{
		bSuccess = SetConsoleWindowInfo(hConsole, TRUE, &srWindowRect);
		bSuccess = SetConsoleScreenBufferSize(hConsole, coordScreen);
	}

	/* if the current buffer is smaller than what we want, resize the */
	/* buffer first, then the console window */
	if ((DWORD) csbi.dwSize.X * csbi.dwSize.Y < (DWORD) xSize * yWinSize)
	{
		bSuccess = SetConsoleScreenBufferSize(hConsole, coordScreen);
		bSuccess = SetConsoleWindowInfo(hConsole, TRUE, &srWindowRect);
	}
	/* if the current buffer *is* the size we want, don't do anything! */
	return;
}

HMODULE session_dll;

typedef int (__stdcall *lpfn_set_hook)();
typedef int (__stdcall *lpfn_cls_hook)();
typedef const char** (__stdcall *lpfn_get_parameters)(HINSTANCE image, const char* catelog_name);
typedef const char** (__stdcall *lpfn_get_parameter)(HINSTANCE image, const char* catelog_name, const char* key_name);
typedef PACKAGE* (__stdcall *lpfn_get_package)();
typedef STARTUP* (__stdcall *lpfn_get_startup)();

lpfn_set_hook set_hook;
lpfn_cls_hook cls_hook;
lpfn_get_parameters get_parameters;
lpfn_get_parameter  get_parameter;
lpfn_get_package get_package;
lpfn_get_startup get_startup;

int init_system_functions()
{
	session_dll = LoadLibraryA(SESSION_DLL_NAME);
	if (session_dll == NULL)
	{
		dbg_msg("daemon.exe LoadLibrary error\n");
		return (0);
	}

	//获取系统函数
	set_hook = (lpfn_set_hook)GetProcAddress(session_dll, "set_hook@0");
	cls_hook = (lpfn_cls_hook)GetProcAddress(session_dll, "cls_hook@0");
	get_parameters = (lpfn_get_parameters)GetProcAddress(session_dll, "get_parameters@8");
	get_parameter  = (lpfn_get_parameter)GetProcAddress(session_dll, "get_parameter@12");
	get_package = (lpfn_get_package)GetProcAddress(session_dll, "get_package@0");
	get_startup = (lpfn_get_startup)GetProcAddress(session_dll, "get_startup@0");

	if ((set_hook == NULL) || 
		(cls_hook == NULL) ||
		(get_parameters == NULL) ||
		(get_parameter == NULL) ||
		(get_package == NULL) ||
		(get_startup == NULL)
		)
	{
		return (0);
	}

	return (1);
}

const char* get_sysparam_valstr(const char* key, char* default_val)
{
	if (get_parameter == NULL)
	{
		dbg_msg("oh, key function \"get_parameter\" is NULL(%s,%s)\n", key, default_val);
		return (NULL);
	}
	const char** sysparam_s = get_parameter(NULL, "system", key);
	return (sysparam_s)? sysparam_s[1] : default_val;
}

int get_sysparam_valint(const char* key, int default_val)
{
	const char* param_str = get_sysparam_valstr(key, NULL);
	return (param_str)? atoi(param_str) : default_val;
}

int main(void)
{
	dbg_msg("<------- daemon.exe start ------->\n");

	if (is_mutex_process())
	{
		dbg_msg("daemon.exe already exists\n");
		return (EXIT_FAILURE);
	}

	dbg_msg("daemon.exe has mutex\n");

	if (!init_system_functions())
	{
		dbg_msg("init_system_functions == error\n");
		return (EXIT_FAILURE);
	}

	dbg_msg("initial session.dll's functions succeed.");

	int time_out = get_sysparam_valint("daemon_wait_stub_timeout", DAEMON_WAIT_TIMEOUT);
	int times = get_sysparam_valint("daemon_wait_stub_times", 2);
	int win_x = get_sysparam_valint("daemon_windows_x", 120);
	int win_y = get_sysparam_valint("daemon_windows_y", 100);
	int buf_y = get_sysparam_valint("daemon_buffer_y", 500);

	resizeConBufAndWindow(GetStdHandle(STD_OUTPUT_HANDLE), win_x, win_y, buf_y);

	//取出启动参数
	PACKAGE* package = get_package();
	STARTUP* startup = get_startup();

	assert(package);
	assert(startup);

	//等待stub.exe的退出
	dbg_msg("stub_process_id: %d\n", startup->stub_process_id);
	DWORD begin_tick = GetTickCount();
	wait_terminat_process(startup->stub_process_id, time_out, times);  
	dbg_msg("wait stub.exe time: %d\n", GetTickCount() - begin_tick);

	if (!set_hook())
	{
		dbg_msg("set_hook() error!\n");
		return (EXIT_FAILURE);
	}


	//还原所有repack打包的程序为原来未打包状态
	char* root_path = (char*)STARTUP(startup->root_path);
	char* ori_cmdline = (char*)STARTUP(startup->stub_command_line);
	char* stub_exe = (char*)STARTUP(startup->stub_process_name);
	char* msg_name = (char*)STARTUP(startup->daemon_dbg_name);

	if (startup->realy_repack_apps.length)
	{
		STORE_ITEM* item = (STORE_ITEM*)STARTUP(startup->realy_repack_apps);
		for (; item->length; item++)
		{
			char* to_unpack_file = (char*)STARTUP(*item);
			dbg_msg("repack file: %s\n", to_unpack_file);

			if (GetFileAttributes(to_unpack_file) == -1)
			{
				continue;
			}

			if (section_to_file(to_unpack_file, ORIGIN_APP_SECTION_NAME, to_unpack_file) == 0)
			{
				dbg_msg("section_to_file error: %s\n", to_unpack_file);
			}
		}
	}

	//启动新进程
	char file_name[MAX_PATH];
	char* new_cmdline = NULL;
	if (startup->stub_is_launch)
	{
		char* launch_file = (char*)PACKAGE(package->launch_exe);
		sprintf(file_name, "%s%s", root_path, launch_file);
		dbg_msg("launch aim: %s\n", file_name);

		new_cmdline = replace_filename_in_cmdline(ori_cmdline, stub_exe, file_name);
		new_winapp(new_cmdline, file_name);
		free(new_cmdline);
	}
	else
	{
		dbg_msg("exec cmdline: %s\n", ori_cmdline);
		new_winapp(ori_cmdline, stub_exe);
	}

	//消息循环
	int cellsize = get_sysparam_valint("daemon_msg_cellsize", MAX_PATH);
	short cellcount = (short)get_sysparam_valint("daemon_msg_cellcount", 128);
	short waitcount = (short)get_sysparam_valint("daemon_msg_waitcount", 1024);
	DWORD timeout = (DWORD)get_sysparam_valint("daemon_msg_timeout", 10*1000);	

	dbg_msg("start message loop, cellsize:%d, cellcount:%d, timeout:%d\n", cellsize, cellcount, timeout);

	thread_msg_event(daemon_message_debug, debug_msg_cb);
	thread_msg_looper(msg_name, cellsize, cellcount, waitcount, timeout);

	//取消全局钩子， 将触发对repack程序的从新打包
	if (!cls_hook())
	{
		OutputDebugStringA("cls_hook() error!\n");
	}
	FreeLibrary(session_dll);

	OutputDebugStringA("daemon process terminate!\n");
	return (EXIT_SUCCESS);
}
