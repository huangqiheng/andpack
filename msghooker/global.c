#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include "global.h"
#include "message_comm.h"

static unsigned int crc_table[256];
int crc_table_init = 0;

/* 
 **初始化crc表,生成32位大小的crc表 
 **也可以直接定义出crc表,直接查表, 
 **但总共有256个,看着眼花,用生成的比较方便. 
 */  
static void init_crc_table(void)  
{  
	unsigned int c;  
	unsigned int i, j;  

	for (i = 0; i < 256; i++) {  
		c = (unsigned int)i;  
		for (j = 0; j < 8; j++) {  
			if (c & 1)  
				c = 0xedb88320L ^ (c >> 1);  
			else  
				c = c >> 1;  
		}  
		crc_table[i] = c;  
	}  
}  

/*计算buffer的crc校验码*/  
unsigned int crc32(unsigned int crc,unsigned char *buffer, unsigned int size)  
{  
	if (crc_table_init == 0)
	{
		init_crc_table();
		crc_table_init = 1;
	}

	unsigned int i;  
	for (i = 0; i < size; i++) {  
		crc = crc_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);  
	}  
	return crc ;  
} 

DWORD enum_parent_pid(HANDLE snap_handle)
{
	DWORD dwpid = GetCurrentProcessId();
	PROCESSENTRY32 pe32;
	memset( &pe32, 0, sizeof(pe32) );
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if( Process32First(snap_handle, &pe32) )
	{
		do {
			if( pe32.th32ProcessID == dwpid )
			{
				return (pe32.th32ParentProcessID);
			}
		} while(Process32Next(snap_handle, &pe32));
	}
	return (0);
}

DWORD enum_pid_exists(HANDLE snap_handle, DWORD pid)
{
	if (pid)
	{
		PROCESSENTRY32 pe32;
		memset( &pe32, 0, sizeof(pe32) );
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if(Process32First(snap_handle, &pe32))
		{
			do 
			{
				if( pe32.th32ProcessID == pid)
				{
					return (pe32.th32ProcessID);
				}
			} while(Process32Next(snap_handle, &pe32));
		}
	}
	return (0);
}

DWORD get_parent_process_id()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) 
		return 0;

	DWORD ppid = enum_parent_pid(hSnap);
	DWORD is_exists = enum_pid_exists(hSnap, ppid);
	
	CloseHandle(hSnap);
	return (is_exists)? ppid : 0;
}

typedef 
DWORD (WINAPI *GETMODULEFILENAMEEX)(
		HANDLE hProcess,
		HMODULE hModule,
		LPTSTR lpFilename,
		DWORD nSize
		);

char* GetProcessName(DWORD PID)
{

	HMODULE lib=LoadLibrary("Psapi.dll");
	GETMODULEFILENAMEEX GetModuleFileNameEx=(GETMODULEFILENAMEEX)GetProcAddress(lib,"GetModuleFileNameExA");

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,PID);

	if (hProcess == NULL) 
	{
		DbgPrint("id_to_name: OpenProcess failure [%d]", GetLastError());
		return NULL;
	}

	char szProcessName[MAX_PATH];
	if (GetModuleFileNameEx(hProcess,(HMODULE)0, szProcessName, MAX_PATH) == 0) 
	{
		CloseHandle(hProcess);
		return NULL;
	}

	CloseHandle(hProcess);
	return (strdup(szProcessName));
}


char* pid_to_exepath(DWORD pid)
{ 
	HANDLE hSnapShot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid); 

	if (hSnapShot == INVALID_HANDLE_VALUE) 
	{
		DbgPrint("pid_to_exepath error = %d", GetLastError());
		return (NULL);
	}

	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnapShot, &me))
	{
		CloseHandle(hSnapShot);
		return strdup(me.szExePath);
	}

	CloseHandle(hSnapShot);
	return (NULL);
}

int kill_process(DWORD pid)
{
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE,FALSE, pid);
	int run_result = TerminateProcess(hProcess,0);
	CloseHandle(hProcess);
	return (run_result);
}

typedef int (*lpfn_process_cb)(void* sender, int* stop, DWORD pid, DWORD parent_pid);

int find_process_to_handle(char* full_process_name, lpfn_process_cb handle_cb, void* sender)
{
	int run_result = 0;
	HANDLE snap_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap_handle == INVALID_HANDLE_VALUE) 
		return (run_result);

	PROCESSENTRY32 pe32;
	memset( &pe32, 0, sizeof(pe32) );
	pe32.dwSize = sizeof(PROCESSENTRY32);

	char* target_name = seek_short_file_name(full_process_name);
	char* check_name;
	int stop = 0;

	if( Process32First(snap_handle, &pe32) )
	{
		do {
			//检查短文件名是否相同
			if (stricmp(pe32.szExeFile, target_name) != 0)
			{
				continue;
			}

			//获取长文件名
			check_name = pid_to_exepath(pe32.th32ProcessID);

			DbgPrint("check[%d]: %s == %s", pe32.th32ProcessID, check_name, full_process_name);

			if (check_name == NULL)
			{
				continue;
			}

			//检查长文件名是否相同
			if (stricmp(check_name, full_process_name) == 0)
			{
				if (handle_cb(sender, &stop, pe32.th32ProcessID, pe32.th32ParentProcessID))
				{
					run_result++;
				}

				if (stop)
				{
					break;
				}
			}
			free(check_name);
		} while(Process32Next(snap_handle, &pe32));
	}

	CloseHandle(snap_handle);
	return (run_result);
}

int kill_process_cb(void* sender, int* stop, DWORD pid, DWORD parent_pid)
{
	return kill_process(pid);
}

int kill_process_byname(char* full_process_name)
{
	return find_process_to_handle(full_process_name, kill_process_cb, NULL);
}

int is_process_exists(DWORD pid)
{
	HANDLE ps_handle = OpenProcess(PROCESS_QUERY_INFORMATION , FALSE, pid);

	if (ps_handle)
	{
		DWORD exit_code = 0;
		if (GetExitCodeProcess(ps_handle, &exit_code))
		{
			if (exit_code == STILL_ACTIVE)
			{
				CloseHandle(ps_handle);
				return (1);
			}
		}
		else
		{
			DbgPrint("is_process_exists GetExitCodeProcess error: %d", pid);
		}

		CloseHandle(ps_handle);
	}
	else
	{
		DbgPrint("is_process_exists OpenProcess error: %d", pid);
	}


	return (0);
}

int is_patern_string(const char* str_a, const char* str_b)
{
	int result = 0;
	int len_a = strlen(str_a);
	int len_b = strlen(str_b);

	if (len_a != len_b)
	{
		return (result);
	}

	char* stra = strdup(str_a);
	char* strb = strdup(str_b);

	int i;
	for (i=0; i<len_a; i++)
	{
		if (stra[i] == '?')
		{
			stra[i] = '-';
			strb[i] = '-';
		}

		if (strb[i] == '?')
		{
			stra[i] = '-';
			strb[i] = '-';
		}
	}

	if (!stricmp(stra, strb))
	{
		result = 1;
	}

	free(stra);
	free(strb);
	return (result);
}

int is_itemdir_strlist(char* target_string, STARTUP* startup, STORE_ITEM* item_dir)
{
	if (item_dir->length == 0)
	{
		return (0);
	}

	STORE_ITEM* item_list = (STORE_ITEM*)STARTUP(*item_dir);

	if (item_list->length == 0)
	{
		return (0);
	}

	char* to_cmp;

	do
	{
		//取出被对比的字符串
		to_cmp = (char*)STARTUP(*item_list);

		//分离“目录名”和“文件名”
		char* cmp_path = strdup(to_cmp);
		char* null = seek_short_file_name(cmp_path);
		char* cmp_short = strdup(null);
		null[0] = '\0';

		char* target_path = strdup(target_string);
		null = seek_short_file_name(target_path);
		char* target_short = strdup(null);
		null[0] = '\0';

		//如果目录都不相同，就不用对比了
		if (stricmp(cmp_path, target_path))
		{
			free(cmp_path);
			free(cmp_short);
			free(target_path);
			free(target_short);
			continue;
		}

		//用不着了，释放它
		free(cmp_path);
		free(target_path);

		int is_done = 0;
		do
		{
			//如果全名对比相同，则被匹配
			if (!stricmp(cmp_short, target_short))
			{
				is_done = 1;
				break;
			}

			//如果是*.*，也被匹配
			if (!stricmp(cmp_short, "*.*"))
			{
				is_done = 1;
				break;
			}

			//进一步拆分文件名和后缀
			int dot_index;
			char* cmp_ext = find_ext_dot(cmp_short, &dot_index);
			if (cmp_ext)
			{
				cmp_ext[0] = '\0';
				cmp_ext++;
			}

			char* target_ext = find_ext_dot(target_short, &dot_index);
			if (target_ext)
			{
				target_ext[0] = '\0';
				target_ext++;
			}

			if ((cmp_ext == NULL) && (target_ext != NULL))
			{
				break;
			}

			if (cmp_short[0] == '*')
			{
				if (is_patern_string(cmp_ext, target_ext))
				{
					is_done = 1;
					break;
				}
			}

			if (cmp_ext[0] == '*')
			{
				if (is_patern_string(cmp_short, target_short))
				{
					is_done = 1;
					break;
				}
			}

		} while (0);

		free(cmp_short);
		free(target_short);

		if (is_done)
		{
			return (1);
		}

	} while((++item_list)->length);

	return (0);
}

int is_repack_process(STARTUP* startup)
{
	char* target_process = current_process_name();
	return is_itemdir_strlist(target_process, startup, &startup->realy_repack_apps);
}

int is_plugin_process(STARTUP* startup)
{
	char* target_process = current_process_name();
	if (target_process == NULL)
	{
		DbgPrint("can't get process name (%d)", GetLastError());
		return (0);
	}

	char* root_path = (char*)STARTUP(startup->root_path);
	int root_len = strlen(root_path);

	if (!stricmp(&target_process[root_len], DAEMON_EXE_NAME))
	{
		DbgPrint("this is daemon.exe");
		free(target_process);
		return (0);
	}

	return is_itemdir_strlist(target_process, startup, &startup->realy_plugin_apps);
}

static char* except_list[] = {
	"DbgView.exe",
	"DebugTrack.exe"
};

int am_i_debuger = -1;

int is_debuger_process()
{
	if (am_i_debuger == -1)
	{
		char* process_name = seek_short_file_name(current_process_name());
		int process_name_len = strlen(process_name);
		int target_name_len;
		char* target_name;
		int i;
		int len = sizeof(except_list) / sizeof(char*);
		int run_result = 0;

		for (i=0; i<len; i++)
		{
			target_name = except_list[i];
			target_name_len = strlen(target_name);

			if (process_name_len == target_name_len)
			{
				if (stricmp(target_name, process_name) == 0)
				{
					run_result = 1;
					break;
				}
			}
		}
		am_i_debuger = run_result;
	}
	return (am_i_debuger);
}

int get_pid_cb(void* sender, int* stop, DWORD pid, DWORD parent_pid)
{
	DbgPrint("get_pid_cb: %d, parent: %d", pid, parent_pid);

	if (is_process_exists(pid))
	{
		DWORD* pid_out = (DWORD*)sender;
		*pid_out = pid;
		*stop = 1; //可以终止例程，直接返回结果
		return (1); //返回TRUE，表示完成任务
	}
	return (0); //未找到活的进程，不算
}

DWORD get_process_alive_id(char* full_process_name)
{
	DWORD pid;
	if (find_process_to_handle(full_process_name, get_pid_cb, &pid))
	{
		return (pid);
	}
	return (0);
}

char* daemon_server_name = NULL;

char* set_msg_reporter(char* msg_name)
{
	char* old = daemon_server_name;
	daemon_server_name = (msg_name)? strdup(msg_name) : NULL;

	if (old)
	{
		free(old);
	}

	return (daemon_server_name);
}

char* enable_reporter(HINSTANCE session_dll)
{
	if (session_dll)
	{
		STARTUP* startup = (STARTUP*)get_section(session_dll, STUB_START_SECTION_NAME);
		char* msg_name = (char*)STARTUP(startup->daemon_dbg_name);
		OutputDebugStringA(msg_name);
		return (set_msg_reporter(msg_name));
	}
	return (NULL);
}

void disable_reporter(char* msg_name)
{
	set_msg_reporter(NULL);
	thread_msg_close_client(msg_name);
}

int dbgstr(char* msg)
{
        return (daemon_server_name)? thread_msg_post_str(daemon_server_name, daemon_message_debug, msg) : 0;
}

char* DbgPrint(const char* format, ...)
{       
#ifdef debug_print
	if (is_debuger_process())
	{
		return (NULL);
	}

	static char DbgMsg[0x1000] = {0}; 
	static int DbgMsg_head = 0;
        if (format)
        {
                va_list args;
                va_start(args, format);

		if (DbgMsg_head == 0)
		{
			char* proc_name = current_process_name();
			char* short_name = NULL;
			if (proc_name)
			{
				short_name = seek_short_file_name(proc_name);
			}

			sprintf(DbgMsg, "[%d]%s:  ", GetCurrentProcessId(), short_name);

			if (proc_name)
			{
				free(proc_name);
			}
	
			OutputDebugStringA("make DbgMsg_head");
			DbgMsg_head = strlen(DbgMsg);
		}

                wvsprintfA(&DbgMsg[DbgMsg_head], format, args);
                va_end(args);
	
		if (!dbgstr(DbgMsg))
		{
			OutputDebugStringA(DbgMsg);
		}
        }
        return DbgMsg;
#else
	return NULL;
#endif
}

int is_path_break(char char2chk)
{
	return ((char2chk == '\\') || (char2chk == '/'))? 1 : 0;
}

char* current_process_name()
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

int is_mutex_process()
{
	char* host_exe = current_process_name();

	if (host_exe)
	{
		long len = strlen(host_exe);
		int i;
		for (i=0; i<len; i++)
		{
			if (is_path_break(host_exe[i]))
			{
				host_exe[i] = '_';
			}
		}

		char mutex_name[MAX_PATH];
		sprintf(mutex_name, "Global\\%s", host_exe);

		HANDLE mutex = CreateMutex(NULL, FALSE, mutex_name);

		if (mutex) 		
		{
			if (GetLastError() == ERROR_ALREADY_EXISTS)
			{
				CloseHandle(mutex);
				return (1);
			}
		}
	}

	return (0);
}

int leave_mutex_process(HANDLE mutex_handle)
{
	if (mutex_handle)
	{
		ReleaseMutex(mutex_handle);
		CloseHandle(mutex_handle);
	}
	return (1);
}

HANDLE enter_mutex_process(const char* mutex_name)
{
	HANDLE mutex = CreateMutex(NULL, TRUE, mutex_name);

	if (mutex) 		
	{
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			leave_mutex_process(mutex);
			return (NULL);
		}
		return (mutex);
	}
	return (NULL);
}

HANDLE enter_mutex_process_wait(const char* mutex_name)
{
	HANDLE mutex = CreateMutex(NULL, TRUE, mutex_name);

	if (mutex) 		
	{
		WaitForSingleObject(mutex, INFINITE);
		return (mutex);
	}

	return (NULL);
}


char* seek_short_file_name(char* buffer)
{
	int outnamesize = strlen(buffer);
	while (!is_path_break(buffer[outnamesize]))
	{
		outnamesize--;
		if (outnamesize == -1)
			break;
	}
	return &buffer[++outnamesize];
}

char* reset_short_file_name(char* buffer, char* new_short_name)
{
	char* input = strdup(buffer);
	char* null = seek_short_file_name(input);
	null[0] = '\0';

	char output[MAX_PATH];
	sprintf(output, "%s%s", input, new_short_name);
	free(input);
	return strdup(output);
}

char* find_ext_dot(char* buffer, int* index)
{
	int scan = strlen(buffer);
	while (buffer[scan] != '.')
	{
		scan--;
		if (scan == -1)
		{
			*index = -1;
			return (NULL);
		}
	}
	*index = scan;
	return (&buffer[scan]);
}

char* change_file_ext(char* buffer, const char* new_ext)
{
	char new_name[MAX_PATH];
	strcpy(new_name, buffer);

	int outnamesize = strlen(new_name);
	while (new_name[outnamesize] != '.')
	{
		outnamesize--;
		if (outnamesize == -1)
			break;
	}

	new_name[++outnamesize] = '\0';
	strcat(new_name, new_ext);
	return strdup(new_name);
}

char* append_file_name(char* src, char* append)
{
	int nofound = 0;
	int name_pos = strlen(src);
	while (src[name_pos] != '.')
	{
		if (is_path_break(src[name_pos]))
		{
			nofound = 1;
			break;
		}

		name_pos--;

		if (name_pos == -1)
		{
			nofound = 1;
			break;
		}
	}
	
	char output[MAX_PATH];

	if (nofound)
	{
		sprintf(output, "%s%s", src, append);
		return strdup(output);
	}

	char* src_cpy = strdup(src);
	src_cpy[name_pos++] = '\0';

	sprintf(output, "%s%s.%s", src_cpy, append, &src_cpy[name_pos]);
	return strdup(output);
}

char* windows_path_linux(char* path)
{
	int i;
	int len = strlen(path);
	for (i=0; i<len; i++)
		if (path[i] == '\\')
			path[i] = '/';
	return path;
}

char* linux_path_windows(char* path)
{
	int i;
	int len = strlen(path);
	for (i=0; i<len; i++)
		if (path[i] == '/')
			path[i] = '\\';
	return path;
}

int imemcpy(char *dest,char *src,int len)
{
        while(--len)
                dest[len] = src[len];
        return 0;
}


long round_up(long val, long alignment)
{
	if( val % alignment )
		return (val + (alignment - (val % alignment)));
	return val;
}


int is_32bit_pefile(char* pe_file)
{
	DWORD lpNumberOfBytesRW;

	HANDLE hfInput = CreateFile(pe_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfInput == 0)
	{
		DbgPrint("openfile error(%s)(%d).", pe_file, GetLastError());
		return 0;

	}

	SetFilePointer(hfInput, 0, NULL, FILE_BEGIN);

	void *data = (void*)malloc(0x1000);
	if (FALSE == ReadFile(hfInput, data, 0x1000, &lpNumberOfBytesRW, NULL))
	{
		DbgPrint("read file error(%s-%d)", pe_file, GetLastError());
		free(data);
		CloseHandle(hfInput);
		return 0;
	}

	CloseHandle(hfInput);


	PIMAGE_NT_HEADERS pNtHeader_File = (PIMAGE_NT_HEADERS)NTHEADER(data);
	return (pNtHeader_File->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE);
}

int mem_to_file(const char* bin_file_name, void* pMemBase, long uMemSize)
{
	int try_times = 2;
	HANDLE hOutput = INVALID_HANDLE_VALUE;

	do
	{
		hOutput = CreateFile(bin_file_name, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hOutput != INVALID_HANDLE_VALUE)
		{
			break;
		}

		DWORD error_code = GetLastError();
		DbgPrint("savetomemfile openfile error.(%s)(%d)[times=%]", bin_file_name, error_code, try_times);

		if (error_code == ERROR_SHARING_VIOLATION)
		{
			continue;
		}
		return (0);
	} while (--try_times);

        SetFilePointer(hOutput, 0, NULL, FILE_BEGIN);

        long uBytesWritten;
        if (FALSE == WriteFile(hOutput, pMemBase, uMemSize, &uBytesWritten, NULL))
        {
                DbgPrint("SaveMemToFile:: WriteFile error");
                CloseHandle(hOutput);
                return (0);
        }

        CloseHandle(hOutput);

        return (1);
}

void* mem_from_file(const char* file_name, long *file_size, long extra_size)
{
	return mem_from_file_raw(file_name, file_size, 0, extra_size);
}

void* mem_from_file_raw(const char* file_name, long *file_size, long limit_size, long extra_size)
{
	DWORD lpNumberOfBytesRW;

	HANDLE hfInput = CreateFile(file_name, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfInput == 0)
	{
		DbgPrint("openfile error(%s)(%d).", file_name, GetLastError());
		return NULL;
	}

	long FileSize = GetFileSize(hfInput, NULL);
	if (FileSize == 0)
	{
		DbgPrint("openfile error(%s)(%d).", file_name, GetLastError());
		CloseHandle(hfInput);
		return NULL;
	}

	SetFilePointer(hfInput, 0, NULL, FILE_BEGIN);

	if (limit_size > 0)
	{
		if (FileSize > limit_size)
			FileSize = limit_size;
	}

	void *data = (void*)malloc(FileSize + extra_size);
	if (FALSE == ReadFile(hfInput, data, FileSize, &lpNumberOfBytesRW, NULL))
	{
		DbgPrint("read file error(%s-%d)", file_name, GetLastError());
		free(data);
		CloseHandle(hfInput);
		return NULL;
	}

	CloseHandle(hfInput);
	*file_size = FileSize;
	return data;
}

