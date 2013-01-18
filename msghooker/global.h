#ifndef __global_h_once__
#define __global_h_once__

#ifdef __cplusplus
extern "C" {
#endif

#include "../system/system_def.h"

#define DAEMON_WAIT_TIMEOUT 	3000

#define DEFAULT_OUTPUT 		"output\\"
#define DEFAULT_PLUGIN 		"plugin\\"

#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))
#define VATORVA(base, addr) ((INT)(addr) - (INT)(base))
#define NTHEADER(hModule)   ((PIMAGE_NT_HEADERS)RVATOVA((hModule), ((PIMAGE_DOS_HEADER)(hModule))->e_lfanew))
#define VALIDRANGE(value, base, size) (((DWORD)(value) >= (DWORD)(base)) && ((DWORD)(value)<((DWORD)(base)+(DWORD)(size))))
#define SIZEOFIMAGE(hModule) (NTHEADER(hModule)->OptionalHeader.SizeOfImage)
#define IMAGEBASE(hModule) (NTHEADER(hModule)->OptionalHeader.ImageBase) 

#define daemon_message_id_base (WM_USER + 512)
#define daemon_message_debug (daemon_message_id_base + 1)

#define debug_print 1
#define key_mutex "Global\\key_operation_ensurance_mutex_name"


//普通常用函数
char* DbgPrint(const char* format, ...);
char* set_msg_reporter(char* msg_name);
void disable_reporter(char* msg_name);
char* enable_reporter(HINSTANCE session_dll);
long round_up(long val, long alignment);
unsigned int crc32(unsigned int crc,unsigned char *buffer, unsigned int size);

//文件名操作相关函数
char* seek_short_file_name(char* buffer);
char* reset_short_file_name(char* buffer, char* new_short_name);
char* change_file_ext(char* buffer, const char* new_ext);
char* find_ext_dot(char* buffer, int* index);
char* append_file_name(char* src, char* append);
char* windows_path_linux(char* path);
char* linux_path_windows(char* path);

//pe文件操作相关
int mem_to_file(const char* bin_file_name, void* pMemBase, long uMemSize);
void* mem_from_file(const char* file_name, long* file_size, long extra_size);
void* mem_from_file_raw(const char* file_name, long *file_size, long limit_size, long extra_size);
int is_32bit_pefile(char* pe_file);

//互斥执行相关
int is_mutex_process();
HANDLE enter_mutex_process(const char* mutex_name);
int leave_mutex_process(HANDLE mutex_handle);
HANDLE enter_mutex_process_wait(const char* mutex_name);

//进程操作相关和函数
char* current_process_name();
DWORD get_parent_process_id();
char* pid_to_exepath(DWORD pid);
int kill_process_byname(char* full_process_name);
int kill_process(DWORD pid);
DWORD get_process_alive_id(char* full_process_name);

int is_process_exists(DWORD pid);
int is_repack_process(STARTUP* startup);
int is_plugin_process(STARTUP* startup);
int is_debuger_process();



#ifdef __cplusplus
}
#endif

#endif
