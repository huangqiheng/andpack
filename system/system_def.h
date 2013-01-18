#ifndef __system_def_h_once__
#define __system_def_h_once__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _STORE_ITEM
{
	unsigned long index;
	unsigned long length;
} __attribute__ ((packed, aligned(1))) STORE_ITEM;

typedef struct _PACKAGE
{
	unsigned long size;
	STORE_ITEM launch_exe;
	long repack_whoami_index; //打包时做的标记，说明此节段所在exe的原来名字
	STORE_ITEM repack_app_dir;
	STORE_ITEM plugin_app_dir;
	STORE_ITEM stub_exe;
	STORE_ITEM daemon_exe;
	STORE_ITEM session_dll;
	STORE_ITEM packer_dll;
	STORE_ITEM plugin_dll_dir;
	unsigned long alloc_size;
	unsigned long max_index;
	char buffer[0];
} __attribute__ ((packed, aligned(1))) PACKAGE;

typedef struct _STARTUP
{
	unsigned long size;
	STORE_ITEM realy_repack_apps; 	//通过实地扫描所得的实际的需要打包的文件
	STORE_ITEM realy_plugin_apps; 	//同上，需要插入插件的进程
	STORE_ITEM map_file_names;    	//映射别名，格式是：“别名:真名”
	STORE_ITEM root_path; 	      	//根目录
	STORE_ITEM stub_process_name; 	//被执行的打包器的文件名
	STORE_ITEM stub_command_line; 	//打包器被执行时的命令行
	STORE_ITEM stub_parent_process; //打包器被执行时的父进程
	STORE_ITEM daemon_process;	//守护进程
	STORE_ITEM session_dll;		//守护dll，记录方便删除
	STORE_ITEM share_mutex_name;	//session范围内的共享数据互斥对象
	STORE_ITEM daemon_dbg_name;	//daemon.exe的消息名
	unsigned long stub_is_launch; 	//打包器是否是launch
	unsigned long stub_parent_process_id; //打包器被执行时的父进程ID
	unsigned long stub_process_id; 	//生成startup的stub进程id，方便检测其退出
	unsigned long max_index;
	char buffer[0];
} __attribute__ ((packed, aligned(1))) STARTUP;

#define PACKAGE(item) (&package->buffer[(item).index])
#define STARTUP(item) (&startup->buffer[(item).index])

#define SESSION_DLL_NAME	"session.dll"
#define DAEMON_EXE_NAME 	"daemon.exe"

#define PACKAGE_SECTION_NAME 	"PACKAGE"
#define STUB_START_SECTION_NAME "STARTUP"
#define ORIGIN_APP_SECTION_NAME "STOREPE"
#define SHARED_SECTION_NAME 	"RUNTIME"
#define RESOURCE_SECTION_NAME	"RESDIRS"
#define PLUGIN_PARAM_SECTION	"DLLPARA"


#ifdef __cplusplus
}
#endif
#endif
