#ifndef __package_h_once__
#define __package_h_once__

#ifdef __cplusplus
extern "C" {
#endif

//生成“包”所需函数
PACKAGE* init_package();
PACKAGE* get_package();
PACKAGE* append_string_to_package(char* add_str, STORE_ITEM* fill_item);
PACKAGE* append_data_to_package(void* mem_base, unsigned long mem_size, STORE_ITEM* fill_item);
PACKAGE* append_file_to_package(char* full_file_name, STORE_ITEM* fill_item);

STARTUP* init_startup();
STARTUP* get_startup();
STARTUP* append_string_to_startup(char* add_str, STORE_ITEM* fill_item);
STARTUP* append_data_to_startup(void* mem_base, unsigned long mem_size, STORE_ITEM* fill_item);

//打包相关函数
typedef struct
{
	List repack_list;
	List plugto_list;
	List map_list;
	char* root_dir;
} SEARCH_PARAM;

int copack_make_package_apps(PACKAGE* package, char* root_dir, char* output_dir);
char* stub_make_session_apps(PACKAGE* package, SEARCH_PARAM *search);

void* make_launch(PACKAGE* package, long* launch_size);
void* make_repack_app(const char* ori_name, const char* app_file, const void* launch_exe, long launch_size, long* repack_size, int cover_repack);
int find_repack_index(PACKAGE* package, const char* ori_name);
char* find_repack_name(PACKAGE* package, int index);

#ifdef __cplusplus
}
#endif

#endif
