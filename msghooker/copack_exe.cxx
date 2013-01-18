/*
   打包器的任务：
   1）使用UI界面搜集打包所需的参数。
   2）生成整个session任务所需的package包裹。
   3）生成“引导程序”stub.exe，该引导程序包囊了原始程序。
*/
#include <windows.h>
#include <assert.h>
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Browser.H>
#include <FL/fl_ask.H>
#include <FL/Fl_Box.H>
#include <FL/fl_utf8.h>
#include <FL/Fl_Text_Editor.H>

#include <iconv.h>
#include <mxml.h>

extern "C" {
#include "list.h"
#include "queue.h"
#include "stackar.h"
}

#include "copack.h"
#include "global.h"
#include "message_comm.h"
#include "package.h"
#include "dll_in_section.h"
#include "xml_in_section.h"
#include "stub.exe.inc"
#include "daemon.exe.inc"
#include "packer.dll.inc"
#include "session.dll.inc"

char * EncodingConv(  const char * in, char *encFrom, char *encTo )
{

	char *buff, *sin, *sout;
	int lenin, lenout;
	iconv_t ct;

	if( (ct=iconv_open(encTo, encFrom)) == (iconv_t)-1 )
	{
		DbgPrint("%s|%d| iconv_open error! %s", __FILE__,
				__LINE__, strerror(errno) );
		return( NULL );
	}

	iconv( ct, NULL, NULL, NULL, NULL );

	sin = (char *)in;
	lenin  = strlen(in) + 1;

	if( (buff = (char*)malloc(lenin*2))==NULL )
	{
		DbgPrint("%s|%d| malloc error! %s", __FILE__, __LINE__,
				strerror(errno) );
		iconv_close( ct );
		return( NULL );
	}
	sout   = buff;
	lenout = lenin*2;

	if( iconv( ct, &sin, (size_t *)&lenin, &sout, (size_t *)&lenout) == -1 )
	{
		DbgPrint("%s|%d| iconv() error! errno=%d %s", __FILE__,
				__LINE__, errno, strerror(errno) );
		free( buff );
		iconv_close( ct );
		return NULL;
	}

	iconv_close( ct );

	sout=strdup(buff);
	free( buff );

	return( sout );
}

int utf8togb2312(const char *sourcebuf,size_t sourcelen,char *destbuf,size_t destlen)
{
	iconv_t cd;
	if( (cd = iconv_open("gb2312","utf-8")) ==0 )
		return -1;
	memset(destbuf,0,destlen);
	char **source = (char**)&sourcebuf;
	char **dest = &destbuf;

	if(-1 == iconv(cd,source,&sourcelen,dest,&destlen))
	{
		return -1;
	}
	iconv_close(cd);
	return 0;

}

int gb2312toutf8(const char *sourcebuf,size_t sourcelen,char *destbuf,size_t destlen)
{
	iconv_t cd;
	if( (cd = iconv_open("utf-8","gb2312")) ==0 )
		return -1;
	memset(destbuf,0,destlen);
	char **source = (char**)&sourcebuf;
	char **dest = &destbuf;

	if(-1 == iconv(cd,source,&sourcelen,dest,&destlen))
		return -1;
	iconv_close(cd);
	return 0;

}

char* u2g(const char* src)
{
	size_t srclen = strlen(src);
	size_t destlen = srclen*2;
	char* distbuf = (char*)malloc(destlen);
	utf8togb2312(src, srclen, distbuf, destlen);
	return distbuf;
}

char* g2u(const char* src)
{
	size_t sourcelen = strlen(src);
	size_t destlen = sourcelen*2;
	char *destbuf = (char*)malloc(destlen);
	gb2312toutf8(src, sourcelen, destbuf, destlen);
	return destbuf;
}

typedef int (*lpfn_search_cb)(char* path, int new_path, char* filename, void* lparam, void* wparam);

void search_file(char* search_path, const char* search_for, lpfn_search_cb cb, void* lparam, void* wparam)
{
	WIN32_FIND_DATA FindData;

	char search_str[MAX_PATH];
	sprintf(search_str, "%s*.*", search_path);

	HANDLE find_handle = FindFirstFile(search_str, &FindData);
	if (find_handle == INVALID_HANDLE_VALUE)
	{
		return;
	}

	int is_new_path = 1;

	do
	{
		//DbgPrint("search: %s", FindData.cFileName);

		if ((strcmp(FindData.cFileName, ".") == 0) || (strcmp(FindData.cFileName, "..") == 0))
			continue;

		if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			char sub_search_path[MAX_PATH];
			sprintf(sub_search_path, "%s%s\\", search_path, FindData.cFileName);
			DbgPrint("sub dir: %s", sub_search_path);
			search_file(sub_search_path, search_for, cb, lparam, wparam);
		}
		else
		{
			if (search_for)
			{
				int len = strlen(FindData.cFileName);
				int len_s = strlen(search_for);
				if (len > len_s)
				{
					if (stricmp(&FindData.cFileName[len-len_s], search_for) == 0)
					{
						if (0 == cb(search_path, is_new_path, FindData.cFileName, lparam, wparam))
						{
							break;
						}
						is_new_path = 0;
					}
				}
			}
			else
			{
				if (0 == cb(search_path, is_new_path, FindData.cFileName, lparam, wparam))
				{
					break;
				}
				is_new_path = 0;
			}
		}
	} while (FindNextFile(find_handle, &FindData));

	FindClose(find_handle);
}

int search_exe_cb(char* path, int new_path, char* filename, void* lparam, void* wparam)
{
	Fl_Check_Browser* entry_apps = (Fl_Check_Browser*)lparam;
	char* raw_path = (char*)wparam;
	int raw_path_len = strlen(raw_path);

	char full_name[MAX_PATH];
	sprintf(full_name, "%s%s", path, filename);
	char* add_name = g2u(&full_name[raw_path_len]);
	entry_apps->add(add_name);
	free(add_name);
	return (1);
}

int search_pe_cb(char* path, int new_path, char* filename, void* lparam, void* wparam)
{
	if (new_path)
	{
		Fl_Check_Browser* plugin_apps = (Fl_Check_Browser*)lparam;
		char* raw_path = (char*)wparam;
		int raw_path_len = strlen(raw_path);

		char full_name[MAX_PATH];
		sprintf(full_name, "%s*.*", path);
		char* add_name = g2u(&full_name[raw_path_len]);
		plugin_apps->add(add_name);
		free(add_name);
	}

	return search_exe_cb(path, new_path, filename, lparam, wparam);
}

void when_pick_a_path(Fl_Widget* sender, void* param)
{
	Packer* packer_ui = (Packer*)param;
	Fl_Input_Choice* root_path = packer_ui->root_path;
	Fl_Check_Browser* entry_apps = packer_ui->entry_apps;
	Fl_Check_Browser* plugin_apps = packer_ui->plugin_apps;
	Fl_Choice *launch_choice = packer_ui->launch_choice;

	char* new_path = fl_dir_chooser("请选择一个目录", NULL, 0);
	if (new_path)
	{
		new_path = linux_path_windows(new_path);
		root_path->value(new_path);
		new_path = u2g(new_path);

		launch_choice->clear();
		entry_apps->clear();
		plugin_apps->clear();

		//添加入口程序列表
		search_file(new_path, ".exe", search_exe_cb, (void*)entry_apps, (void*)new_path);

		//添加launch选择列表
		int i;
		int count = entry_apps->nitems();
		for (i=1; i<=count; i++)
		{
			char* to_add = strdup(entry_apps->text(i));
			char* choice_name = windows_path_linux(to_add);
			launch_choice->add(choice_name);
			free(to_add);
		}

		//添加被打包的程序列表
		search_file(new_path, ".exe", search_pe_cb, (void*)plugin_apps, (void*)new_path);

		entry_apps->redraw();
		plugin_apps->redraw();
	}
}

void print_store_item(const char* title, STORE_ITEM* item)
{
	DbgPrint("%s: %d, size:%d", title, item->index, item->length);
}

PACKAGE* add_checklist_to_package(Fl_Check_Browser* check_browser, STORE_ITEM* fill_item)
{
	int i;
	int count_checked = check_browser->nchecked();

	if (count_checked)
	{
		STORE_ITEM* entry_items = (STORE_ITEM*)calloc(count_checked + 1, sizeof(STORE_ITEM));
		STORE_ITEM* ori_items = entry_items;

		int count = check_browser->nitems();
		for (i=1; i<=count; i++)
		{
			if (check_browser->checked(i))
			{
				char* to_add = u2g(check_browser->text(i));
				append_string_to_package(to_add, entry_items);

/*
				if (list_mode == checked_filelist)
				{
					append_string_to_package(to_add, entry_items);
				}
				else if (list_mode == checked_filedata)
				{
					long file_size;
					void* file_mem = mem_from_file(to_add, &file_size, 0);
					append_data_to_package(file_mem, file_size, entry_items);
					free(file_mem);
				}	
*/

				print_store_item(to_add, entry_items);

				entry_items++;
				free(to_add);
			}
		}
		append_data_to_package(ori_items, sizeof(STORE_ITEM)*(count_checked+1), fill_item);
	}
	return (get_package());
}


char* get_output_dir()
{
	char current_path[MAX_PATH];
	if (GetModuleFileNameA(NULL, current_path, sizeof(current_path)))
	{
		char* file_name = seek_short_file_name(current_path);
		file_name[0] = '\0';
		file_name = strdup(current_path);
		sprintf(current_path, "%s%s", file_name, DEFAULT_OUTPUT); 
		free(file_name);
		return strdup(current_path);
	}
	return (NULL);
}


const char* whitespace_cb(mxml_node_t *node, int where)
{
	const char* name = node->value.element.name;

	if (!strncmp(name, "?xml", 4))
	{
		return (NULL);
	}
	else if (
			!strcmp(name, "dependent") ||
			!strcmp(name, "parameter") ||
			!strcmp(name, "system") ||
			!strcmp(name, "hints"))
	{
		if (where == MXML_WS_BEFORE_OPEN || 
		    where == MXML_WS_AFTER_OPEN ||
		    where == MXML_WS_AFTER_CLOSE)
			return ("\n");
	}
	else
	{
		if (where == MXML_WS_BEFORE_OPEN)
			return ("\t");

		if (where == MXML_WS_AFTER_CLOSE)
			return ("\n");
	}

	return (NULL);
}

char* make_default_xml_text()
{
	mxml_node_t *xml;
	mxml_node_t *group;
	mxml_node_t *node;
	
	xml = mxmlNewXML("1.0");

	group = mxmlNewElement(xml, "dependent");
	node = mxmlNewElement(group, "plugin");  mxmlNewText(node, 0, "null");
	node = mxmlNewElement(group, "plugin");  mxmlNewText(node, 0, "null");

	group = mxmlNewElement(xml, "parameter");
	node = mxmlNewElement(group, "value");	mxmlNewText(node, 0, "null");
	node = mxmlNewElement(group, "value");	mxmlNewText(node, 0, "null");

	group = mxmlNewElement(xml, "system");
	node = mxmlNewElement(group, "value");	mxmlNewText(node, 0, "null");
	node = mxmlNewElement(group, "value");	mxmlNewText(node, 0, "null");

	group = mxmlNewElement(xml, "hints");
	node = mxmlNewElement(group, "title");	mxmlNewText(node, 0, "john smith");
	node = mxmlNewElement(group, "header"); mxmlNewText(node, 0, "anything about the plugin dll.");
	node = mxmlNewElement(group, "body");	mxmlNewText(node, 0, "john smith");
	node = mxmlNewElement(group, "email");	mxmlNewText(node, 0, "author@youremail.com");

	mxmlSetWrapMargin(2);
	char* result = mxmlSaveAllocString(xml, whitespace_cb);
	mxmlDelete(xml);
	return (strdup(result));
}

char* default_plugin_root = NULL;

char* get_plugin_path()
{
	if (default_plugin_root)
		return (default_plugin_root);

	char* exe_name = current_process_name();
	char* exe_end = seek_short_file_name(exe_name);
	exe_end[0] = '\0';

	char to_search_path[MAX_PATH];
	sprintf(to_search_path, "%s%s", exe_name, DEFAULT_PLUGIN);

	default_plugin_root = strdup(to_search_path);
	return (default_plugin_root);
}

int search_plugin_dll_cb(char* path, int new_path, char* filename, void* lparam, void* wparam)
{
	Fl_Hold_Browser* plugin_list = (Fl_Hold_Browser*)lparam;

	char full_name[MAX_PATH];
	sprintf(full_name, "%s%s", path, filename);

	int pos = strlen(get_plugin_path());

	char* add_name = g2u(&full_name[pos]);
	plugin_list->add(add_name);
	free(add_name);

	return (1);
}

void set_plugin_list(Fl_Hold_Browser* plugin_list)
{
	char* to_search_path = get_plugin_path();
	DbgPrint("to search: %s", to_search_path);
	search_file(to_search_path, ".dll", search_plugin_dll_cb, (void*)plugin_list, (void*)to_search_path);
}

char* last_xml_file = NULL;
int   last_xml_file_modified = 0;
DWORD last_click_time = 0;
int   last_click_index = 0;

char* get_xml_file(Fl_Hold_Browser* plugin_list)
{
	char* item_str = u2g(plugin_list->text(plugin_list->value()));
	char* root_str = get_plugin_path();

	char full_name[MAX_PATH];
	sprintf(full_name, "%s%s", root_str, item_str);

	return change_file_ext(full_name, "xml");
}


char*** dependent_list = NULL;
int  dependent_list_count = 0;

char** make_list_from_xmlfile(char* xml_file)
{
	char** run_result = NULL;
	FILE *fp = fopen(xml_file, "r");
	mxml_node_t *tree = mxmlLoadFile(NULL, fp, MXML_TEXT_CALLBACK);
	fclose(fp);

	DbgPrint("parse dependent list of: %s", xml_file);

	do
	{
		if (tree == NULL)
		{
			DbgPrint("make_list: empty [%s]", xml_file);
			break;
		}

		mxml_node_t *dep = mxmlFindElement(tree, tree, "dependent", NULL, NULL, MXML_DESCEND);

		if (dep == NULL)
		{
			DbgPrint("make_list: can't found element \"dependent\"");
			break;
		}

		mxml_node_t* current = dep;
		int item_count = 0;
		typedef struct {
			void* next;
			char* item;
		} char_item;
		char_item* item_head = NULL;

		while (current = mxmlFindElement(current, dep, "plugin", NULL, NULL, MXML_DESCEND))
		{
			const char* dll_name = current->child->value.text.string;
			char_item* new_item;

			if (item_head == NULL)
			{
				item_head = (char_item*)malloc(sizeof(char_item));
				new_item = item_head;
				new_item->next = NULL;
			}
			else
			{
				new_item = (char_item*)malloc(sizeof(char_item));
				new_item->next = item_head;
				item_head = new_item;
			}

			new_item->item = strdup(dll_name);
			item_count++;

			DbgPrint("plugin dll[%d]: %s", item_count, dll_name);
		}

		if (item_count)
		{
			char** ret_list = (char**)calloc(item_count+1, sizeof(char*));

			int i;
			char_item* scan = item_head;
			char_item* del_item;

			for (i=0; i<item_count; i++)
			{
				ret_list[i] = scan->item;
				del_item = scan;
				scan = (char_item*)scan->next;
				free(del_item);
			}

			run_result = ret_list;
			break;
		}

	} while (FALSE);

	if (tree)
		mxmlDelete(tree);
	return (run_result);
}

int find_indexof_xmlfile(Fl_Hold_Browser* plugin_list, char* xml_file)
{
	int i;
	char* filename;
	int count = plugin_list->size();

	char* plugin_path = get_plugin_path();
	char* xml_short = &xml_file[strlen(plugin_path)];
	char* xml_item;

	for (i=1; i<= count; i++)
	{
		filename = u2g(plugin_list->text(i));
		xml_item = change_file_ext(filename, "xml");
		free(filename);

		if (!stricmp(xml_item, xml_short))
		{
			return (i);
		}
	}
	return (0);
}

void update_dependent_list(Fl_Hold_Browser* plugin_list, char* xml_file)
{
	int index = find_indexof_xmlfile(plugin_list, xml_file);
	if (index == 0)
	{
		return;
	}

	index--;

	char** sub_list = dependent_list[index];

	if (sub_list)
	{
		char* to_del_file;
		do
		{
			to_del_file = *sub_list;
			free(to_del_file);
		} while (*(++sub_list));
		free(dependent_list[index]);
	}
	
	dependent_list[index] = make_list_from_xmlfile(xml_file);
}


int hold_checked(Fl_Hold_Browser* plugin_list, int index)
{
	return (int)plugin_list->data(index);
}

int hold_nchecked(Fl_Hold_Browser* plugin_list)
{
	int result = 0;
	int i;
	int count = plugin_list->size();
	for (i=1; i<=count; i++)
	{
		if (hold_checked(plugin_list, i))
		{
			result++;
		}
	}
	return (result);
}

void hold_check(Fl_Hold_Browser* plugin_list, int index, int b)
{
	plugin_list->data(index, (void*)b);

	if (b)
	{
		plugin_list->icon(index, plugin_list->image());
	}
	else
	{
		plugin_list->icon(index, plugin_list->deimage());
	}
}


void init_dependent_list(Fl_Hold_Browser* plugin_list)
{
	int i;
	char* filename;
	char* xml_file;
	char fullname[MAX_PATH];
	int count = plugin_list->size();

	if (dependent_list == NULL)
	{
		dependent_list = (char***)calloc(count+1, sizeof(char**));
	}

	for (i=1; i<= count; i++)
	{
		filename = u2g(plugin_list->text(i));
		sprintf(fullname, "%s%s", get_plugin_path(), filename);
		free(filename);

		xml_file = change_file_ext(fullname, "xml");

		DbgPrint("init %s", xml_file);

		if (GetFileAttributes(xml_file) != -1)
		{
			dependent_list[i-1] = make_list_from_xmlfile(xml_file);
		}

		hold_check(plugin_list, i, 0);
	}
}


char* get_plugin_name_in_list(Fl_Hold_Browser* plugin_list, int index, int is_full_name)
{	
	char* file_name;

	if (is_full_name)
	{
		file_name = u2g(plugin_list->text(index));
		char out[MAX_PATH];
		sprintf(out, "%s%s", get_plugin_path(), file_name);
		return strdup(out);
	}
	else
	{
		file_name = u2g(plugin_list->text(index));
		char* short_name= strdup(seek_short_file_name(file_name));
		free(file_name);
		return short_name;
	}
}

int get_indexof_plugin_name(Fl_Hold_Browser* plugin_list, char* path, char* plugin_name, 
			int bypass_checked, int bypass_unchecked, int bypass_index)
{
	int i;
	int count = plugin_list->size();
	for (i=1; i<=count; i++)
	{
		int is_check = hold_checked(plugin_list, i);

		if (bypass_checked && is_check)
		{
			continue;
		}

		if (bypass_unchecked && !is_check)
		{
			continue;
		}

		if (i == bypass_index)
		{
			continue;
		}

		char* enum_plugin_name = get_plugin_name_in_list(plugin_list, i, 0);
		if (!stricmp(enum_plugin_name, plugin_name))
		{
			if (path)
			{
				char full_plugin_name[MAX_PATH]; 
				sprintf(full_plugin_name, "%s%s", path, plugin_name);

				char* full_enum_plugin_name = get_plugin_name_in_list(plugin_list, i, 1);

				if (!stricmp(full_enum_plugin_name, full_plugin_name))
				{
					return (i);
				}
			}
			else
			{
				return (i);
			}
		}
	}

	return (0);
}

/*
   这里设计的关键是：
   1）逐个取出列表中的“终端元素”塞入盏中，也就是那些顶层的，不被其他插件依赖的“插件”。
   2）弹出栈中的元素（完整的路径名），逐个塞入到package中。
   3）每个插件，都带上xml参数文件
 */
char* add_plugin_dlls_to_package(Fl_Hold_Browser* plugin_list, STORE_ITEM* fill_item)
{
	int i;
	int count_checked = hold_nchecked(plugin_list);
	int count = plugin_list->size();
	char name_buff[MAX_PATH];

	if (count_checked == 0)
	{
		return (NULL);
	}

	//创建一个模版
	char** list_dll = (char**)calloc(count + 1, sizeof(char*));

	for (i=1; i<=count; i++)
	{
		int is_check = hold_checked(plugin_list, i);

		if (is_check)
		{
			char* to_add = u2g(plugin_list->text(i));
			sprintf(name_buff, "%s%s", get_plugin_path(), to_add);
			free(to_add);

			list_dll[i-1] = strdup(name_buff);
		}
	}

	//创建一个栈
	Stack dll_stack = CreateStack(count);

	//从模版中，取出一个“终端元素”
	do
	{
		int scan_index;
		int enum_index;

		for (scan_index=0; scan_index<count; scan_index++)
		{
			char* scan_file = list_dll[scan_index];

			if (scan_file == NULL)
			{
				continue;
			}

			DbgPrint("start check: %s", scan_file);
			int i_am_tail = 1;

			for (enum_index=0; enum_index<count; enum_index++)
			{
				char* enum_file = list_dll[enum_index];

				if (enum_file == NULL)
				{
					continue;
				}

				if (scan_index == enum_index)
				{
					continue;
				}

				DbgPrint("\tcheck dep: %s", enum_file);

				//检查是否有插件（enum_file)依赖自己（scan_file）
				char** dependlist = dependent_list[enum_index];

				if (dependlist == NULL)
				{
					continue;
				}

				char* scan_file_short = seek_short_file_name(scan_file);
				int ii = 0;
				int is_dependon_me = 0;

				while (dependlist[ii])
				{
					char* depend_plugin_name = dependlist[ii];
					DbgPrint("\t\tcheck plugin: %s ?= %s", scan_file_short, depend_plugin_name);

					if (!stricmp(depend_plugin_name, scan_file_short))
					{
						is_dependon_me = 1;
						break;
					}
					ii++;
				}

				if (is_dependon_me)
				{
					i_am_tail = 0;
					break;
				}
			}

			//如果发现自己是“终端”，则压入栈中，并在模版中删除自己
			if (i_am_tail)
			{
				DbgPrint("--> push stack: %s", scan_file);
				Push((int)scan_file, dll_stack);
				list_dll[scan_index] = NULL;
				count_checked--;
				break;
			}
		}
	} while (count_checked);


	char* system_xmlstr = NULL;
	mxml_node_t *xml = mxmlNewXML("1.0");
	mxml_node_t *group = mxmlNewElement(xml, "system");
	mxml_node_t *node;

	count_checked = hold_nchecked(plugin_list);
	STORE_ITEM* ori_items = (STORE_ITEM*)calloc(count_checked + 1, sizeof(STORE_ITEM));
	STORE_ITEM* entry_items;
	for (entry_items=ori_items; !IsEmptyStack(dll_stack); entry_items++)
	{
		//取出插件的原始内容
		char* dll_file_name = (char*)TopAndPop(dll_stack);
		long file_size;
		void* file_mem = mem_from_file(dll_file_name, &file_size, 0);

		if (file_mem == NULL)
		{
			DbgPrint("fatal error: can't load %s", dll_file_name);
			continue;
		}

		//取出xml参数文件
		char* xml_file_name = change_file_ext(dll_file_name, "xml");
		long xml_size;
		void* xml_mem = mem_from_file(xml_file_name, &xml_size, 0);

		if (xml_mem)
		{
			//将xml文件插入到插件dll中
			DbgPrint("append \"%s\" to \"%s\"", xml_file_name, dll_file_name);
			long mix_out_size = 0;
			void* mix_out_mem = append_section(file_mem, file_size, &mix_out_size, PLUGIN_PARAM_SECTION, xml_mem, xml_size);

			//写入到package包中
			append_data_to_package(mix_out_mem, mix_out_size, entry_items);

			char* out_test = strdup(dll_file_name);
			out_test[strlen(out_test)-1] = '0';
			mem_to_file(out_test, mix_out_mem, mix_out_size);

			//取出xml文件中的system标签的，并收集起来
			const char** keyval_lst = get_catelog((char*)xml_mem, "system");
			
			//枚举出xml中的system元素的全部节点内容
			if (keyval_lst)
			{
				for (i=0; keyval_lst[i]; i+=2)
				{
					const char* key = keyval_lst[i];
					const char* val = keyval_lst[i+1];
					DbgPrint("add key:%s, val:%s", key, val);

					if (node=mxmlFindElement(group,group,key,NULL,NULL,MXML_DESCEND))
					{
						mxmlSetText(node, 0, val);
					}
					else
					{
						node = mxmlNewElement(group, key);
						mxmlNewText(node, 0, val);
					}
				}
			}

			//释放xml文件资源
			free(mix_out_mem);
			free(xml_mem);
		}
		else
		{
			append_data_to_package(file_mem, file_size, entry_items);
			free(file_mem);
		}

		print_store_item(dll_file_name, entry_items);

		free(dll_file_name);
		free(xml_file_name);
	}

	append_data_to_package(ori_items, sizeof(STORE_ITEM)*(count_checked+1), fill_item);

	mxmlSetWrapMargin(2);
	system_xmlstr = strdup(mxmlSaveAllocString(xml, whitespace_cb));
	mxmlDelete(xml);

	DisposeStack(dll_stack);
	free(list_dll);
	return (system_xmlstr);
}

void check_on_plugin(Fl_Hold_Browser* plugin_list, int index, char* path)
{
	assert(index>0);
	
	if (path == NULL)
	{
		path = get_plugin_name_in_list(plugin_list, index, TRUE);
		char* short_name_base = seek_short_file_name(path);
		short_name_base[0] = '\0';
	}

	char* check_on_name = get_plugin_name_in_list(plugin_list, index, FALSE);
	DbgPrint("check on: %s", check_on_name);

	//全列表检查，看是否已经有check，如果有，则只需转换一下即可
	int same_plugin_index = get_indexof_plugin_name(plugin_list, NULL, check_on_name, 0, 1, index);

	if (same_plugin_index)
	{
		hold_check(plugin_list, same_plugin_index, 0);
		check_on_plugin(plugin_list, index, path);
		return;
	}

	//如果没有依赖的插件，则不需特殊处理
	char** dependlist = dependent_list[index-1];
	if (dependlist == NULL)
	{
		return;
	}

	int ii = 0;
	while (dependlist[ii])
	{
		char* depend_plugin_name = dependlist[ii];

		int found_index_local = get_indexof_plugin_name(plugin_list, path, depend_plugin_name,0,0,0);
		int found_index_global = get_indexof_plugin_name(plugin_list, NULL, depend_plugin_name,0,0,0);

		if ((found_index_local) && (found_index_global == 0))
		{
			DbgPrint(" --local check on:[%d] %s", found_index_local, depend_plugin_name);
			hold_check(plugin_list, found_index_local, 1);
			check_on_plugin(plugin_list, found_index_local, path);
		}
		else
		{
			if (found_index_global)
			{
				DbgPrint(" --global check on:[%d] %s", found_index_global, depend_plugin_name);

				hold_check(plugin_list, found_index_global, 1);
				check_on_plugin(plugin_list, found_index_global, path);
			}
		}

		ii++;
	}

	free(check_on_name);
}

void check_off_plugin(Fl_Hold_Browser* plugin_list, int index)
{
	assert(index>0);

	char* check_off_name = get_plugin_name_in_list(plugin_list, index, FALSE);
	DbgPrint("check off: %s", check_off_name);
	
	int i;
	int count = plugin_list->size();
	for (i=1; i<=count; i++)
	{
		//逐个检查列表，看列表中有没有依赖的
		//所有依赖的，都必须同时check_off
		if (i != index)
		{
			//如果依赖列表是空的，就忽略
			char** dependlist = dependent_list[i-1];

			if (!dependlist)
			{
				continue;
			}

			//如果该项并没有“选上”，则忽略之
			int is_check = hold_checked(plugin_list, i);
			
			if (!is_check)
			{
				continue;
			}

			//检查整个依赖列表，如果有依赖的，则需要check_off
			int j = 0;
			char* check_plugin_name = get_plugin_name_in_list(plugin_list, i, 0);

			while (dependlist[j])
			{
				char* plugin_name = dependlist[j];
				if (!stricmp(plugin_name, check_off_name))
				{
					DbgPrint(" --sub check off: %s", check_plugin_name);
					hold_check(plugin_list, i, 0);
					check_off_plugin(plugin_list, i);
					break;
				}
				j++;
			}
		}
	}
}

void plugin_parameter_modify_cb(int pos, int nInserted, int nDeleted, int nRestyled, const char* deletedText, void* cbArg)
{
	last_xml_file_modified = 1;
}

Fl_Text_Buffer* get_xml_buff(Fl_Text_Editor* param_editor)
{
	Fl_Text_Buffer* buff = param_editor->buffer();

	//初始化数据结构
	if (buff == NULL)
	{
		buff = new Fl_Text_Buffer();
		buff->add_modify_callback(plugin_parameter_modify_cb, NULL);
		param_editor->buffer(buff);
	}

	return (buff);
}

int save_text_buff(Fl_Text_Editor* param_editor)
{
	if (last_xml_file_modified)
	{
		if (last_xml_file)
		{
			char* xml_file_utf8 = g2u(last_xml_file);
			Fl_Text_Buffer* buff = get_xml_buff(param_editor);
			buff->savefile(xml_file_utf8);
			free(xml_file_utf8);
			return (1);
		}
		last_xml_file_modified = 0;
	}

	return (0);
}

void print_click_count_list(Fl_Hold_Browser* plugin_list)
{
	int i;
	char* filename;
	int click_index = plugin_list->value();
	int click_count = plugin_list->size();

	DbgPrint("--------- plugin check state -----------");

	for (i=1; i<= click_count; i++)
	{
		filename = u2g(plugin_list->text(i));
		DbgPrint("[%.2d] : [%d] : %s %s", i, (int)plugin_list->data(i), filename, (click_index == i)? "<--" : NULL);
		free(filename);
	}

	DbgPrint("------------  end  ----------------");
}

void when_click_plugin(Fl_Widget* sender, void* param)
{
	Packer* packer_ui = (Packer*)param;
	Fl_Hold_Browser* plugin_list = packer_ui->plugin_list;
	Fl_Text_Editor* param_editor = packer_ui->param_editor;
	Fl_Text_Buffer* buff = get_xml_buff(param_editor);
	
	int index = plugin_list->value();
	int is_double_click = ((GetTickCount()-last_click_time)<500)? (last_click_index==index)? 1 : 0 : 0;

	if (!is_double_click)
	{
		//保存xml
		if (save_text_buff(param_editor))
		{
			update_dependent_list(plugin_list, last_xml_file);
			free(last_xml_file);
			last_xml_file = NULL;
		}

		//如果没有选中任何一行，则退出
		if (index == 0)
		{
			return;
		}

		//将xml加载到文本框中
		char* xml_file = get_xml_file(plugin_list);
		if (GetFileAttributes(xml_file) == -1)
		{
			buff->text(make_default_xml_text());
		}
		else
		{
			char* xml_file_utf8 = g2u(xml_file);
			buff->loadfile(xml_file_utf8);
			free(xml_file_utf8);
		}
		last_xml_file = xml_file;
		last_click_time = GetTickCount();
		last_click_index = index;


		//如果按下了ctrl或者shift键，则“选中”
		if (!(Fl::event_ctrl() || Fl::event_shift()))
		{
			return;
		}
	}

	int checked = hold_checked(plugin_list, index);
	checked = checked? 0 : 1;
	hold_check(plugin_list, index, checked);

	//如果选择了一个item，则其依赖的item也同时需选上
	if (checked)
	{
		check_on_plugin(plugin_list, index, NULL);
	}
	//否则，取消选择一个item，所有依赖它的，都必须取消选择之
	else
	{
		check_off_plugin(plugin_list, index);
	}

	print_click_count_list(plugin_list);

}

void save_configured_ui(Packer* packer_ui);

void when_submit_pack(Fl_Widget* sender, void* param)
{
	Packer* packer_ui = (Packer*)param;
	Fl_Input_Choice* root_path = packer_ui->root_path;
	Fl_Check_Browser* entry_apps = packer_ui->entry_apps;
	Fl_Check_Browser* plugin_apps = packer_ui->plugin_apps;
	Fl_Hold_Browser* plugin_list = packer_ui->plugin_list;
	Fl_Choice *launch_choice = packer_ui->launch_choice;
	
	//可能会有未保存的已经修改的xml文件
	save_text_buff(packer_ui->param_editor);

	PACKAGE* package = init_package();

	//添加启动器目录
	char name[MAX_PATH];
	if (launch_choice->item_pathname(name, sizeof(name)-1) == 0)
	{
		char* launch_name = u2g(name);
		linux_path_windows(launch_name);
		DbgPrint("launch exe: %s", launch_name);
		package = append_string_to_package(launch_name, &package->launch_exe);
		free(launch_name);
	}
	print_store_item("launch exe", &package->launch_exe);

	//添加入口程序的列表
	package = add_checklist_to_package(entry_apps, &package->repack_app_dir);
	print_store_item("repack dir", &package->repack_app_dir);

	//添加运行插件的程序列表
	package = add_checklist_to_package(plugin_apps, &package->plugin_app_dir);
	print_store_item("plguin app dir", &package->plugin_app_dir);

	//添加插件
	char* system_xmlstr = add_plugin_dlls_to_package(plugin_list, &package->plugin_dll_dir);
	if (system_xmlstr == NULL)
	{
		init_package();
		return;
	}

	package = get_package();
	print_store_item("plguin dir", &package->plugin_dll_dir);
	DbgPrint("session.dll xml file:\n%s", system_xmlstr);

	//添加xml文件到session.dll中
	long xmlstr_len = strlen(system_xmlstr) + 1;
	long mix_out_size = 0;
	void* mix_out_mem = append_section(&session_dll, session_dll_size, &mix_out_size, PLUGIN_PARAM_SECTION, system_xmlstr, xmlstr_len);

	//添加内嵌模块
	package = append_data_to_package(&stub_exe, stub_exe_size, &package->stub_exe);
	package = append_data_to_package(&daemon_exe, daemon_exe_size, &package->daemon_exe);
	package = append_data_to_package(mix_out_mem, mix_out_size, &package->session_dll);
	package = append_data_to_package(&packer_dll, packer_dll_size, &package->packer_dll);

	free(mix_out_mem);
	free(system_xmlstr);
	
	print_store_item("stub_exe", &package->stub_exe);
	print_store_item("daemon_exe", &package->daemon_exe);
	print_store_item("session_dll", &package->session_dll);
	print_store_item("packer_dll", &package->packer_dll);

	//生成打包程序
	char* root_dir = u2g(strdup(root_path->value()));
	char* output_dir = get_output_dir();
	copack_make_package_apps(package, root_dir, output_dir);

	save_configured_ui(packer_ui);
	ExitProcess(0);
}

void add_item(mxml_node_t *group, const char* name, const char* attr, const char* value)
{
	mxml_node_t *node = mxmlNewElement(group, name);  
	mxmlNewText(node, 0, value);
}

void init_solution_setting(Packer* packer_ui)
{
	packer_ui->is_cover_src->deactivate();
	packer_ui->is_backup_src->deactivate();
	packer_ui->is_retore_last->deactivate();
}

void save_configured_ui(Packer* packer_ui)
{
	return;

	Fl_Input_Choice* root_path = packer_ui->root_path;
	Fl_Check_Browser* entry_apps = packer_ui->entry_apps;
	Fl_Check_Browser* plugin_apps = packer_ui->plugin_apps;
	Fl_Hold_Browser* plugin_list = packer_ui->plugin_list;
	Fl_Choice *launch_choice = packer_ui->launch_choice;
	Fl_Check_Button *is_cover_src = packer_ui->is_cover_src;
	Fl_Check_Button *is_backup_src = packer_ui->is_backup_src;
	Fl_Check_Button *is_retore_last = packer_ui->is_retore_last;

	mxml_node_t *xml;
	mxml_node_t *group;
	mxml_node_t *node;

	const char* old_xmlstr;

	if (1)
	{
		xml = mxmlLoadString(NULL, old_xmlstr, MXML_TEXT_CALLBACK);
	}
	else
	{
		xml = mxmlNewXML("1.0");

		group = mxmlNewElement(xml, "extra_options");
		add_item(group, "is_cover_source", NULL, is_cover_src->value()?"true":"false");
		add_item(group, "is_backup_source", NULL, is_backup_src->value()?"true":"false");
		add_item(group, "is_restore_setting", NULL, is_retore_last->value()?"true":"false");

		group = mxmlNewElement(xml, "app_solutions");

	}


	node = mxmlNewElement(group, "email");	mxmlNewText(node, 0, "author@youremail.com");

	mxmlSetWrapMargin(2);
	char* result = mxmlSaveAllocString(xml, whitespace_cb);
	mxmlDelete(xml);
}

void when_add_plugin_pattern(Fl_Widget* sender, void* param)
{
	Packer* packer_ui = (Packer*)param;
	Fl_Check_Browser* plugin_apps = packer_ui->plugin_apps;
	Fl_Input* input_text = packer_ui->add_pluginapp_text;

	const char* input_str = input_text->value();

	if (input_str)
	{
		plugin_apps->add(input_str);
		input_text->value(NULL);
		plugin_apps->redraw();
	}
}

int main(void)
{
	//asm ("int $3\n\t" :::);

	Packer *packer_ui = new Packer();

	//第一次运行，初始化"依赖表"
	set_plugin_list(packer_ui->plugin_list);
	init_dependent_list(packer_ui->plugin_list);
	init_solution_setting(packer_ui);

	packer_ui->select_path->callback(when_pick_a_path, (void*)packer_ui);
	packer_ui->ok_button->callback(when_submit_pack, (void*)packer_ui);
	packer_ui->plugin_list->callback(when_click_plugin, (void*)packer_ui);
	packer_ui->plugin_list->when(FL_WHEN_RELEASE_ALWAYS);
	packer_ui->add_pluginapp_button->callback(when_add_plugin_pattern, (void*)packer_ui);

	Fl::run();
}
