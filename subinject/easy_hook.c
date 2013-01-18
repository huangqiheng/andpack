#include <windows.h>

typedef HMODULE (*LPFN_Hook_InlineHookInstall)(void* fnHookFrom, void* fnHookTo);
typedef void*   (*LPFN_Hook_InlineHookGetOri)(HMODULE hHooker);
typedef void    (*LPFN_Hook_InlineHookRemove)(HMODULE hHooker);
LPFN_Hook_InlineHookInstall Hook_InlineHookInstall;
LPFN_Hook_InlineHookGetOri Hook_InlineHookGetOri;
LPFN_Hook_InlineHookRemove Hook_InlineHookRemove;

HMODULE hCodeTrick = NULL;

int init_hooker()
{
        if (!hCodeTrick) 
	{
            if (hCodeTrick = LoadLibrary("codetrick.dll")) 
	    {
		Hook_InlineHookInstall = (LPFN_Hook_InlineHookInstall)GetProcAddress(hCodeTrick, "Hook_InlineHookInstall");
		Hook_InlineHookGetOri = (LPFN_Hook_InlineHookGetOri)GetProcAddress(hCodeTrick, "Hook_InlineHookGetOri");
		Hook_InlineHookRemove = (LPFN_Hook_InlineHookRemove)GetProcAddress(hCodeTrick, "Hook_InlineHookRemove");
		return (1);
	    }
	}
	return (Hook_InlineHookInstall != NULL);
}


struct HOOK_LIST
{
	char dll_name[16];
	char fun_name[32];
	HMODULE dll_handle;
	void* fun_entry;
	HMODULE hook_handle;
	void* real_entry;
	void* hooker;
	struct HOOK_LIST* next;
};

struct HOOK_LIST* hook_list_head = NULL;

int easy_hook_clean(void* hooker)
{
	/*
	第一次运行会初始化hooker库
	*/
	init_hooker();
	struct HOOK_LIST *next_item,*pre_item;
	struct HOOK_LIST* hook_item = hook_list_head;


	/*
	检查这个函数是否被hook过，如果有，直接删除
	如果hooker为空，则表示删除所有的hook
	*/
	pre_item = NULL;
	while (hook_item)
	{
		next_item = hook_item->next;
		if (hooker)
		{
			if (hook_item->hooker == hooker)
			{
				Hook_InlineHookRemove(hook_item->hook_handle);
				FreeLibrary(hook_item->dll_handle);
				//特别处理头节的情况
				if (pre_item)
				{
					pre_item->next = next_item;
				}
				else
				{
					hook_list_head = next_item;
				}
				free(hook_item);
				return (1);
			}
		}
		else
		{
			//先将头节清空了无妨
			if (pre_item == NULL)
			{
				hook_list_head = NULL;
			}
			//回收资源，FreeLibrary有计数的
			Hook_InlineHookRemove(hook_item->hook_handle);
			FreeLibrary(hook_item->dll_handle);
			free(hook_item);
		}
		pre_item = hook_item;
		hook_item = next_item;
	}


	/*
	根据情况返回
	如果是全清除，会总是返回成功
	*/
	return (hooker)? 0 : 1;
}

void* easy_hook_install(char* dll_name, char* fun_name, void* hooker)
{
	/*
	第一次运行会初始化hooker库
	*/
	init_hooker();
	struct HOOK_LIST* hook_list = hook_list_head;
	struct HOOK_LIST* target_item = NULL;


	/*
	检查这个函数是否被hook过，如果有，直接取出返回。
	如果没有，则表明还没处理。
	*/
	while (hook_list)
	{
		if (stricmp(dll_name, hook_list->dll_name) == 0)
		{
			if (stricmp(fun_name, hook_list->fun_name) == 0)
			{
				if (hook_list->real_entry)
				{
					return hook_list->real_entry;
				}
				target_item = hook_list;
				break;
			}
		}
		hook_list = hook_list->next;
	}
	

	/*
	如果不在列表中，但是，调用者却没有提供hooker指针，
	也就是说，调用并不想安装新的hook，所以只需直接返回。
	*/
	if (hooker == NULL)
		return (NULL);


	/*
	如果在列表中没有发现节点，则需要新分配一个
	并加入到链表中
	*/
	if (target_item == NULL)
	{
		target_item = malloc(sizeof(struct HOOK_LIST));
		strcpy(target_item->dll_name, dll_name);
		strcpy(target_item->fun_name, fun_name);
		target_item->next = NULL;
		//添加到链表末尾
		if (hook_list_head == NULL)
		{
			hook_list_head = target_item;
		}
		else
		{
			hook_list = hook_list_head;
			while (hook_list->next)
				hook_list = hook_list->next;
			hook_list->next = target_item;
		}
	}


	/*
	填充剩下的数据
	对指定的函数打api hook
	*/
	target_item->dll_handle = LoadLibrary(target_item->dll_name);
	target_item->fun_entry = GetProcAddress(target_item->dll_handle, target_item->fun_name);
	target_item->hooker = hooker;
	target_item->hook_handle = Hook_InlineHookInstall(target_item->fun_entry, target_item->hooker);
	target_item->real_entry = Hook_InlineHookGetOri(target_item->hook_handle);
	return (target_item->real_entry);
}
