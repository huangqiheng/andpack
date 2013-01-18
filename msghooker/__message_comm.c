#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "message_comm.h"

#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))
#define default_prefix_name "Local\\thread_message-"
#define WAIT_QUEUE_MSG (WM_USER + 0xffff)

typedef struct 
{
	DWORD last_active_tick;
	char data[0];
} __attribute__ ((packed, aligned(1))) cell_data_head;

typedef struct 
{
	int size;
	int shutdown;
	DWORD thread_id;
	DWORD msg_timeout;
	HANDLE mutex_handle;
	short cells_count;
	int cell_size;
	short wait_count;
	int cell_item_size;

	//操作2个栈结构的互斥对象
	int stack_mutex_name_offset;

	//操作“容器”栈的变量
	int stack_base_offset;
	int cells_base_offset;
	int stack_top_index;

	//操作“等待室”的变量
	int wait_base_offset;
	int wait_cell_offset;
	int wait_stack_top;
	char buffer[0];
} __attribute__ ((packed, aligned(1))) MAPVIEW_HEADER;

typedef struct _WAIT_ITEM
{
	struct _WAIT_ITEM* pre;
	struct _WAIT_ITEM* next;
	int wait_cell_index;
	ATOM event_atom;
} WAIT_ITEM;

typedef struct _EVENT_ITEM
{
	struct _EVENT_ITEM *next;
	unsigned int cmd_type;
	fn_msg_recevier msg_cb;
} EVENT_ITEM;

typedef struct _NAME_TO_MAPVIEW
{
	struct _NAME_TO_MAPVIEW *next;
	char* msg_name_ori;
	HANDLE file_map;
	HANDLE mutex;
	int is_access_deny;
	MAPVIEW_HEADER *msg_mapview;
} NAME_TO_MAPVIEW;

typedef struct _MSG_THREAD_DATA{
	EVENT_ITEM 	*server_msg_event_head;
	NAME_TO_MAPVIEW *client_name_map_head;
	DWORD thread_id;
	struct _MSG_THREAD_DATA *next;
} MSG_THREAD_DATA;

DWORD msg_thread_tls = TLS_OUT_OF_INDEXES;
CRITICAL_SECTION msg_thread_cs;
MSG_THREAD_DATA* thread_chain = NULL;

static char* DbgPrint(const char* format, ...)
{       
#ifdef debug_print
	static char DbgMsg[0x1000]; 
        if (format)
        {
                va_list args;
                va_start(args, format);
                wvsprintfA(DbgMsg, format, args);
                va_end(args);
                OutputDebugStringA(DbgMsg);
        }
        return DbgMsg;
#else
	return NULL;
#endif
}

sizevoid message_exit(char* err_title, char* err_msg)
{
	MessageBoxA(0,err_msg,err_title,MB_OK | MB_ICONERROR);
	ExitProcess(0);
}

void walk_clean_thread_chain()
{
	if (thread_chain)
	{
		MSG_THREAD_DATA* scan = thread_chain;
		HANDLE hThread;
		DWORD exit_code;
		MSG_THREAD_DATA* pre_item = NULL;
		int item_deleted;

		do
		{
			item_deleted = 0;
			HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,FALSE,scan->thread_id); 
			if (GetExitCodeThread(hThread, &exit_code))
			{
				if (exit_code != STILL_ACTIVE)
				{
					//处理scan的资源,主要是客户的的资源
					//如果是服务器，它们已经自己清理了资源
					NAME_TO_MAPVIEW *mapper = scan->client_name_map_head;

					while(mapper)
					{
						DbgPrint("%d clean \"%s\" of thread %d", GetCurrentThreadId(), mapper->msg_name_ori, scan->thread_id);
						ReleaseMutex(mapper->mutex);
						CloseHandle(mapper->mutex);
						UnmapViewOfFile(mapper->msg_mapview);
						CloseHandle(mapper->file_map);

						NAME_TO_MAPVIEW *next = mapper->next;
						free(mapper->msg_name_ori);
						free(mapper);
						mapper = next;
					}

					//删除节点，如果是头节
					EnterCriticalSection(&msg_thread_cs);
					if (pre_item == NULL)
					{
						thread_chain = scan->next;
					}
					else
					{
						pre_item->next = scan->next;
					}
					LeaveCriticalSection(&msg_thread_cs);

					free(scan);
					item_deleted = 1;
				}
			}
			CloseHandle(hThread);

			if (item_deleted == 0)
			{
				pre_item = scan;
			}
		} while(scan = scan->next);
	}
}


long new_thread_counter = 0;

void init_tls_variable()
{
	//整个进程，只运行一次
	if (msg_thread_tls == TLS_OUT_OF_INDEXES)
	{
		InitializeCriticalSection(&msg_thread_cs);
		msg_thread_tls = TlsAlloc();

		if (msg_thread_tls == TLS_OUT_OF_INDEXES)
		{
			message_exit("out of indexes!" ,"can't alloc tls variable!");
		}
	}

	//每个线程，只运行一次
	if (TlsGetValue(msg_thread_tls) == NULL)
	{
		MSG_THREAD_DATA *thread_data = calloc(1, sizeof(MSG_THREAD_DATA));

		if (!TlsSetValue(msg_thread_tls, thread_data))
		{
			message_exit("TlsSetValue err!", "can't set tls variable!");
		}

		thread_data->thread_id = GetCurrentThreadId();

		EnterCriticalSection(&msg_thread_cs);
		thread_data->next = thread_chain;
		thread_chain = thread_data;
		LeaveCriticalSection(&msg_thread_cs);

		//每10个线程，清理一次
		long now_count = InterlockedIncrement(&new_thread_counter);
		if (now_count % 10 == 0)
		{
			DbgPrint("clean thread tls data %d", now_count);
			walk_clean_thread_chain();
		}
	}
}

MSG_THREAD_DATA* get_thread_data()
{
	init_tls_variable();
	return (MSG_THREAD_DATA*)TlsGetValue(msg_thread_tls);
}

int thread_msg_event(unsigned int cmd_type, fn_msg_recevier msg_cb)
{
	if (cmd_type == WAIT_QUEUE_MSG)
	{
		return (0);
	}

	EVENT_ITEM* new_item = malloc(sizeof(EVENT_ITEM));
	new_item->cmd_type = cmd_type;
	new_item->msg_cb = msg_cb;

	MSG_THREAD_DATA *thread_data = get_thread_data();

	if (thread_data->server_msg_event_head == NULL)
	{
		new_item->next = NULL;
		thread_data->server_msg_event_head = new_item;
		return (1);
	}

	new_item->next = thread_data->server_msg_event_head;
	thread_data->server_msg_event_head = new_item;
	return (1);
}

char* gen_guid_str()
{
	GUID guid;
	unsigned char* strguid = NULL;

	if (S_OK == CoCreateGuid(&guid))
	{
		if (RPC_S_OK == (UuidToString(&guid, &strguid)))
		{
			char* ret_str = strdup(strguid);
			RpcStringFree(&strguid);
			return (ret_str);
		}
	}
	DbgPrint("can't gen guid string");
	return (NULL);
}

static long round_align(long val, long alignment)
{
	if( val % alignment )
	{
		return (val + (alignment - (val % alignment)));
	}
	return val;
}

void push_cell_index(MAPVIEW_HEADER* mapview, HANDLE mutex, int cell_index)
{
	if (cell_index < 0)
	{
		return;
	}

	if (WAIT_OBJECT_0 == WaitForSingleObject(mutex, INFINITE))
	{
		LPWORD stack_item = (LPWORD)RVATOVA(mapview, mapview->stack_base_offset);
		stack_item[++mapview->stack_top_index] = cell_index;
		//DbgPrint("push index: %d, current stack: %d", cell_index, mapview->stack_top_index);

		if (!ReleaseMutex(mutex))
		{
			DbgPrint("ReleaseMutex error: %x", mutex);
		}
	}
	else
	{
		DbgPrint("push_cell_index:: WaitForSingleObject(%x) error: %d", mutex, GetLastError());
	}
}

int pop_cell_index(MAPVIEW_HEADER* mapview, HANDLE mutex)
{
	int ret_index = -1;

	if (WAIT_OBJECT_0 != WaitForSingleObject(mutex, INFINITE))
	{
		DbgPrint("WaitForSingleObject error: %x", mutex);
		return (ret_index);
	}

	if (mapview->stack_top_index >= 0)
	{
		LPWORD stack_item = (LPWORD)RVATOVA(mapview, mapview->stack_base_offset);
		ret_index = stack_item[mapview->stack_top_index--];
		DbgPrint("simple pop index: %d, current stack: %d", ret_index, mapview->stack_top_index);
	}
	else
	{
		DbgPrint("can't simple get wait a index from stack: %d", mapview->stack_top_index);
	}

	if (!ReleaseMutex(mutex))
	{
		DbgPrint("ReleaseMutex error: %x", mutex);
	}

	return (ret_index);
}


cell_data_head* pop_cell_data(MAPVIEW_HEADER* mapview, HANDLE mutex, int* index)
{
	cell_data_head* ret_result = NULL;
	if (mapview->shutdown)
	{
		return (ret_result);
	}

	*index = -1;
	int need_wait = 0;
	int wait_cell_index;

	if (WAIT_OBJECT_0 != WaitForSingleObject(mutex, INFINITE))
	{
		DbgPrint("WaitForSingleObject error: %x", mutex);
		return (ret_result);
	}

	if (mapview->stack_top_index >= 0)
	{
		LPWORD stack_item = (LPWORD)RVATOVA(mapview, mapview->stack_base_offset);
		int cell_index = stack_item[mapview->stack_top_index--];
		int cell_offset = mapview->cells_base_offset + cell_index * mapview->cell_item_size;
		ret_result = (cell_data_head*)RVATOVA(mapview, cell_offset);
		*index = cell_index;
		//DbgPrint("pop index: %d, current stack: %d", cell_index, mapview->stack_top_index);
	}
	else
	{
		if (mapview->wait_stack_top >= 0)
		{
			need_wait = 1;
			LPWORD wait_item = (LPWORD)RVATOVA(mapview, mapview->wait_base_offset);
			wait_cell_index = wait_item[mapview->wait_stack_top--];
			DbgPrint("-- pop wait:%d, current stack:%d", wait_cell_index, mapview->wait_stack_top); 
		}
		else
		{
			DbgPrint("can't get/wait a index from stack: %d", mapview->stack_top_index);
		}
	}

	if (!ReleaseMutex(mutex))
	{
		DbgPrint("ReleaseMutex error: %x", mutex);
	}

	if (need_wait)
	{
		char* guid_str = gen_guid_str();
		char event_name[MAX_PATH];
		sprintf(event_name, "%s%s", default_prefix_name, guid_str);
		free(guid_str);

		SECURITY_ATTRIBUTES sa;
		SECURITY_DESCRIPTOR sd;
		InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
		sa.lpSecurityDescriptor = &sd;
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = FALSE;

		HANDLE event_handle = NULL;
		ATOM atom = 0;

		do
		{
			if ((event_handle = CreateEvent(&sa, FALSE, FALSE, event_name)) == NULL)
			{
				DbgPrint("CreateEvent error: %s", event_name);
				break;
			}

			if ((atom = GlobalAddAtom(event_name)) == 0)
			{
				DbgPrint("GlobalAddAtom error: %s", event_name);
				break;
			}

			if (!PostThreadMessage(mapview->thread_id, WAIT_QUEUE_MSG, (WPARAM)atom, wait_cell_index))
			{
				DWORD last_err = GetLastError();
				if (last_err == ERROR_INVALID_THREAD_ID)
				{
					mapview->shutdown = 1;
					DbgPrint("pop_cell_data: PostThreadMessage == ERROR_INVALID_THREAD_ID, set shutdown.");
				}
				else
				{
					DbgPrint("pop_cell_data: PostThreadMessage error: %d", last_err);
				}
				break;
			}

			if (WAIT_OBJECT_0 != WaitForSingleObject(event_handle, INFINITE)) 
			{
				DbgPrint("WaitForSingleObject 1 error: %x", event_handle);
				break;
			}

			LPWORD wait_item = (LPWORD)RVATOVA(mapview, mapview->wait_base_offset);
			LPWORD wait_cell = (LPWORD)RVATOVA(mapview, mapview->wait_cell_offset);
			int cell_index = wait_cell[wait_cell_index];
			int cell_offset = mapview->cells_base_offset + cell_index * mapview->cell_item_size;
			ret_result = (cell_data_head*)RVATOVA(mapview, cell_offset);
			*index = cell_index;
			DbgPrint("wait pop index: %d, current stack: %d", cell_index, mapview->stack_top_index);

			//上面已经优先得到了从服务器来的cell_index
			//下面要归还wait_item

			if (WAIT_OBJECT_0 == WaitForSingleObject(mutex, INFINITE))
			{
				wait_item[++mapview->wait_stack_top] = wait_cell_index;
				DbgPrint("-- push wait:%d, current stack:%d", wait_cell_index, mapview->wait_stack_top); 
			}
			else
			{
				//无论何时出现，这都是一个严重的异常
				DbgPrint("WaitForSingleObject 2 error: %x", mutex);
			}

			if (!ReleaseMutex(mutex))
			{
				DbgPrint("ReleaseMutex error: %x", mutex);
			}

		} while (0);

		if (atom)
		{
			GlobalDeleteAtom(atom);
		}
		if (event_handle)
		{
			CloseHandle(event_handle);
		}
	}

	return (ret_result);
}

int reply_wait_item(MAPVIEW_HEADER* mapview, ATOM atom,int wait_cell_index, int cell_index)
{
	char atom_event_name[MAX_PATH];

	if (GlobalGetAtomName(atom, atom_event_name, MAX_PATH))
	{
		HANDLE event_handle;
		if (event_handle = OpenEvent(EVENT_MODIFY_STATE, FALSE, atom_event_name))
		{
			//填入客户端期待的wait_cell中
			LPWORD wait_cell = (LPWORD)RVATOVA(mapview, mapview->wait_cell_offset);
			wait_cell[wait_cell_index] = cell_index;

			//通知了客户端直接来取，就越过了“归还”流程
			SetEvent(event_handle);
			CloseHandle(event_handle);
			return (1);
		}
		else
		{
			DbgPrint("OpenEvent error:(%d) %s",GetLastError(),atom_event_name);
		}
	}
	else
	{
		DbgPrint("GlobalGetAtomName error:(%d) %d",GetLastError(),atom);
	}
	return (0);
}

void thread_msg_init()
{
	MSG msg_init;
	PeekMessage(&msg_init, NULL, WM_USER, WM_USER, PM_NOREMOVE);
}

int thread_msg_looper(char* msg_name, int cell_size, short cell_count, short wait_count, DWORD msg_timeout)
{
	//初始化消息队列
	thread_msg_init();

	MSG_THREAD_DATA *thread_data = get_thread_data();

	int map_size = sizeof(MAPVIEW_HEADER)
			+ cell_count * (sizeof(WORD) + sizeof(cell_data_head)+cell_size) 
			+ wait_count * (sizeof(WORD)*2)
			+ 0x10;
	map_size = round_align(map_size, 0x1000);

	char map_name[MAX_PATH];
	sprintf(map_name, "%s%s", default_prefix_name, msg_name);

	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.lpSecurityDescriptor = &sd;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;

	HANDLE file_map = CreateFileMapping(INVALID_HANDLE_VALUE,&sa,PAGE_READWRITE|SEC_COMMIT,0,map_size,map_name);

	if (file_map == NULL)
	{
		printf("CreateFileMapping error: %d\n", GetLastError());
		message_exit("fatal error", "CreateFileMapping error, process exit");
	}

	MAPVIEW_HEADER* mapview = (MAPVIEW_HEADER*)MapViewOfFile(file_map,FILE_MAP_ALL_ACCESS,0,0,0);

	if (mapview == NULL)
	{
		message_exit("fatal error", "MapViewOfFile error, process exit");
	}

	char* guid_name = gen_guid_str();
	char mutex_name[MAX_PATH];
	sprintf(mutex_name, "%s%s", default_prefix_name, guid_name);
	free(guid_name);

	mapview->size = map_size;
	mapview->msg_timeout = msg_timeout;
	mapview->thread_id = GetCurrentThreadId();
	mapview->cells_count = cell_count;
	mapview->cell_size = cell_size;
	mapview->cell_item_size = cell_size + sizeof(cell_data_head);

	int mutex_len = strlen(mutex_name);
	strcpy(&mapview->buffer[0], mutex_name);
	mapview->stack_mutex_name_offset = (int)(&mapview->buffer[0]) - (int)mapview;
	mapview->stack_base_offset = mapview->stack_mutex_name_offset + mutex_len + 1;
	mapview->stack_base_offset = round_align(mapview->stack_base_offset, sizeof(int));
	mapview->cells_base_offset = mapview->stack_base_offset + sizeof(WORD)*cell_count;
	mapview->stack_top_index = mapview->cells_count-1;

	mapview->wait_count = wait_count;
	mapview->wait_base_offset = mapview->cells_base_offset + mapview->cell_item_size*cell_count;
	mapview->wait_cell_offset = mapview->wait_base_offset + sizeof(WORD)*wait_count;
	mapview->wait_stack_top = wait_count-1; 

	int i;
	LPWORD stack_item = (LPWORD)RVATOVA(mapview, mapview->stack_base_offset);
	for (i=0; i<mapview->cells_count; i++)
	{
		stack_item[i] = i;
	}

	LPWORD wait_item = (LPWORD)RVATOVA(mapview, mapview->wait_base_offset);
	for (i=0; i<mapview->wait_count; i++)
	{
		wait_item[i] = i;
	}

	WAIT_ITEM* wait_queue_head = NULL;
	WAIT_ITEM* wait_queue_tail = NULL;
	mapview->mutex_handle = CreateMutex(NULL, FALSE, mutex_name);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		//进入等待队列中
		if (msg.message == WAIT_QUEUE_MSG)
		{
			ATOM atom = (ATOM)msg.wParam;
			int wait_cell_index = msg.lParam;

			//进入队列之前，可能stack中已经有了“之前没有的空位”
			int cell_index = pop_cell_index(mapview, mapview->mutex_handle);

			//找到空位了,马上给你解决
			if (cell_index != -1)
			{
				if (reply_wait_item(mapview, atom, wait_cell_index, cell_index))
				{
					DbgPrint("instance reply a wait:%d val:%d", wait_cell_index, cell_index);
				}
			}
			else
			{
				//没找到？进入队列再等等
				WAIT_ITEM* new_item = malloc(sizeof(WAIT_ITEM));
				new_item->next = wait_queue_head;
				new_item->pre = NULL;
				new_item->event_atom = atom;
				new_item->wait_cell_index = wait_cell_index;

				DbgPrint("enqueue a wait: %d", wait_cell_index);

				//如果是空列表的第一个元素
				if (wait_queue_head == NULL)
				{
					wait_queue_tail = new_item;
				}
				else
				{
					wait_queue_head->pre = new_item;
				}

				wait_queue_head = new_item;
			}

			continue;
		}

		//调用回调函数，处理到来消息
		EVENT_ITEM* event_head = thread_data->server_msg_event_head;

		for (; event_head; event_head = event_head->next)
		{
			if (event_head->cmd_type == msg.message)
			{
				int cell_index = msg.wParam;
				int data_size = msg.lParam;
				int cell_offset = mapview->cells_base_offset + cell_index * mapview->cell_item_size;
				cell_data_head* cell_data = (cell_data_head*)RVATOVA(mapview, cell_offset);

				//处理该消息
				if ((GetTickCount() - cell_data->last_active_tick) <= mapview->msg_timeout)
				{
					event_head->msg_cb(&cell_data->data[0], data_size);
				}

				//归还cell_index前，先检查一下等待队列
				//如果有人在等待，优先给它
				if (wait_queue_tail)
				{
					WAIT_ITEM* pop_item = wait_queue_tail;

					//如果是列表中的最后一个元素
					if (pop_item->pre == NULL)
					{
						wait_queue_head = NULL;
					}
					else
					{	
						pop_item->pre->next = NULL;
					}
					wait_queue_tail = pop_item->pre;

					DbgPrint("dequeue a wait: %d", pop_item->wait_cell_index);

					//上面已经取出元素并维护了链表
					//下面可以回应客户端了

					if (reply_wait_item(mapview, pop_item->event_atom, pop_item->wait_cell_index, cell_index))
					{
						free(pop_item);
						break;
					}

					free(pop_item);
				}

				//归还cell_index
				push_cell_index(mapview, mapview->mutex_handle, cell_index);
				break;
			}
		}
	}


	//这是“关闭服务”标志
	mapview->shutdown = 1;

	//清理回调函数链表
	EVENT_ITEM* event_head = thread_data->server_msg_event_head;
	while(event_head)
	{
		EVENT_ITEM* next = event_head->next;
		free(event_head);
		event_head = next;
	}
	thread_data->server_msg_event_head = NULL;

	//清理mutex资源
	ReleaseMutex(mapview->mutex_handle);
	CloseHandle(mapview->mutex_handle);
	mapview->mutex_handle = NULL;

	//清理内存映射资源
	UnmapViewOfFile(mapview);
	CloseHandle(file_map);

	return (1);
}

int report_once_OpenFileMapping = 0;

NAME_TO_MAPVIEW* create_new_mapview(char* msg_name)
{
	char map_name[MAX_PATH];
	sprintf(map_name, "%s%s", default_prefix_name, msg_name);

	HANDLE file_map = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, map_name);

	if (file_map == NULL)
	{
		if (report_once_OpenFileMapping++ == 0)
		{
			DbgPrint("can't OpenFileMapping: %s, err:%d", map_name, GetLastError());
		}
		return (NULL);
	}

	MAPVIEW_HEADER* mapview = (MAPVIEW_HEADER*)MapViewOfFile(file_map, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (mapview == NULL)
	{
		DbgPrint("can't MapViewOfFile: %d, err:%d", file_map, GetLastError());
		CloseHandle(file_map);
		return (NULL);
	}

	if (mapview->shutdown)
	{
		DbgPrint("i don't wana to MapViewOfFile a shutdown mapview: %s, err:%d", map_name, GetLastError());
		UnmapViewOfFile(mapview);
		CloseHandle(file_map);
		return (NULL);
	}

	NAME_TO_MAPVIEW *new_item = (NAME_TO_MAPVIEW*)malloc(sizeof(NAME_TO_MAPVIEW));

	if (new_item == NULL)
	{
		message_exit("fatal error", "out of memory!");
	}

	new_item->msg_name_ori = strdup(msg_name);
	new_item->msg_mapview = mapview;
	new_item->file_map = file_map;
	new_item->is_access_deny = FALSE;

	char* mutex_name = (char*)RVATOVA(mapview, mapview->stack_mutex_name_offset);
	new_item->mutex = OpenMutex(SYNCHRONIZE, FALSE, mutex_name);

	if (new_item->mutex == NULL)
	{
		UnmapViewOfFile(mapview);
		CloseHandle(file_map);
		DbgPrint("can't OpenMutex: %s, err:%d", mutex_name, GetLastError());
		return (NULL);
	}

	new_item->next = NULL;

	return (new_item);
}


NAME_TO_MAPVIEW* name_to_mapview(MSG_THREAD_DATA *thread_data, char* msg_name)
{
	NAME_TO_MAPVIEW* name_map_scan = thread_data->client_name_map_head;

	if (name_map_scan == NULL)
	{
		name_map_scan = create_new_mapview(msg_name);
		if (name_map_scan == NULL)
		{
			return (NULL);
		}

		thread_data->client_name_map_head = name_map_scan;
		return (name_map_scan);
	}

	for (; name_map_scan; name_map_scan = name_map_scan->next)
	{
		if (!stricmp(name_map_scan->msg_name_ori, msg_name))
		{
			return (name_map_scan);
		}
	}

	name_map_scan = create_new_mapview(msg_name);
	if (name_map_scan == NULL)
	{
		DbgPrint("continue create_new_mapview error: %s", msg_name);
		return (NULL);
	}

	name_map_scan->next = thread_data->client_name_map_head;
	thread_data->client_name_map_head = name_map_scan;
	return (name_map_scan);
}

int report_once_access_deny = 0;

int  thread_msg_post(char* msg_name, unsigned int cmd_type, void* msg_data, int msg_size)
{
	int ret_result = 0;
	WPARAM wParam = 0;
	LPARAM lParam = (LPARAM)msg_size;

	NAME_TO_MAPVIEW* client_mapper = name_to_mapview(get_thread_data(), msg_name);

	if (client_mapper == NULL)
	{
		return (ret_result);
	}

	if (client_mapper->is_access_deny == TRUE)
	{
		if (report_once_access_deny++ == 0)
		{
			DbgPrint("msg_name:%s dany by somewhere in my process", msg_name);
		}

		return (ret_result);
	}

	MAPVIEW_HEADER* mapview = client_mapper->msg_mapview;

	if (mapview == NULL)
	{
		return (ret_result);
	}

	if (mapview->shutdown)
	{
		return (ret_result);
	}
	
	if (msg_size > 0)
	{
		int cell_index;
		cell_data_head* cell_data;

		if (cell_data = pop_cell_data(mapview, client_mapper->mutex, &cell_index))
		{
			cell_data->last_active_tick = GetTickCount();
			memcpy(&cell_data->data[0], msg_data, msg_size);
			cell_data->data[msg_size] = '\0';

			wParam = (WPARAM)cell_index;

			if (PostThreadMessage(mapview->thread_id, cmd_type, wParam, lParam))
			{
				return (1);
			}
			else
			{
				DWORD last_err = GetLastError();

				//访问拒绝？
				if (last_err == ERROR_ACCESS_DENIED)
				{
					DbgPrint("PostThreadMessage(%d) error: %d, set is_access_deny=TRUE", mapview->thread_id, last_err);
					client_mapper->is_access_deny = TRUE;

					//既然投递不了，回收资源
					push_cell_index(mapview, client_mapper->mutex, cell_index);
				}
				else

				//服务器线程已经死了，可以清除mapview了
				if (last_err == ERROR_INVALID_THREAD_ID)
				{
					DbgPrint("PostThreadMessage(%d) error: %d, server is dead, set is_access_deny=TRUE", mapview->thread_id, last_err);
					client_mapper->is_access_deny = TRUE;
					thread_msg_close_client(msg_name);
				}
				else
				{
					DbgPrint("PostThreadMessage error: %d", last_err);
				}
			}
		}
		else
		{
			DbgPrint("pop_cell_data error: %d", cell_index);
		}
	}
	else
	{
		wParam = (WPARAM)msg_data;
		ret_result = PostThreadMessage(mapview->thread_id, cmd_type, wParam, lParam);
	}

	return (ret_result);
}

int  thread_msg_post_str(char* msg_name, unsigned int cmd_type, char* str)
{
	int data_size = strlen(str) + 1;
	return thread_msg_post(msg_name, cmd_type, str, data_size);
}


int  thread_msg_close(char* msg_name)
{
	NAME_TO_MAPVIEW* client_mapper = name_to_mapview(get_thread_data(), msg_name);

	if ((client_mapper == NULL) || (client_mapper->msg_mapview == NULL))
	{
		DbgPrint("name_to_mapview error: %s", msg_name);
		return (0);
	}

	if (!PostThreadMessage(client_mapper->msg_mapview->thread_id, WM_QUIT, 0, 0))
	{
		DbgPrint("PostThreadMessage error: %d", GetLastError());
		return (0);
	}

	return (thread_msg_close_client(msg_name));
}

int thread_msg_close_client(char* msg_name)
{
	if (msg_name == NULL)
	{
		return (0);
	}

	if (TlsGetValue(msg_thread_tls) == 0)
	{
		return (0);
	}

	MSG_THREAD_DATA *thread_data = get_thread_data();
	if (thread_data == NULL)
	{
		return (0);
	}

	NAME_TO_MAPVIEW *mapper = thread_data->client_name_map_head;
	NAME_TO_MAPVIEW* pre = NULL;
	NAME_TO_MAPVIEW *next;

	while(mapper)
	{
		next = mapper->next;
		if (!stricmp(mapper->msg_name_ori, msg_name))
		{
			DbgPrint("tid:%d  clean:\"%s\"", GetCurrentThreadId(), mapper->msg_name_ori);
			ReleaseMutex(mapper->mutex);
			CloseHandle(mapper->mutex);
			UnmapViewOfFile(mapper->msg_mapview);
			CloseHandle(mapper->file_map);
			free(mapper->msg_name_ori);
			free(mapper);

			//如果是第一个节
			if (pre == NULL)
			{
				thread_data->client_name_map_head = next;
			}
			else
			{
				pre->next = next;
			}
			return (1);
		}
		pre = mapper;
		mapper = next;
	}
	return (0);
}
