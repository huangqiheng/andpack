#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include "sync_funcs.h"

#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))

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

static long round_align(long val, long alignment)
{
	if( val % alignment )
	{
		return (val + (alignment - (val % alignment)));
	}
	return val;
}

#define sign_string "namedmemory"

typedef struct __sign_end
{
	char null[MAX_PATH];
	DWORD sign_a;
	DWORD sign_b;
	DWORD owner_pid;
	HANDLE file_map_handle;
	void* map_base;
	size_t map_size;
	size_t ori_size;
	char file_map_name[MAX_PATH];
} sign_end;

HANDLE create_readwrite_maping(const char* full_name, size_t map_size)
{
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.lpSecurityDescriptor = &sd;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;
	return CreateFileMapping(INVALID_HANDLE_VALUE,&sa,PAGE_READWRITE|SEC_COMMIT,0,map_size,full_name);
}

sign_end* find_sign_end(void* address)
{
	char* signstr = sign_string;
	DWORD sign_a = *(LPDWORD)&signstr[0];
	DWORD sign_b = *(LPDWORD)&signstr[sizeof(DWORD)];
	sign_end* scan_addr = (sign_end*)round_align((DWORD)address, 0x1000);

	do
	{
		if (scan_addr->sign_a == sign_a)
		{
			if (scan_addr->sign_b == sign_b)
			{
				break;
			}
		}
		scan_addr = (sign_end*)((DWORD)scan_addr + 0x1000);
	} while (TRUE);

	return (scan_addr);
}

typedef struct __client_block
{
	struct __client_block* next;
	char* client_name;
	
	HANDLE client_file_map;
	void* client_map_base;
	size_t client_map_size;
	size_t client_ori_size;

	HANDLE server_file_map;
	void* server_map_base;
	size_t server_map_size;
	size_t server_ori_size;
} client_block;

client_block root_client_block = {NULL};

void free_client_block(const char* full_name)
{
	if (root_client_block.next == NULL)
	{
		return;
	}

	char client_name[MAX_PATH];
	sprintf(client_name, "%s-[%s]", full_name, GetCurrentProcessId());

	client_block *pre_client = &root_client_block;
	client_block *scan_client = root_client_block.next;
	client_block *target = NULL;

	for (; scan_client; pre_client=scan_client, scan_client=scan_client->next)
	{
		if (strcmp(scan_client->client_name, client_name) == 0)
		{
			target = scan_client;
			pre_client->next = scan_client->next;
			break;
		}
	}

	if (target)
	{
		HANDLE file_map = target->client_file_map;
		void* map_base = target->client_map_base;
		UnmapViewOfFile(map_base);
		CloseHandle(file_map);
	}
	return;
}

client_block* get_client_block(const char* full_name)
{
	char client_name[MAX_PATH];
	sprintf(client_name, "%s-[client]", full_name);

	client_block* scan_client = root_client_block.next;
	for (; scan_client; scan_client=scan_client->next)
	{
		if (strcmp(scan_client->client_name, client_name) == 0)
		{
			return (scan_client->client_map_base);
		}
	}

	HANDLE file_map = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, client_name);

	int new_created = 0;
	size_t map_size = 0;
	if (file_map == NULL)
	{
		map_size = round_align(sizeof(client_block), 0x1000);
		file_map = create_readwrite_maping(client_name, map_size);
		if (file_map == NULL)
		{
			static int report_once_get_client_block = 0;
			if (report_once_get_client_block++ == 0)
			{
				DbgPrint("report_once_named_mem_open: can't OpenFileMapping %s, err:%d", client_name, GetLastError());
			}
			return (NULL);
		}
		new_created = 1;
	}

	void* mapview = MapViewOfFile(file_map, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (mapview == NULL)
	{
		DbgPrint("can't MapViewOfFile: %d, err:%d", file_map, GetLastError());
		CloseHandle(file_map);
		return (NULL);
	}

	client_block* client_item = (client_block*)mapview;

	if (new_created)
	{
		client_item->client_file_map = file_map;
		client_item->client_map_base = mapview;
		client_item->client_map_size = map_size;
		client_item->client_ori_size = sizeof(client_block);
		client_item->server_file_map = NULL;
		client_item->client_name = strdup(client_name);
		DbgPrint("new create: %s", client_item->client_name);
	}


	client_item->next = root_client_block.next; 
	root_client_block.next = client_item;
	return (client_item);
}

void* named_memory_alloc(const char* full_name, size_t size)
{
	size_t ori_size = size;
	size_t map_size = round_align(ori_size, 0x1000) + 0x1000;

	HANDLE file_map = create_readwrite_maping(full_name, map_size);
	if (file_map == NULL)
	{
		DbgPrint("CreateFileMapping error(%s): %d\n", full_name, GetLastError());
		return (NULL);
	}

	void* mapview = MapViewOfFile(file_map,FILE_MAP_ALL_ACCESS,0,0,0);
	if (mapview == NULL)
	{
		CloseHandle(file_map);
		DbgPrint("MapViewOfFile error(%s): %d\n", full_name, GetLastError());
		return (NULL);
	}

	sign_end* sign = (sign_end*)((DWORD)mapview + (DWORD)size);
	char* signstr = sign_string;
	sign->sign_a = *(LPDWORD)&signstr[0];
	sign->sign_b = *(LPDWORD)&signstr[sizeof(DWORD)];
	sign->owner_pid = GetCurrentProcessId();
	sign->file_map_handle = file_map;
	sign->map_base = mapview;
	sign->map_size = map_size;
	sign->ori_size = ori_size;
	strcpy(&sign->file_map_name[0], full_name);

	client_block* client_item = (client_block*)get_client_block(full_name);
	if (client_item == NULL)
	{
		DbgPrint("named_memory_alloc get_client_block error: %s", full_name);
		UnmapViewOfFile(mapview);
		CloseHandle(file_map);
		return (NULL);
	}

	client_item->server_file_map = sign->file_map_handle;
	client_item->server_map_base = sign->map_base;
	client_item->server_map_size = sign->map_size;
	client_item->server_ori_size = sign->ori_size;

	return (mapview);
}

void* named_memory_open(const char* full_name, size_t *size)
{
	client_block* client_item = (client_block*)get_client_block(full_name);

	if (client_item == NULL)
	{
		return (NULL);
	}

	if (client_item->server_file_map == NULL)
	{
		HANDLE file_map = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, full_name);
		if (file_map == NULL)
		{
			static int report_once_named_mem_open = 0;
			if (report_once_named_mem_open++ == 0)
			{
				DbgPrint("named_memory_open: can't OpenFileMapping %s, err:%d", full_name, GetLastError());
			}
			return (NULL);
		}

		void* mapview = MapViewOfFile(file_map, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (mapview == NULL)
		{
			DbgPrint("named_memory_open can't MapViewOfFile: %d, err:%d", file_map, GetLastError());
			CloseHandle(file_map);
			return (NULL);
		}

		sign_end* scan_addr = find_sign_end(mapview);

		client_item->server_file_map = file_map;
		client_item->server_map_base = mapview;
		client_item->server_map_size = scan_addr->map_size;
		client_item->server_ori_size = scan_addr->ori_size;
	}

	*size = client_item->server_ori_size;
	return (client_item->server_map_base);
}


void named_memory_free(const char* full_name)
{
	client_block* client =  get_client_block(full_name);
	HANDLE file_map = client->server_file_map;
	void* mapview = client->server_map_base;

	free_client_block(full_name);

	UnmapViewOfFile(mapview);
	CloseHandle(file_map);
}

typedef struct
{
	short size;
	void* addr;
	char buffer[MAX_PATH];
} __attribute__ ((packed, aligned(1))) NAME_ITEM;

typedef struct 
{
	size_t size;
	size_t used_size;
	int count;
	char buffer[MAX_PATH];
} __attribute__ ((packed, aligned(1))) ADDR_TABLE;

#define default_addrid_size 0x1000
ADDR_TABLE* addr_table_bk = NULL;
const char* addrid_mutex_format = "Local\\addrid-mutex(%d)";
char* addrid_mutex_id = NULL;

char* addrid_mutex()
{
	if (addrid_mutex_id)
	{
		return (addrid_mutex_id);
	}

	char buff[MAX_PATH];
	sprintf(buff, addrid_mutex_format, GetCurrentProcessId());
	addrid_mutex_id = strdup(buff);
	return (addrid_mutex_id);
}

ADDR_TABLE* get_addr_table()
{
	if (addr_table_bk)
	{
		return (addr_table_bk);
	}

	char name_buf[MAX_PATH];
	sprintf(name_buf, "Local\\addrid(%d)", GetCurrentProcessId());

	size_t addr_table_size;
	ADDR_TABLE* addr_table = (ADDR_TABLE*)named_memory_open(name_buf, &addr_table_size);

	if (addr_table == NULL)
	{
		addr_table_size = default_addrid_size;
		addr_table = (ADDR_TABLE*)named_memory_alloc(name_buf, addr_table_size);

		if (addr_table == NULL)
		{
			DbgPrint("named_memory_alloc error: %s", name_buf);
			return (NULL);
		}

		addr_table->size = addr_table_size;
		addr_table->used_size = 0;
		addr_table->count = 0;
	}

	addr_table_bk = addr_table;

	return (addr_table);
}

void** find_addrid(ADDR_TABLE* addr_table, const char* addr_id)
{
	NAME_ITEM* scan = (NAME_ITEM*)&addr_table->buffer[0];
	int scan_count = addr_table->count;

	for (; scan_count; scan_count--);
	{
		if (strcmp(scan->buffer, addr_id) == 0)
		{
			return &scan->addr;
		}
		scan = (NAME_ITEM*)((DWORD)scan + scan->size);
	}

	return (NULL);
}

void* __addrid(const char* addr_id)
{
	ADDR_TABLE* addr_table = get_addr_table();

	if (addr_table == NULL)
	{
		return (NULL);
	}

	void** p_addr = find_addrid(addr_table, addr_id);

	if (p_addr == NULL)
	{
		SetLastError(0xE0000000);
	}

	return (p_addr? *p_addr : NULL);
}

void* __addrid_set(const char* addr_id, void* addr)
{
	ADDR_TABLE* addr_table = get_addr_table();

	if (addr_table == NULL)
	{
		return (NULL);
	}

	void** p_addr = find_addrid(addr_table, addr_id);

	if (p_addr)
	{
		*p_addr = addr;
		return (addr);
	}

	NAME_ITEM name_item;
	name_item.size = sizeof(NAME_ITEM) - MAX_PATH + strlen(addr_id) + sizeof(char);
	name_item.addr = addr;
	strcpy(name_item.buffer, addr_id);

	if (addr_table->size - addr_table->used_size < name_item.size)
	{
		return (NULL);
	}

	memcpy(&addr_table->buffer[addr_table->used_size], &name_item, name_item.size);
	addr_table->used_size += name_item.size;
	addr_table->count++;
	return (addr);
}

void* addrid(const char* addr_id)
{
	HANDLE mutex = __enter_mutex(addrid_mutex());
	void* run_ret = __addrid(addr_id);
	__leave_mutex(mutex);
	return (run_ret);
}

void* addrid_set(const char* addr_id, void* addr)
{
	HANDLE mutex = __enter_mutex(addrid_mutex());
	void* run_ret = __addrid_set(addr_id, addr);
	__leave_mutex(mutex);
	return (run_ret);
}


void* addrid_init(const char* addr_id, lpfn_addrid_cb initer, size_t init_size)
{
	HANDLE mutex = __enter_mutex(addrid_mutex());
	void* run_ret = __addrid(addr_id);

	if (run_ret == NULL)
	{
		run_ret = calloc(init_size, sizeof(char));
		if (run_ret == NULL)
		{
			DbgPrint("addrid_init calloc: %d", GetLastError());
		}

		initer(run_ret, addr_id);
		__addrid_set(addr_id, run_ret);
	}

	__leave_mutex(mutex);
	return (run_ret);
}

#define map_local_prefix "Local\\sync_mapname-"

void* malloc_local(const char* mem_id, size_t size)
{
	char map_name[MAX_PATH];
	sprintf(map_name, "%s%s", map_local_prefix, mem_id);
	HANDLE mutex = __enter_mutex(mem_id);
	void* ret = named_memory_alloc(map_name, size);
	__leave_mutex(mutex);
	return (ret);
}

void* open_local(const char* mem_id)
{
	char map_name[MAX_PATH];
	sprintf(map_name, "%s%s", map_local_prefix, mem_id);
	int size;

	HANDLE mutex = __enter_mutex(mem_id);
	void* ret = named_memory_open(map_name, &size);
	__leave_mutex(mutex);
	return (ret);
}

void  free_local(const char* mem_id)
{
	char map_name[MAX_PATH];
	sprintf(map_name, "%s%s", map_local_prefix, mem_id);
	HANDLE mutex = __enter_mutex(mem_id);
	named_memory_free(map_name);
	__leave_mutex(mutex);
}

typedef struct __idmap_item
{
	char* item_id;
	void* item_value;
	struct __idmap_item* next;
} idmap_item;

idmap_item* get_root_idmap(const char* idmap_type)
{
	idmap_item* root_item = __addrid(idmap_type);

	if (root_item == NULL)
	{
		root_item = (idmap_item*)malloc(sizeof(idmap_item));

		if (root_item == NULL)
		{
			DbgPrint("get_root_idmap malloc: %d", GetLastError());
			return (NULL);
		}

		memset(root_item, 0, sizeof(idmap_item));
		__addrid_set(idmap_type, root_item);
	}
	return (root_item);
}

idmap_item* find_idmap_item(idmap_item* root_item, const char* item_id)
{
	if (root_item == NULL)
	{
		return (NULL);
	}

	idmap_item* scan_item = root_item->next;

	for (; scan_item; scan_item=scan_item->next)
	{
		if (strcmp(scan_item->item_id, item_id) == 0)
		{
			return scan_item;
		}
	}
	return (NULL);
}

void* __addrid_group(const char* item_id_group, const char* item_id)
{
	idmap_item* root_item = get_root_idmap(item_id_group);
	idmap_item* target_item = find_idmap_item(root_item, item_id);

	if (target_item)
	{
		return (target_item->item_value);
	}
	else
	{
		SetLastError(0xF0000000);
		return (NULL);
	}
}

void* __addrid_group_set(const char* item_id_group, const char* item_id, void* addr)
{
	idmap_item* root_item = get_root_idmap(item_id_group);

	idmap_item* target_item = find_idmap_item(root_item, item_id);

	if (target_item == NULL)
	{
		target_item = malloc(sizeof(idmap_item));

		if (target_item == NULL)
		{
			DbgPrint("addrid_group_set malloc: %d", GetLastError());
			return (NULL);
		}

		target_item->item_id = strdup(item_id);
		target_item->next = root_item->next;
		root_item->next = target_item;
	}

	target_item->item_value = addr;
	return (target_item->item_value);
}

void* addrid_group(const char* item_id_group, const char* item_id)
{
	HANDLE mutex = __enter_mutex(addrid_mutex());
	void* run_ret = __addrid_group(item_id_group, item_id);
	__leave_mutex(mutex);
	return (run_ret);
}

void* addrid_group_set(const char* item_id_group, const char* item_id, void* addr)
{
	HANDLE mutex = __enter_mutex(addrid_mutex());
	void* run_ret = __addrid_group_set(item_id_group, item_id, addr);
	__leave_mutex(mutex);
	return (run_ret);
}

void* addrid_group_init(const char* item_id_group, const char* item_id, lpfn_addrid_cb initer, size_t init_size)
{
	HANDLE mutex = __enter_mutex(addrid_mutex());

	void* run_ret = __addrid_group(item_id_group, item_id);

	if (run_ret == NULL)
	{
		run_ret = calloc(init_size, sizeof(char));
		if (run_ret == NULL)
		{
			DbgPrint("addrid_group_init can't calloc, err=%d", GetLastError());
		}

		initer(run_ret, item_id);

		__addrid_group_set(item_id_group, item_id, run_ret);
	}

	__leave_mutex(mutex);
	return (run_ret);
}

/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
//	cs
/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

typedef struct __CS_ITEM
{
	char* cs_id;
	CRITICAL_SECTION cs;
} CS_ITEM;

void cs_item_init(void* data, const char* cs_id)
{
	CS_ITEM* new_item = (CS_ITEM*)data;
	new_item->cs_id = strdup(cs_id);
	InitializeCriticalSection(&new_item->cs);
}

const char* cs_group_list = "cs_group_list";

void enter_cs(const char* cs_id)
{
	CS_ITEM* scan_item = (CS_ITEM*)addrid_group_init(cs_group_list, cs_id, cs_item_init, sizeof(CS_ITEM));

	EnterCriticalSection(&scan_item->cs);
	return;
}

void leave_cs(const char* cs_id)
{
	CS_ITEM* scan_item = (CS_ITEM*)addrid_group(cs_group_list, cs_id);

	if (scan_item)
	{
		LeaveCriticalSection(&scan_item->cs);
	}
	return;
}


/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
//	mutex	
/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

const char* mutex_atom_list = "mutex_atom_list";

void enter_mutex(const char* mutex_id)
{
	HANDLE mutex_handle = (HANDLE)addrid_group(mutex_atom_list, mutex_id);

	if (mutex_handle == NULL)
	{
		char mutex_name[MAX_PATH];
		sprintf(mutex_name, "%s_%s", mutex_atom_list, mutex_id);
		HANDLE mutex_handle = CreateMutex(NULL, TRUE, mutex_name);
		addrid_group_set(mutex_atom_list, mutex_id, mutex_handle);
	}

	if (mutex_handle) 		
	{
		DWORD wait_ret =  WaitForSingleObject(mutex_handle, INFINITE);

		if (wait_ret == WAIT_FAILED)
		{
			ReleaseMutex(mutex_handle);
			CloseHandle(mutex_handle);
			addrid_group_set(mutex_atom_list, mutex_id, NULL);

			enter_mutex(mutex_id);
		}
	}
	return;
}

void leave_mutex(const char* mutex_id)
{
	HANDLE mutex_handle = (HANDLE)addrid_group(mutex_atom_list, mutex_id);

	if (mutex_handle)
	{
		ReleaseMutex(mutex_handle);
		CloseHandle(mutex_handle);
	}
}

HANDLE __enter_mutex(const char* mutex_id)
{
	char mutex_ori[MAX_PATH];
	sprintf(mutex_ori, "%s-orimutex", mutex_id);

	HANDLE mutex = CreateMutex(NULL, TRUE, mutex_ori);

	if (mutex) 		
	{
		WaitForSingleObject(mutex, INFINITE);
		return (mutex);
	}

	return (NULL);
}

void __leave_mutex(HANDLE mutex)
{
	if (mutex)
	{
		ReleaseMutex(mutex);
		CloseHandle(mutex);
	}
}

const char* tls_atom_list = "tls_atom_list";

int set_tls(const char* tls_id, void* value)
{
	assert(tls_id);

	DWORD tls_value = (DWORD)addrid_group(tls_atom_list, tls_id);

	if ((tls_value == 0) && (GetLastError() == 0xF0000000))
	{
		tls_value = (DWORD)addrid_group_set(tls_atom_list, tls_id, (void*)TlsAlloc());

		if (tls_value == TLS_OUT_OF_INDEXES)
		{
			return (0);
		}
	}

	if (tls_value == TLS_OUT_OF_INDEXES)
	{
		tls_value = TlsAlloc();

		if (tls_value == TLS_OUT_OF_INDEXES)
		{
			return (0);
		}

		addrid_group_set(tls_atom_list, tls_id, (void*)tls_value);
	}

	return TlsSetValue(tls_value, value);
}

void* get_tls(const char* tls_id)
{
	DWORD tls_value = (DWORD)addrid_group(tls_atom_list, tls_id);

	if ((tls_value == 0) && (GetLastError() == 0xF0000000))
	{
		tls_value = (DWORD)addrid_group_set(tls_atom_list, tls_id, (void*)TLS_OUT_OF_INDEXES);
	}

	if (tls_value == TLS_OUT_OF_INDEXES)
	{
		return (NULL);
	}

	return TlsGetValue(tls_value);
}

typedef struct __queue_item
{
	struct __queue_item* prev;
	struct __queue_item* next;
	size_t size;
	char buffer[1];
} QUEUE_ITEM;

typedef struct
{
	QUEUE_ITEM head;
	QUEUE_ITEM tail;
	int queue_count;
	HANDLE queue_heap;
	HANDLE enqueue_event;
	CRITICAL_SECTION enqueue_cs;
	CRITICAL_SECTION dequeue_cs;
} QUEUE_BLOCK;

void que_block_init(void* data, const char* item_id)
{
	QUEUE_BLOCK* que_block = (QUEUE_BLOCK*)data;

	InitializeCriticalSection(&que_block->enqueue_cs);
	InitializeCriticalSection(&que_block->dequeue_cs);

	que_block->queue_heap =  HeapCreate(0, 0, 0);
	que_block->enqueue_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	que_block->head.next = &que_block->tail;
	que_block->head.prev= NULL; 
	que_block->tail.next = NULL;
	que_block->tail.prev = &que_block->head;
}

const char*  queue_group_list = "queue_group_list";

long  enqueue(const char* queue_id, const void* data, int size)
{
	QUEUE_BLOCK* que_block = addrid_group_init(queue_group_list, queue_id, que_block_init, sizeof(QUEUE_BLOCK));

	EnterCriticalSection(&que_block->enqueue_cs);

	int new_item_size = sizeof(QUEUE_ITEM) + size;
	QUEUE_ITEM* new_item = (QUEUE_ITEM*)HeapAlloc(que_block->queue_heap, 0, new_item_size);

	if (new_item == NULL)
	{	
		DWORD last_error = GetLastError();
		LeaveCriticalSection(&que_block->enqueue_cs);
		DbgPrint("enqueue can't HeapAlloc(%x), err=%d", que_block->queue_heap, last_error);
		return (0);
	}
	
	new_item->size = size;
	memcpy(&new_item->buffer[0], data, size);

	new_item->next = que_block->head.next;
	que_block->head.next = new_item;
	new_item->prev = new_item->next->prev;
	new_item->next->prev = new_item;
	LeaveCriticalSection(&que_block->enqueue_cs);

	SetEvent(que_block->enqueue_event);
	return (size);
}

QUEUE_ITEM* do_dequeue(QUEUE_BLOCK* que_block)
{
	EnterCriticalSection(&que_block->dequeue_cs);
	QUEUE_ITEM* del_item = que_block->tail.prev;
	if (del_item == &que_block->head)
	{
		LeaveCriticalSection(&que_block->dequeue_cs);
		return (NULL);
	}

	del_item->prev->next = del_item->next;
	que_block->tail.prev = del_item->prev;
	LeaveCriticalSection(&que_block->dequeue_cs);
	
	return (del_item);
}

void* dequeue(const char* queue_id, int* size, DWORD time_out)
{
	*size = 0;
	QUEUE_BLOCK* que_block = addrid_group_init(queue_group_list, queue_id, que_block_init, sizeof(QUEUE_BLOCK));

	ResetEvent(que_block->enqueue_event);
	QUEUE_ITEM* del_item = do_dequeue(que_block);

	if (del_item == NULL)
	{
		if (time_out == 0)
		{
			return (NULL);
		}

		DbgPrint("set event");
		WaitForSingleObject(que_block->enqueue_event, time_out);
		del_item = do_dequeue(que_block);

		if (del_item == NULL)
		{
			return (NULL);
		}
	}

	void* run_ret = malloc(del_item->size);
	memcpy(run_ret, &del_item->buffer[0], del_item->size);
	*size = del_item->size;

	HeapFree(que_block->queue_heap, 0, del_item);
	return (run_ret);
}

typedef struct __msg_item
{
	int size;
	int data_size;
	char buffer[0];
} __attribute__ ((packed, aligned(1))) MSG_ITEM;

typedef struct __MSG_BLOCK
{
	size_t size;
	DWORD owner_pid;
	HANDLE server_event;
	long item_count;
	int begin;
	int end;
	int head;
	int tail;
	int offset_event_name;
	int offset_mutex_name;
	char buffer[0];
} MSG_BLOCK;

long  msg_client(const char* msg_id, const void* data, int size)
{
	if (data == NULL)
	{
		free_local(msg_id);
		addrid_set(msg_id, NULL);
		return (0);
	}

	MSG_BLOCK* msg_block = (MSG_BLOCK*)addrid(msg_id);

	if (msg_block == NULL)
	{
		MSG_BLOCK* msg_block = (MSG_BLOCK*)open_local(msg_id);
		if (msg_block == NULL)
		{
			return (0);
		}

		addrid_set(msg_id, msg_block);
	}

	//使用事件，作为检测服务器存活的标志
	char* event_name = (char*)RVATOVA(msg_block, msg_block->offset_event_name);
	HANDLE enqueue_event = OpenEvent(EVENT_MODIFY_STATE, FALSE, event_name);

	if (enqueue_event == NULL)
	{
		DbgPrint("msg_client can't OpenEvent(%s), maybe server(%s) is down", event_name, msg_id);
		free_local(msg_id);
		addrid_set(msg_id, NULL);
		return (0);
	}

	char* mutex_name = (char*)RVATOVA(msg_block, msg_block->offset_mutex_name);
	enter_mutex(mutex_name);

	int space = (msg_block->head>=msg_block->tail)? msg_block->head-msg_block->tail : msg_block->end-msg_block->tail;
	int item_size = size + sizeof(MSG_ITEM);

	long succeed_size = 0;
	if (space >= item_size)
	{
		char* copy_to = (char*)RVATOVA(msg_block, msg_block->tail);
		MSG_ITEM* add_item = (MSG_ITEM*)copy_to;
		add_item->size = item_size;
		add_item->data_size = size;
		copy_to += sizeof(MSG_ITEM);
		memcpy(copy_to, data, size);

		msg_block->tail += item_size;
		InterlockedIncrement(&msg_block->item_count);
		succeed_size = size; 
	}
	else
	{
		if (msg_block->tail > msg_block->head)
		{
			int null_size = msg_block->end = msg_block->tail;
			MSG_ITEM* null_item = (MSG_ITEM*)RVATOVA(msg_block, msg_block->tail);
			null_item->size = null_size;
			null_item->data_size = 0;

			msg_block->tail += null_size;
			InterlockedIncrement(&msg_block->item_count);
			succeed_size = -1;
		}
	}

	if (msg_block->tail == msg_block->end)
	{
		msg_block->tail = msg_block->begin;
	}

	leave_mutex(mutex_name);

	if (succeed_size > 0)
	{
		SetEvent(enqueue_event);
		CloseHandle(enqueue_event);
		return (succeed_size);
	}

	if (succeed_size == 0)
	{
		CloseHandle(enqueue_event);
		return (0);
	}

	CloseHandle(enqueue_event);
	return msg_client(msg_id, data, size);
}

HANDLE make_event(const char* name)
{
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.lpSecurityDescriptor = &sd;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;

	return CreateEvent(&sa, FALSE, FALSE, name);
}

const char* EVENT_PREFIX = "msg_event_of";
const char* MUTEX_PREFIX = "msg_mutex_of";

void* msg_server(const char* msg_id, int* size, DWORD time_out)
{
	MSG_BLOCK* msg_block = (MSG_BLOCK*)addrid(msg_id);

	if (size == NULL)
	{
		CloseHandle(msg_block->server_event);
		free_local(msg_id);
		addrid_set(msg_id, NULL);
		return (0);
	}

	if (msg_block == NULL)
	{
		int alloc_size = sizeof(MSG_BLOCK) + MAX_PATH + 0x1000*0x100;
		alloc_size = round_align(alloc_size, 0x1000);
		MSG_BLOCK* msg_block = (MSG_BLOCK*)malloc_local(msg_id, alloc_size);
		if (msg_block == NULL)
		{
			return (0);
		}

		msg_block->size = alloc_size;
		msg_block->owner_pid = GetCurrentProcessId();
		msg_block->item_count = 0;

		msg_block->offset_event_name = sizeof(MSG_BLOCK);
		char* copy_base = (char*)RVATOVA(msg_block, msg_block->offset_event_name);
		int cp_offset = sprintf(copy_base, "%s_%s", EVENT_PREFIX, msg_id);
		msg_block->server_event = make_event(copy_base);

		msg_block->offset_mutex_name = msg_block->offset_event_name + cp_offset+1;
		copy_base = (char*)RVATOVA(msg_block, msg_block->offset_mutex_name);
		cp_offset = sprintf(copy_base, "%s_%s", MUTEX_PREFIX, msg_id);

		msg_block->begin = msg_block->offset_mutex_name + cp_offset + 1;
		msg_block->end = alloc_size;
		msg_block->head = msg_block->begin;
		msg_block->tail = msg_block->head;

		addrid_set(msg_id, msg_block);
	}

	//先取出结果
	int de_size;
	void* de_data = dequeue(msg_id, &de_size, 0);

	//再取出共享内存列表的大小
	int que_size = msg_block->tail - msg_block->head;
	int total_size = msg_block->end - msg_block->begin;
	if (que_size < 0)
	{
		que_size = total_size + que_size;
	}

	//看看是否需要主动取？
	int need_get = (que_size > (total_size/2))? 1 : 0;
	*size = de_size;

	//如果根本共享列表中没有数据，则直接退出
	if (msg_block->head == msg_block->tail)
	{
		return (de_data);
	}

	//如果有数据但不多，且已经从本地列表中获得，则也退出
	if ((de_data) && (need_get == 0))
	{
		return (de_data);
	}

	char* mutex_name = (char*)RVATOVA(msg_block, msg_block->offset_mutex_name);
	enter_mutex(mutex_name);

	do
	{
		MSG_ITEM* pop_item = (MSG_ITEM*)RVATOVA(msg_block, msg_block->head);

		if (de_data == NULL)
		{
			*size = pop_item->data_size;
			de_data = malloc(pop_item->data_size);
			memcpy(de_data, &pop_item->buffer[0], pop_item->data_size);
			goto next_msg_item;
		}

		if (pop_item->data_size)
		{
			enqueue(msg_id, &pop_item->buffer[0], pop_item->data_size);
		}

next_msg_item:
		msg_block->head += pop_item->size; 
		if (msg_block->head == msg_block->end)
		{
			msg_block->head = msg_block->begin;
		}

		InterlockedDecrement(&msg_block->item_count);
	} while (msg_block->head == msg_block->tail);


	leave_mutex(mutex_name);

	if (de_data)
	{
		return (de_data);
	}
	else
	{
		ResetEvent(msg_block->server_event);
		WaitForSingleObject(msg_block->server_event, time_out);
		return msg_server(msg_id, size, time_out);
	}
}

