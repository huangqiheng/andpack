#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "message_comm.h"
#include "sync_funcs.h"

#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))
#define default_prefix_name "Local\\thread_message-"
#define WAIT_QUEUE_MSG (WM_USER + 0xffff)

typedef struct 
{
	DWORD last_active_tick;
	char data[0];
} __attribute__ ((packed, aligned(1))) cell_data_head;


typedef struct _EVENT_ITEM
{
	struct _EVENT_ITEM *next;
	unsigned int cmd_type;
	fn_msg_recevier msg_cb;
} EVENT_ITEM;


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


int thread_msg_event(unsigned int cmd_type, fn_msg_recevier msg_cb)
{
}

int thread_msg_looper(char* msg_name, int cell_size, short cell_count, short wait_count, DWORD msg_timeout)
{
}

int thread_msg_post(char* msg_name, unsigned int cmd_type, void* msg_data, int msg_size)
{
}

int thread_msg_post_str(char* msg_name, unsigned int cmd_type, char* str)
{
}

int thread_msg_close(char* msg_name)
{
}

int thread_msg_close_client(char* msg_name)
{
}

