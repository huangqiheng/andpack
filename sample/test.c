#include <windows.h>
#include <stdio.h>
#include <message_comm.h>
#include <sync_funcs.h>

static char* DbgPrint(const char* format, ...)
{       
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
}


HANDLE run_thread(LPTHREAD_START_ROUTINE thread_pro, PVOID param)     
{                                  
        DWORD tid;        
        return CreateThread(NULL, 0, thread_pro, param, 0, &tid);       
}   

CRITICAL_SECTION tempcs;
int is_init = 0;

void post_dbgstr(char* str)
{
	if (is_init == 0)
	{
		InitializeCriticalSection(&tempcs);
		is_init = 1;
	}

	//EnterCriticalSection(&tempcs);

	DWORD tid = GetCurrentThreadId();
	char buff[MAX_PATH];
	sprintf(buff, "%d:%s", tid, str);

	int sent = enqueue("msg_id", &buff[0], strlen(buff)+1); 

	if (sent == 0)
	{
		DbgPrint("post msg error");
	}

	//LeaveCriticalSection(&tempcs);
}

DWORD WINAPI test_thread_pro(void* param)
{
	char buff[MAX_PATH];
	DWORD tid = GetCurrentThreadId();
	sprintf(buff, "(%d)thread start...\n", tid);
	DbgPrint(buff);

	post_dbgstr(buff);

	int count = 1024;
	while(count--)
	{
		post_dbgstr("00000000000000000000000000000000000000000000000000000000000000000000\n");
		post_dbgstr("11111111111111111111111111111111111111111111111111111111111111111111\n");
		post_dbgstr("22222222222222222222222222222222222222222222222222222222222222222222\n");
		post_dbgstr("33333333333333333333333333333333333333333333333333333333333333333333\n");
		post_dbgstr("44444444444444444444444444444444444444444444444444444444444444444444\n");
		post_dbgstr("55555555555555555555555555555555555555555555555555555555555555555555\n");
		post_dbgstr("66666666666666666666666666666666666666666666666666666666666666666666\n");
		post_dbgstr("77777777777777777777777777777777777777777777777777777777777777777777\n");
		post_dbgstr("88888888888888888888888888888888888888888888888888888888888888888888\n");
		post_dbgstr("99999999999999999999999999999999999999999999999999999999999999999999\n");
		post_dbgstr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
		post_dbgstr("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n");
		post_dbgstr("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n");
		post_dbgstr("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n");
		post_dbgstr("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n");
		post_dbgstr("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n");
	}

	sprintf(buff, "(%d)thread finish...\n", tid);
	DbgPrint(buff);
	post_dbgstr(buff);
	return (0);
}

DWORD WINAPI test_thread_pro_2(void* param)
{
	char* de_data;
	int size;

	do
	{
		//EnterCriticalSection(&tempcs);
		de_data = (char*)dequeue("msg_id", &size, INFINITE);
		//LeaveCriticalSection(&tempcs);

		printf(de_data);
		free(de_data);

		if (de_data == NULL)
		{
			break;
		}
	} while (1);


	DbgPrint("test_thread_pro_2 end...");
}

int main() 
{
	DbgPrint("test.exe start..");
	int size;
	dequeue("msg_id", &size, 0);
	
	DbgPrint("start create enqueue threads");
	int thread_count = 26;
	HANDLE* handle_list = calloc(thread_count+1, sizeof(HANDLE));
	int i;
	for (i=0; i<thread_count; i++)
	{
		handle_list[i] = run_thread(test_thread_pro, (void*)i);
	}

	run_thread(test_thread_pro_2, (void*)i);
	run_thread(test_thread_pro_2, (void*)i);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
	}
}

