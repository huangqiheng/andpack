#ifndef	__thread_power_h_once__
#define __thread_power_h_once__

#ifdef __cplusplus
extern "C" {
#endif

void* get_thread_entry(HANDLE thread_handle);
DWORD get_main_thread_id();
BOOL thread_power_stealer(DWORD dwThreadId, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter); 

BOOL main_thread_power(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);

#ifdef __cplusplus
}
#endif

#endif
