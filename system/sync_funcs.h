#ifndef __sync_funcs_h_once__ 
#define __sync_funcs_h_once__

#ifdef __cplusplus
extern "C" {
#endif

#define debug_print 1

typedef void (*lpfn_addrid_cb)(void* data, const char* item_id);

//进程范围的”全局原子表“
void* addrid(const char* addr_id); 
void* addrid_set(const char* addr_id, void* addr); 
void* addrid_init(const char* addr_id, lpfn_addrid_cb initer, size_t init_size);
void* addrid_group(const char* item_id_group, const char* item_id);
void* addrid_group_set(const char* item_id_group, const char* item_id, void* addr);
void* addrid_group_init(const char* item_id_group, const char* item_id, lpfn_addrid_cb initer, size_t init_size);

//申请一片”命名“内存, 系统"session"范围内容可见
void* malloc_local(const char* mem_id, size_t size);
void* open_local(const char* mem_id);
void  free_local(const char* mem_id);

//解决“全局变量“冲突的怀柔办法
int   set_tls(const char* tls_id, void* value);
void* get_tls(const char* tls_id);

//解决”全局变量“冲突的强制办法
void enter_cs(const char* cs_id);
void leave_cs(const char* cs_id);

//解决跨进程全局资源冲突的强制办法
void enter_mutex(const char* mutex_id);
void leave_mutex(const char* mutex_id);
HANDLE __enter_mutex(const char* mutex_id);
void __leave_mutex(HANDLE mutex);

//进程内夸模块的队列
long  enqueue(const char* queue_id, const void* data, int size);
void* dequeue(const char* queue_id, int* size, DWORD time_out);

//全session共享队列
long  msg_client(const char* msg_id, const void* data, int size);
void* msg_server(const char* msg_id, int* size, DWORD time_out);


#ifdef __cplusplus
}
#endif

#endif
