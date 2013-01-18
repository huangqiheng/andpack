#ifndef __message_comm_h_once__ 
#define __message_comm_h_once__

#ifdef __cplusplus
extern "C" {
#endif

#define debug_print 1

typedef int (*fn_msg_recevier)(void* msg_data, int msg_size);

int thread_msg_event(unsigned int cmd_type, fn_msg_recevier msg_cb);
int thread_msg_looper(char* msg_name, int cell_size, short cell_count, short wait_count, DWORD msg_timeout);

int thread_msg_post(char* msg_name, unsigned int cmd_type, void* msg_data, int msg_size);
int thread_msg_post_str(char* msg_name, unsigned int cmd_type, char* str);
int thread_msg_close(char* msg_name);
int thread_msg_close_client(char* msg_name);

char* gen_guid_str();

#ifdef __cplusplus
}
#endif

#endif
