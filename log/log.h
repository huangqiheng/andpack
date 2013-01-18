/* Common functions provided in common.c */

#ifndef _COMMON_H
#define _COMMON_H

enum VIEW_METHOD
{
	vm_log_file,
	vm_debug_view,
	vm_daemon_console
};

extern enum VIEW_METHOD view_method;

__declspec(dllexport) void set_log_options(int, char *, int);
__declspec(dllexport) void vshow_msg(char *modname, int level, const char *fmt, va_list ap);
__declspec(dllexport) void show_msg(char *modname, int level, const char *fmt, ...); 
__declspec(dllexport) void __stdcall _show_msg(char *modname, int level, const char *msg); 

#define MSGNONE   -1
#define MSGERR    0
#define MSGWARN   1
#define MSGNOTICE 2
#define MSGDEBUG  3

#endif
