#ifndef __EASY_HOOK_H_ONCE
#define __EASY_HOOK_H_ONCE


int easy_hook_clean(void* hooker);
void* easy_hook_install(char* dll_name, char* fun_name, void* hooker);


#endif
