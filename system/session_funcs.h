#ifndef __section_funcs_h_once__ 
#define __section_funcs_h_once__

#ifdef __cplusplus
extern "C" {
#endif

#include "system_def.h"

//从session.dll中导入的函数
int __stdcall set_session_sharekey(const char* type, const char* key, const char* value);
const char* __stdcall get_session_sharekey(const char* type, const char* key);
int __stdcall set_hook();
int __stdcall cls_hook();
const char** __stdcall get_parameters(HINSTANCE image, const char* catelog_name);
const char** __stdcall get_parameter(HINSTANCE image, const char* catelog_name, const char* key_name);
PACKAGE* __stdcall get_package();
STARTUP* __stdcall get_startup();

//扩展的方便使用的版本
long get_param_valint(const char* key, long default_val);
long get_sysparam_valint(const char* key, long default_val);
const char* get_param_valstr(const char* key, char* default_val);
const char* get_sysparam_valstr(const char* key, char* default_val);
long get_share_valint(const char* type, const char* key, long default_val);
long set_share_valint(const char* type, const char* key, long value);

#ifdef __cplusplus
}
#endif

#endif
