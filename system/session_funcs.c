#include <windows.h>
#include <stdlib.h>
#include "session_funcs.h"


#define xml_plugin_param "parameter"
HMODULE session_dll;

typedef int (__stdcall *lpfn_set_hook)();
typedef int (__stdcall *lpfn_cls_hook)();
typedef const char** (__stdcall *lpfn_get_parameters)(HINSTANCE image, const char* catelog_name);
typedef const char** (__stdcall *lpfn_get_parameter)(HINSTANCE image, const char* catelog_name, const char* key_name);
typedef PACKAGE* (__stdcall *lpfn_get_package)();
typedef STARTUP* (__stdcall *lpfn_get_startup)();
typedef int (__stdcall *lpfn_set_session_sharekey)(const char* type, const char* key, const char* value);
typedef const char* (__stdcall *lpfn_get_session_sharekey)(const char* type, const char* key);

lpfn_set_hook _set_hook;
lpfn_cls_hook _cls_hook;
lpfn_get_parameters _get_parameters;
lpfn_get_parameter  _get_parameter;
lpfn_get_package _get_package;
lpfn_get_startup _get_startup;
lpfn_set_session_sharekey _set_session_sharekey;
lpfn_get_session_sharekey _get_session_sharekey;

int init_system_functions()
{
	if (session_dll == NULL)
	{
		session_dll = LoadLibraryA(SESSION_DLL_NAME);
		if (session_dll == NULL)
		{
			OutputDebugStringA("daemon.exe LoadLibrary error\n");
			return (0);
		}

		//获取系统函数
		_set_hook = (lpfn_set_hook)GetProcAddress(session_dll, "set_hook@0");
		_cls_hook = (lpfn_cls_hook)GetProcAddress(session_dll, "cls_hook@0");
		_get_parameters = (lpfn_get_parameters)GetProcAddress(session_dll, "get_parameters@8");
		_get_parameter  = (lpfn_get_parameter)GetProcAddress(session_dll, "get_parameter@12");
		_get_package = (lpfn_get_package)GetProcAddress(session_dll, "get_package@0");
		_get_startup = (lpfn_get_startup)GetProcAddress(session_dll, "get_startup@0");
		_get_session_sharekey = (lpfn_get_session_sharekey)GetProcAddress(session_dll, "get_session_sharekey@8");
		_set_session_sharekey = (lpfn_set_session_sharekey)GetProcAddress(session_dll, "set_session_sharekey@12");

		if ((_set_hook == NULL) || 
				(_cls_hook == NULL) ||
				(_get_parameters == NULL) ||
				(_get_parameter == NULL) ||
				(_get_session_sharekey == NULL) ||
				(_set_session_sharekey == NULL) ||
				(_get_package == NULL) ||
				(_get_startup == NULL)
		   )
		{
			OutputDebugStringA("some func from session.dll is null");
			return (0);
		}
	}
	return (1);
}


int __stdcall set_hook()
{
	init_system_functions();
	return (_set_hook)? _set_hook() : 0;
}

int __stdcall cls_hook()
{
	init_system_functions();
	return (_cls_hook)? _cls_hook() : 0;
}

const char** __stdcall get_parameters(HINSTANCE image, const char* catelog_name)
{
	init_system_functions();
	return (_get_parameters)? _get_parameters(image,catelog_name) : NULL;
}

const char** __stdcall get_parameter(HINSTANCE image, const char* catelog_name, const char* key_name)
{
	init_system_functions();
	return (_get_parameter)? _get_parameter(image,catelog_name,key_name) : NULL;
}

PACKAGE* __stdcall get_package()
{
	init_system_functions();
	return (_get_package)? _get_package() : NULL;
}

STARTUP* __stdcall get_startup()
{
	init_system_functions();
	return (_get_startup)? _get_startup() : NULL;
}


int __stdcall set_session_sharekey(const char* type, const char* key, const char* value)
{
	init_system_functions();
	return (_set_session_sharekey)? _set_session_sharekey(type,key,value) : 0;
}

const char* __stdcall get_session_sharekey(const char* type, const char* key)
{
	init_system_functions();
	return (_get_session_sharekey)? _get_session_sharekey(type,key) : 0;
}

const char* get_sysparam_valstr(const char* key, char* default_val)
{
	const char** sysparam_s = get_parameter(NULL, "system", key);
	return (sysparam_s)? sysparam_s[1] : default_val;
}

long get_sysparam_valint(const char* key, long default_val)
{
	const char* param_str = get_sysparam_valstr(key, NULL);
	return (param_str)? atol(param_str) : default_val;
}


static HMODULE this_module = 0;

static __inline__ void* readMyAddr()
{
        void* value;
    __asm__("call next\n"
            "next:\n\t"
            "popl %0\n\t" 
            :"=m" (value):);
        return value;
}

static HANDLE get_pe_handle()
{
	if (this_module == NULL) 
	{
		DWORD pebase = (DWORD)readMyAddr();
		pebase = pebase & 0xFFFFF000;
		while (*((LPWORD)pebase) != IMAGE_DOS_SIGNATURE)
			pebase -= 0x1000;
		this_module = (HMODULE)pebase;
	}
	return (this_module);
}

const char* get_param_valstr(const char* key, char* default_val)
{
	const char** params = get_parameter(get_pe_handle(), xml_plugin_param, key); 
	return (params)? params[1] : default_val;
}

long get_param_valint(const char* key, long default_val)
{
	const char* param_str = get_param_valstr(key, NULL);
	return (param_str)? atol(param_str) : default_val;
}

long get_share_valint(const char* type, const char* key, long default_val)
{
	const char* got_str = get_session_sharekey(type, key);
	return (got_str)? atol(got_str) : default_val;
}

long set_share_valint(const char* type, const char* key, long value)
{
	char buff[20];
	ltoa(value, buff, 10);
	return set_session_sharekey(type, key, buff);
}




