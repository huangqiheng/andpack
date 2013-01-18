#ifndef __dll_loader_h_once__
#define __dll_loader_h_once__

#ifdef __cplusplus
extern "C" {
#endif

#define ERROR_UNKNOW            (HMODULE)0
#define ERROR_INVALID_IMAGE     (HMODULE)1
#define ERROR_INITIAL_FUNCTIONS (HMODULE)2
#define ERROR_DOS_HEADER        (HMODULE)3
#define ERROR_NT_HEADERS        (HMODULE)4
#define ERROR_ALLOC_RESERVE     (HMODULE)5
#define ERROR_COPYSECTIONS      (HMODULE)6
#define ERROR_FIX_IMPORTTABLE   (HMODULE)7
#define ERROR_NOTFOUND_ENTRY    (HMODULE)8
#define ERROR_ENTRY_RET_FALSE   (HMODULE)9

typedef BOOL (WINAPI *DllEntryProc) (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

HMODULE __LoadLibrary(HMODULE *NotifyMods, LPVOID lpFileBase, LPVOID lpReserved);
BOOL 	__FreeLibrary(HMODULE *NotifyMods, HMODULE hModule, LPVOID lpReserved);
FARPROC __GetProcAddress(HMODULE hModule, PCHAR lpFunName);
PCHAR	__GetMemoryFileName(LPVOID pDllFileBase);
PCHAR 	__GetModuleFileName(HMODULE hDllModule);

HMODULE LoadPlugin(LPVOID lpFileBase, LPVOID lpReserved);
BOOL	FreePlugin(HMODULE hModule, LPVOID lpReserved);

#ifdef __cplusplus
}
#endif

#endif
