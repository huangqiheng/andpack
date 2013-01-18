#include <windows.h>
#include <string.h>
#include <global.h>
#include <tlhelp32.h>

#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))
#define VATORVA(base, addr) ((INT)(addr) - (INT)(base))
#define NTHEADER(hModule)   ((PIMAGE_NT_HEADERS)RVATOVA((hModule), ((PIMAGE_DOS_HEADER)(hModule))->e_lfanew))
#define DATADIRECTORY(pNtHeader, nIndex) &(pNtHeader)->OptionalHeader.DataDirectory[(nIndex)]
#define VALIDRANGE(value, base, size) (((DWORD)(value) >= (DWORD)(base)) && ((DWORD)(value)<((DWORD)(base)+(DWORD)(size))))
#define DLLENTRY(hModule) ((DllEntryProc)RVATOVA ((DWORD)(hModule), NTHEADER(hModule)->OptionalHeader.AddressOfEntryPoint))
#define ENTRYRVA(hModule) (NTHEADER(hModule)->OptionalHeader.AddressOfEntryPoint)
#define SIZEOFIMAGE(hModule) (NTHEADER(hModule)->OptionalHeader.SizeOfImage)
#define IMAGEBASE(hModule) (NTHEADER(hModule)->OptionalHeader.ImageBase)

#define DLL_MODULE_ATTACH  DLL_PROCESS_DETACH + 10
#define DLL_MODULE_DETACH  DLL_MODULE_ATTACH + 1

typedef HMODULE (WINAPI *LOADLIBRARY)(LPCTSTR lpFileName); 
typedef HMODULE (WINAPI *GETMODULEHANDLE)(LPCTSTR lpFileName); 
typedef BOOL (WINAPI *FREELIBRARY)(HMODULE hModule);
typedef FARPROC (WINAPI *GETPROCADDRESS)(HINSTANCE hModule, LPCSTR lpProcName);

void DebugMsg(const char *szFormat, ...)
{
	char szData[512] = {0};
	va_list args;
	va_start(args, szFormat);
	_vsnprintf(szData, sizeof(szData) - 1, szFormat, args);
	va_end(args);
	OutputDebugString(szData);
}

LPDWORD GetProcEATAddress(HMODULE hModule, PCHAR lpFunName)
{
	PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY) DATADIRECTORY (NTHEADER (hModule), IMAGE_DIRECTORY_ENTRY_EXPORT);

	if (directory->Size == 0)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) RVATOVA (hModule, directory->VirtualAddress);

	if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0)
	{
		return NULL;
	}

	LPDWORD pAddressOfFunctions = (LPDWORD) RVATOVA (hModule, exports->AddressOfFunctions);
	LPWORD  pAddressOfOrdinals = (LPWORD) RVATOVA (hModule, exports->AddressOfNameOrdinals);
	LPDWORD pAddressOfNames  = (LPDWORD) RVATOVA (hModule, exports->AddressOfNames);

	int i;
	char *pName;
	for (i=0; i < exports->NumberOfNames; i++)
	{
		if (pAddressOfNames[i])
		{
			pName = (char* ) RVATOVA (hModule, pAddressOfNames[i]);
			DebugMsg("GetProcEATAddress: %s = %s", pName, lpFunName);
			if (stricmp(pName, lpFunName) == 0)
			{
				return pAddressOfFunctions + pAddressOfOrdinals[i];
			}
		}
	}
	return NULL;
}

FARPROC __GetProcAddress(HMODULE hModule, PCHAR lpFunName)
{
	LPDWORD pdwEATAddr = GetProcEATAddress(hModule, lpFunName);
	if (pdwEATAddr == NULL)
	{
		return (NULL);
	}
	return (FARPROC) RVATOVA (hModule, *pdwEATAddr);
}

typedef struct {
	HMODULE hModule; //if it's NULL, mean that's the end of list.
	BOOL    bActive; //set it FALSE, if remove a module.
	DWORD   dwCounter; //the counter of loadlibrary.
	char    szModuleName[32];
} MODULEITEM, *LPMODULEITEM;

LPMODULEITEM g_pExistModule = NULL;


PCHAR __GetModuleFileName(HMODULE hDllModule)
{
        PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY) DATADIRECTORY (NTHEADER (hDllModule), IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (directory->Size == 0) return NULL;
        PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) RVATOVA (hDllModule, directory->VirtualAddress);
        return (PCHAR) RVATOVA(hDllModule, exports->Name);
}


LPMODULEITEM modlist_fill_item(LPMODULEITEM pModItem, HMODULE hModule)
{
	pModItem->hModule = hModule;
	pModItem->bActive = TRUE;
	pModItem->dwCounter = 0;
	PCHAR szModName = __GetModuleFileName(hModule);
	strcpy(&pModItem->szModuleName[0], szModName);
	pModItem->szModuleName[strlen(szModName)] = '\0';

	DebugMsg("add a new item: %x, name: %s", hModule, szModName);
	return pModItem;
}

LPMODULEITEM modlist_find_item_by_handle(HMODULE hModule)
{
	if (!g_pExistModule)
	{
		DebugMsg("g_pExistModule hasn't initial %x", hModule);
		return NULL;
	}

	LPMODULEITEM pScanModule = g_pExistModule;
	for (; pScanModule->hModule; pScanModule++) 
	{
		if ((pScanModule->bActive) && (pScanModule->hModule == hModule))
		{
			return pScanModule;
		}
	}

	return NULL;
}

LPMODULEITEM modlist_find_item(PCHAR szDllName)
{
	if (!g_pExistModule)
		return NULL;

	if (!szDllName)
		return NULL;

	LPMODULEITEM pScanModule = g_pExistModule;
	for (; pScanModule->hModule; pScanModule++) 
	{
		if (stricmp(&pScanModule->szModuleName[0], szDllName) == 0)
		{
			return pScanModule;
		}
	}
	return NULL;
}

BOOL modlist_remove(HMODULE hModule)
{
	if (!g_pExistModule)
		return FALSE;

	LPMODULEITEM pScanModule = g_pExistModule;
	for (; pScanModule->hModule; pScanModule++) {
		if (pScanModule->hModule == hModule){
			pScanModule->bActive = FALSE;
		}
	}
	return TRUE;
}

LPMODULEITEM modlist_add(HMODULE hModule)
{
	if (!g_pExistModule) 
	{
		g_pExistModule = malloc(sizeof(MODULEITEM));
		g_pExistModule->hModule = NULL;
	}

	modlist_remove(hModule);

	DWORD dwItemCount = 1;
	LPMODULEITEM pScanModule = g_pExistModule;
	for (; pScanModule->hModule; dwItemCount++, pScanModule++) 
	{
		if (!pScanModule->bActive) 
		{
			return modlist_fill_item(pScanModule, hModule);
		} 
	}

	g_pExistModule = realloc(g_pExistModule, (dwItemCount+1) * sizeof(MODULEITEM));
	pScanModule = modlist_fill_item(g_pExistModule + dwItemCount - 1, hModule);
	pScanModule[1].hModule = NULL;

	return pScanModule;
}

typedef HMODULE (WINAPI *GETMODULEHANDLEA)(PCHAR lpFileName); 
typedef DWORD   (WINAPI *GETMODULEFILENAME)(HMODULE hModule, LPTSTR lpFilename, DWORD nSize);

LOADLIBRARY OriLoadLibrary;
FREELIBRARY OriFreeLibrary;
GETMODULEHANDLEA OriGetModuleHandle;
GETPROCADDRESS OriGetProcAddress;
GETMODULEFILENAME OriGetModuleFileName;

HMODULE WINAPI LoadLibraryA_Hook(PCHAR dllName)
{
	LPMODULEITEM item = modlist_find_item(dllName);
	if (item) {
		item->dwCounter++;
		return item->hModule;
	}
	return OriLoadLibrary(dllName);
}

BOOL WINAPI FreeLibrary_Hook(HMODULE hModule)
{
	LPMODULEITEM item = modlist_find_item_by_handle(hModule);
	if (item) {
		item->dwCounter--;
		return TRUE;
	}
	return OriFreeLibrary(hModule);
}

FARPROC WINAPI GetProcAddress_Hook(HMODULE hModule, PCHAR lpProcName)
{
	LPMODULEITEM item = modlist_find_item_by_handle(hModule);
	if (item) 
	{
		DebugMsg("GetProcAddress_Hook: hModule:%x, Name:%s, Proc:%s", item->hModule, item->szModuleName, lpProcName);
		return __GetProcAddress(hModule, lpProcName);
	}
	return OriGetProcAddress(hModule, lpProcName);
}

DWORD WINAPI GetModuleFileName_Hook(HMODULE hModule, PCHAR lpFilename, DWORD nSize)
{
	LPMODULEITEM item = modlist_find_item_by_handle(hModule);
	if (item) {
		PCHAR szModName = &item->szModuleName[0];
		DWORD dwNameLen = strlen(szModName);
		strcpy(lpFilename, szModName);
		lpFilename[dwNameLen] = '\0';
		return dwNameLen;
	}
	return OriGetModuleFileName(hModule, lpFilename, nSize);
}

HMODULE WINAPI GetModuleHandleA_Hook(PCHAR lpModuleName)
{
	LPMODULEITEM item = modlist_find_item(lpModuleName);
	if (item) 
	{
		return item->hModule;
	}
	return OriGetModuleHandle(lpModuleName);
}

void* IATHook(HMODULE hModuleToFix, PCHAR szLibName, PCHAR szFunName, void* Hooker)
{
	LPVOID pTargetFun = (LPVOID)GetProcAddress(GetModuleHandle(szLibName), szFunName);
	if (!pTargetFun) 
	{
		DebugMsg("IATHook: target func address error: %s - %s\n", szLibName, szFunName);
		return NULL;
	}

	PIMAGE_NT_HEADERS pNtHeaders = NTHEADER(hModuleToFix);
	PIMAGE_DATA_DIRECTORY directory = DATADIRECTORY(pNtHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size == 0) 
	{
		DebugMsg("IATHook: import data directory size is 0: %s - %s\n", szLibName, szFunName);
		return NULL;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)RVATOVA(hModuleToFix, directory->VirtualAddress);
	DWORD nSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;

	DWORD *thunkRef;
	FARPROC *funcRef;
	LPVOID pOriFun;
	while (VALIDRANGE(importDesc, hModuleToFix, nSizeOfImage) && (importDesc->Name))
	{
		PCHAR szScanLib = (PCHAR)RVATOVA(hModuleToFix, importDesc->Name);

		if (stricmp(szScanLib, szLibName) == 0)
		{
			if (importDesc->OriginalFirstThunk) 
			{
				thunkRef = (DWORD*) RVATOVA (hModuleToFix, importDesc->OriginalFirstThunk);
				funcRef = (FARPROC *) RVATOVA (hModuleToFix, importDesc->FirstThunk);
			}
			else 
			{
				// no hint table
				thunkRef = (DWORD*) RVATOVA (hModuleToFix, importDesc->FirstThunk);
				funcRef = (FARPROC *) RVATOVA (hModuleToFix, importDesc->FirstThunk);
			}

			for (; *thunkRef; thunkRef++, funcRef++) 
			{
				pOriFun = (LPVOID)(*funcRef); 
				if (pOriFun == pTargetFun)
				{
					DWORD dwOLD;
					MEMORY_BASIC_INFORMATION mbi;

					VirtualQuery((LPVOID)funcRef, &mbi, sizeof(mbi));
					VirtualProtect((LPVOID)funcRef, sizeof(DWORD), PAGE_READWRITE, &dwOLD);
					*funcRef = (FARPROC)Hooker;
					VirtualProtect((LPVOID)funcRef, sizeof(DWORD), dwOLD, 0);
					return pOriFun;
				}
			}
		}
		importDesc++;
	}
	DebugMsg("IATHook: not found to hook: %s - %s\n", szLibName, szFunName);
	return NULL;
}

void ProcessIATHook(HMODULE hNewHandle)
{
	void* _loadlibrary = IATHook(hNewHandle, "kernel32.dll", "LoadLibraryA", &LoadLibraryA_Hook);
	void* _freelibrary = IATHook(hNewHandle, "kernel32.dll", "FreeLibrary", &FreeLibrary_Hook);
	void* _getprocaddress = IATHook(hNewHandle, "kernel32.dll", "GetProcAddress", &GetProcAddress_Hook);
	void* _getmodulehandle = IATHook(hNewHandle, "kernel32.dll", "GetModuleHandleA", &GetModuleHandleA_Hook);
	void* _getmodulefilename = IATHook(hNewHandle, "kernel32.dll", "GetModuleFileNameA", &GetModuleFileName_Hook);

	if ((_loadlibrary) && (!OriLoadLibrary))
		OriLoadLibrary = (LOADLIBRARY)_loadlibrary;

	if ((_freelibrary) && (!OriFreeLibrary))
		OriFreeLibrary = (FREELIBRARY)_freelibrary;

	if ((_getprocaddress) && (!OriGetProcAddress))
		OriGetProcAddress = (GETPROCADDRESS)_getprocaddress;

	if ((_getmodulehandle) && (!OriGetModuleHandle))
		OriGetModuleHandle = (GETMODULEHANDLEA)_getmodulehandle;

	if ((_getmodulefilename) && (!OriGetModuleFileName))
		OriGetModuleFileName = (GETMODULEFILENAME)_getmodulefilename;
}


int is_patern_string(const char* str_a, const char* str_b)
{
	int result = 0;
	int len_a = strlen(str_a);
	int len_b = strlen(str_b);

	if (len_a != len_b)
	{
		return (result);
	}

	char* stra = strdup(str_a);
	char* strb = strdup(str_b);

	int i;
	for (i=0; i<len_a; i++)
	{
		if (stra[i] == '?')
		{
			stra[i] = '-';
			strb[i] = '-';
		}

		if (strb[i] == '?')
		{
			stra[i] = '-';
			strb[i] = '-';
		}
	}

	if (!stricmp(stra, strb))
	{
		result = 1;
	}

	free(stra);
	free(strb);
	return (result);
}

char* find_ext_dot(char* buffer, int* index)
{
	int scan = strlen(buffer);
	while (buffer[scan] != '.')
	{
		scan--;
		if (scan == -1)
		{
			*index = -1;
			return (NULL);
		}
	}
	*index = scan;
	return (&buffer[scan]);
}

int is_path_break(char char2chk)
{
	return ((char2chk == '\\') || (char2chk == '/'))? 1 : 0;
}

char* seek_short_file_name(char* buffer)
{
	int outnamesize = strlen(buffer);
	while (!is_path_break(buffer[outnamesize]))
	{
		outnamesize--;
		if (outnamesize == -1)
			break;
	}
	return &buffer[++outnamesize];
}

int is_itemdir_strlist(char* target_string, STARTUP* startup, STORE_ITEM* item_dir)
{
	if (item_dir->length == 0)
	{
		return (0);
	}

	STORE_ITEM* item_list = (STORE_ITEM*)STARTUP(*item_dir);

	if (item_list->length == 0)
	{
		return (0);
	}

	char* to_cmp;

	do
	{
		//取出被对比的字符串
		to_cmp = (char*)STARTUP(*item_list);

		//分离“目录名”和“文件名”
		char* cmp_path = strdup(to_cmp);
		char* null = seek_short_file_name(cmp_path);
		char* cmp_short = strdup(null);
		null[0] = '\0';

		char* target_path = strdup(target_string);
		null = seek_short_file_name(target_path);
		char* target_short = strdup(null);
		null[0] = '\0';

		//如果目录都不相同，就不用对比了
		if (stricmp(cmp_path, target_path))
		{
			free(cmp_path);
			free(cmp_short);
			free(target_path);
			free(target_short);
			continue;
		}

		//用不着了，释放它
		free(cmp_path);
		free(target_path);

		int is_done = 0;
		do
		{
			//如果全名对比相同，则被匹配
			if (!stricmp(cmp_short, target_short))
			{
				is_done = 1;
				break;
			}

			//如果是*.*，也被匹配
			if (!stricmp(cmp_short, "*.*"))
			{
				is_done = 1;
				break;
			}

			//进一步拆分文件名和后缀
			int dot_index;
			char* cmp_ext = find_ext_dot(cmp_short, &dot_index);
			if (cmp_ext)
			{
				cmp_ext[0] = '\0';
				cmp_ext++;
			}

			char* target_ext = find_ext_dot(target_short, &dot_index);
			if (target_ext)
			{
				target_ext[0] = '\0';
				target_ext++;
			}

			if ((cmp_ext == NULL) && (target_ext != NULL))
			{
				break;
			}

			if (cmp_short[0] == '*')
			{
				if (is_patern_string(cmp_ext, target_ext))
				{
					is_done = 1;
					break;
				}
			}

			if (cmp_ext[0] == '*')
			{
				if (is_patern_string(cmp_short, target_short))
				{
					is_done = 1;
					break;
				}
			}

		} while (0);

		free(cmp_path);
		free(target_path);

		if (is_done)
		{
			return (1);
		}

	} while((++item_list)->length);

	return (0);
}

static PIMAGE_SECTION_HEADER get_spectial_section_byname(void* pe_base, const char *section_name)
{
	PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER(pe_base);
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(pNtHeader_File);

	int i;  
	for (i=0; i<pNtHeader_File->FileHeader.NumberOfSections; i++)
	{               
		if (stricmp(Sections[i].Name, section_name) == 0)
		{               
			return (PIMAGE_SECTION_HEADER)&Sections[i];
		}
	}

	return NULL;
}


static void* get_section(void* pe_base, const char* section_name)
{
	if (pe_base)
	{
		PIMAGE_SECTION_HEADER aim_section = get_spectial_section_byname(pe_base, section_name);
		if (aim_section)
		{
			if (aim_section->VirtualAddress)
			{
				return (void*)RVATOVA(pe_base, aim_section->VirtualAddress);
			}
		}
	}
	return (NULL);
}


HINSTANCE find_session_dll()
{       
	HINSTANCE result = NULL;
	STARTUP* startup;

	HANDLE hSnapShot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0);

	if (hSnapShot == INVALID_HANDLE_VALUE)
	{       
		return (result);
	}

	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hSnapShot, &me))
	{
		CloseHandle(hSnapShot);
		return (result);
	}
	char* main_exe = strdup(me.szExePath);

	while (Module32Next(hSnapShot, &me))
	{
		if ((startup = get_section(me.modBaseAddr, STUB_START_SECTION_NAME)) == NULL)
		{
			continue;
		}

		if ((is_itemdir_strlist(main_exe, startup, &startup->realy_plugin_apps)) == 0)
		{
			continue;
		}

		result = (HINSTANCE)me.modBaseAddr;
		break;
	}

	CloseHandle(hSnapShot);
	return (result);
}

HINSTANCE session_dll;

BOOL WINAPI DllMain (HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
	PCHAR ImportModName;
	switch(fdwReason) 
	{ 
		case DLL_PROCESS_ATTACH:    
			modlist_add((HMODULE)hinstDll);    

			if (session_dll = find_session_dll())
			{
				modlist_add((HMODULE)session_dll);    
			}

			break;
		case DLL_THREAD_ATTACH:     
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:    
			modlist_remove((HMODULE)session_dll);
			break;
		case DLL_MODULE_ATTACH:
			if ((LPVOID)hinstDll != lpReserved) 
			{
				modlist_add((HMODULE)lpReserved);    
				ProcessIATHook((HMODULE)lpReserved);
			}
			break;
		case DLL_MODULE_DETACH:     
			modlist_remove((HMODULE)lpReserved);
			break;
	}
	SetLastError(0);
	return (TRUE);
}
