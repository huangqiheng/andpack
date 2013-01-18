
#ifdef __cplusplus
extern "C" {
#endif

#define MSGNONE   -1
#define MSGERR    0
#define MSGWARN   1
#define MSGNOTICE 2
#define MSGDEBUG  3

#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))
#define NTHEADER(hModule)   ((PIMAGE_NT_HEADERS)RVATOVA((hModule), ((PIMAGE_DOS_HEADER)(hModule))->e_lfanew))
#define DATADIRECTORY(pNtHeader, nIndex) &(pNtHeader)->OptionalHeader.DataDirectory[(nIndex)]

typedef void FAR (*fnlp_vshow_msg)(char*, int, const char*, va_list);
static fnlp_vshow_msg __vshow_msg = NULL;
static char *log_modname = NULL;
static int log_dll_error = 0;
static HMODULE hlog;
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

static PCHAR _GetModuleName(HMODULE hModule)
{
        PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY) DATADIRECTORY (NTHEADER (hModule), IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (directory->Size == 0) return NULL;
        PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) RVATOVA (hModule, directory->VirtualAddress);
        return (PCHAR) RVATOVA(hModule, exports->Name);
}

static PCHAR __GetModuleName()
{
	if (this_module == NULL) 
	{
		DWORD pebase = (DWORD)readMyAddr();
		pebase = pebase & 0xFFFFF000;
		while (*((LPWORD)pebase) != IMAGE_DOS_SIGNATURE)
			pebase -= 0x1000;
		this_module = (HMODULE)pebase;
	}
	return strdup(_GetModuleName(this_module));
}


//static void __DebugMsg(const char *szFormat, ...)
//{
//	char szData[512] = {0};
//	va_list args;
//	va_start(args, szFormat);
//	_vsnprintf(szData, sizeof(szData) - 1, szFormat, args);
//	va_end(args);
//	OutputDebugString(szData);
//}


static void FAR show_msg(int level, const char *fmt, ...)
{
	if (__vshow_msg == NULL)
	{
		if (log_dll_error)
			return;
		do {
			if (hlog = LoadLibraryA("log.dll")) 
			{
				if (__vshow_msg = (fnlp_vshow_msg)GetProcAddress(hlog, "vshow_msg")) 
				{
					char* name_mine = __GetModuleName();
					if (name_mine)
					{
						char name_buff[MAX_PATH];
						sprintf(name_buff, "[%d]%s", GetCurrentProcessId(), name_mine);
						free(name_mine);

						log_modname = strdup(name_buff);
						break;
					}
				}
			}
			OutputDebugStringA("can't loadibrary vshow_msg() for log.dll");
			log_dll_error = 1;
			return;
		} while (0);
	}

	va_list args;
	va_start(args, fmt);
	__vshow_msg(log_modname, level, fmt, args);  
	va_end(args);
}


#ifdef __cplusplus
}
#endif
