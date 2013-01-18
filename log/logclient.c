#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))
#define NTHEADER(hModule)   ((PIMAGE_NT_HEADERS)RVATOVA((hModule), ((PIMAGE_DOS_HEADER)(hModule))->e_lfanew))
#define DATADIRECTORY(pNtHeader, nIndex) &(pNtHeader)->OptionalHeader.DataDirectory[(nIndex)]

typedef void (*fnlp_vshow_msg)(char*, int, const char*, va_list);
fnlp_vshow_msg __vshow_msg = NULL;
char *log_modname = NULL;
int log_dll_error = 0;
HMODULE hlog;
HMODULE this_module = 0;

#define __inline__ inline  __attribute__((always_inline))

__inline__ void* readMyAddr()
{
	void* value;
	__asm__ __volatile__(
			".byte 0xe8		\n\t"
			".long 0x00000000  	\n\t"
			"popl %0		\n\t" 
			:"=m" (value):);
	return value;
}

PCHAR _GetModuleName(HMODULE hModule)
{
        PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY) DATADIRECTORY (NTHEADER (hModule), IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (directory->Size == 0) return NULL;
        PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) RVATOVA (hModule, directory->VirtualAddress);
        return (PCHAR) RVATOVA(hModule, exports->Name);
}

PCHAR __GetModuleName()
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


void logmsg(int level, const char *fmt, ...)
{
	if (__vshow_msg == NULL)
	{
		if (log_dll_error)
			return;
		do {
			if (hlog = LoadLibrary("log.dll")) 
				if (__vshow_msg = (fnlp_vshow_msg)GetProcAddress(hlog, "vshow_msg")) 
					if (log_modname = __GetModuleName())
						break;
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


void log_hex(int level, char* title, void *p, int len)
{
	char buffer[256];
	unsigned char *s = p;
	int cplen = 0;

	memset(buffer, 0, 256);
	while (len--) {
		wsprintf(&buffer[cplen], "%02x \0", *s++);
		cplen += 3;
	}

	logmsg(level, "%s %s\n", title, buffer);
}

void log_hex_block(int level, char* title, char* membase, long memsize)
{
	int line = memsize / 16;
	int left = memsize % 16;
	int i;
	logmsg(level, "%s  -  mem:%p size:%d\n", title, membase, memsize);

	char buffer[16];
	for (i=0; i<line; i++)
	{
		wsprintf(buffer, "%07x0   ", i);
		log_hex(level, buffer, membase + i*16, 16);
	}
	if (left)
	{
		wsprintf(buffer, "%08x   ", i);
		log_hex(level, buffer, membase + i*16, left);
	}
}


#ifdef __cplusplus
}
#endif
