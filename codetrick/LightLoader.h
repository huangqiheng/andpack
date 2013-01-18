#ifndef ____lightloader_once____
#define ____lightloader_once____

#include <windows.h>
#include <winnt.h>

#define __inline__ inline  __attribute__((always_inline))

#define DEBUG_MSG_MODE

typedef SIZE_T (WINAPI *VIRTUALQUERY)(LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOL (WINAPI *VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HMODULE (WINAPI *LOADLIBRARY)(LPCTSTR lpFileName); 
typedef HMODULE (WINAPI *GETMODULEHANDLE)(LPCTSTR lpFileName); 
typedef BOOL (WINAPI *FREELIBRARY)(HMODULE hModule);
typedef FARPROC (WINAPI *GETPROCADDRESS)(HINSTANCE hModule, LPCSTR lpProcName);
typedef void (WINAPI *OUTPUTDEBUGSTRINGA)(LPCSTR);
typedef DWORD (WINAPI *GETLASTERROR)(void);
typedef BOOL (WINAPI *UNMAPVIEWOFFILE)(LPCVOID);
typedef BOOL (WINAPI *CLOSEHANDLE)(HANDLE);

typedef struct {
	VIRTUALALLOC  xVirtualAlloc;
	VIRTUALFREE   xVirtualFree;
	VIRTUALQUERY xVirtualQuery;
	VIRTUALPROTECT  xVirtualProtect;
	LOADLIBRARY  xLoadLibrary;
	FREELIBRARY  xFreeLibrary;
	GETPROCADDRESS  xGetProcAddress;
	GETMODULEHANDLE xGetModuleHandle;
	OUTPUTDEBUGSTRINGA xOutputDebugStringA;
	GETLASTERROR xGetLastError;
	UNMAPVIEWOFFILE xUnmapViewOfFile;
	CLOSEHANDLE xCloseHandle;
} PROCLIST, *PPROCLIST;

typedef BOOL 
(WINAPI *DllEntryProc) (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef HMODULE 
(WINAPI *DllEntryProcH) (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

typedef struct {
	HMODULE hModule;
	DllEntryProc fnEntry;
} MODITEM, *LPMODITEM;

__inline__ HMODULE  lLoadLibrary (LPVOID lpFileBase, LPVOID lpReserved);
__inline__ HMODULE  __lLoadLibrary (PROCLIST *fns, LPMODITEM NotifyMods, LPVOID lpFileBase, LPVOID lpReserved);
__inline__ FARPROC  lGetProcAddress (HMODULE hModule, PCHAR lpFunName);
__inline__ BOOL     lFreeLibrary (HMODULE hModule, LPVOID lpReserved);

__inline__ HMODULE only_map_exe(PROCLIST *fns, char* lpFileBase, void* parameter);

//(1)copy a code buffer from function "LoadFromTail".(wrap a function outside, notice the same function prototype. 
//(2)and then append several dll buffers to the tail.
//(3)define a function type like LPTHREAD_START_ROUTINE, witch pointing to the above code buffer head
//(4)finally ,just call or CreateThread to run it. The return HMODULE can free by lFreeLibrary.
__inline__ HMODULE __LoadFromTail (LPVOID pAddrOfBlock, DWORD dwSizeOfOurself, LPVOID lpReserved);

////////////////////////////////////////////////////////////
#ifndef __GNUC__
#pragma warning (disable: 4311 4312)
#endif

#ifdef _WIN64
#define POINTER_TYPE ULONGLONG
#else
#define POINTER_TYPE DWORD
#endif

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#define DLL_MODULE_ATTACH  DLL_PROCESS_DETACH + 10
#define DLL_MODULE_DETACH  DLL_MODULE_ATTACH + 1

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY  
{  
	LIST_ENTRY InLoadOrderLinks;  
	LIST_ENTRY InMemoryOrderLinks;  
	LIST_ENTRY InInitializationOrderLinks;  
	PVOID DllBase;  
	PVOID EntryPoint;  
	DWORD SizeOfImage;  
	UNICODE_STRING FullDllName;  
	UNICODE_STRING BaseDllName;  
	DWORD Flags;  
	WORD LoadCount; 
	WORD TlsIndex;  
	LIST_ENTRY HashLinks;  
	PVOID SectionPointer;  
	DWORD CheckSum;  
	DWORD TimeDateStamp;  
	PVOID LoadedImports;  
	PVOID EntryPointActivationContext;  
	PVOID PatchInformation;  
}LDR_DATA_TABLE_ENTRY,*PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA {
	DWORD Length;             //0
	BYTE Initialized;         //4
	void* SsHandle;           //8
	LIST_ENTRY InLoadOrderModuleList;            //0ch
	LIST_ENTRY InMemoryOrderModuleList;          //14h
	LIST_ENTRY InInitializationOrderModuleList;  //1ch
}PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _CLIENT_ID
{
     PVOID UniqueProcess;
     PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;


typedef struct {
	UNICODE_STRING DosPath;
	void* Handle;
}CURDIR;
typedef struct RTL_USER_PROCESS_PARAMETERS {
	DWORD MaximumLength;
	DWORD Length;
	DWORD Flags;
	DWORD DebugFlags;
	void* ConsoleHandle;
	DWORD ConsoleFlags;
	void* StandardInput;
	void* StandardOutput;
	void* StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	void* Environment;
	DWORD StartingX;
	DWORD StartingY;
	DWORD CountX;
	DWORD CountY;
	DWORD CountCharsX;
	DWORD CountCharsY;
	DWORD FillAttribute;
	DWORD WindowFlags;
	DWORD ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
}*PRTL_USER_PROCESS_PARAMETERS;
typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	HANDLE			      Mutant;
	PVOID			      ImageBaseAddress;
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PVOID                         PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, *PPEB;

typedef struct _TEB {
	NT_TIB                  Tib;
	PVOID                   EnvironmentPointer;
	CLIENT_ID               Cid;
	PVOID                   ActiveRpcInfo;
	PVOID                   ThreadLocalStoragePointer;
	PPEB                    Peb;
	ULONG                   LastErrorValue;
	ULONG                   CountOfOwnedCriticalSections;
	PVOID                   CsrClientThread;
	PVOID                   Win32ThreadInfo;
	ULONG                   Win32ClientInfo[0x1F];
	PVOID                   WOW32Reserved;
	ULONG                   CurrentLocale;
	ULONG                   FpSoftwareStatusRegister;
	PVOID                   SystemReserved1[0x36];
	PVOID                   Spare1;
	ULONG                   ExceptionCode;
	ULONG                   SpareBytes1[0x28];
	PVOID                   SystemReserved2[0xA];
	ULONG                   GdiRgn;
	ULONG                   GdiPen;
	ULONG                   GdiBrush;
	CLIENT_ID               RealClientId;
	PVOID                   GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID                   GdiThreadLocaleInfo;
	PVOID                   UserReserved[5];
	PVOID                   GlDispatchTable[0x118];
	ULONG                   GlReserved1[0x1A];
	PVOID                   GlReserved2;
	PVOID                   GlSectionInfo;
	PVOID                   GlSection;
	PVOID                   GlTable;
	PVOID                   GlCurrentRC;
	PVOID                   GlContext;
	ULONG			LastStatusValue;
	UNICODE_STRING          StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[0x105];
	PVOID                   DeallocationStack;
	PVOID                   TlsSlots[0x40];
	LIST_ENTRY              TlsLinks;
	PVOID                   Vdm;
	PVOID                   ReservedForNtRpc;
	PVOID                   DbgSsReserved[0x2];
	ULONG                   HardErrorDisabled;
	PVOID                   Instrumentation[0x10];
	PVOID                   WinSockData;
	ULONG                   GdiBatchCount;
	ULONG                   Spare2;
	ULONG                   Spare3;
	ULONG                   Spare4;
	PVOID                   ReservedForOle;
	ULONG                   WaitingOnLoaderLock;
	PVOID                   StackCommit;
	PVOID                   StackCommitMax;
	PVOID                   StackReserved;
} TEB, *PTEB;


#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))
#define VATORVA(base, addr) ((INT)(addr) - (INT)(base))
#define NTHEADER(hModule)   ((PIMAGE_NT_HEADERS)RVATOVA((hModule), ((PIMAGE_DOS_HEADER)(hModule))->e_lfanew))
#define DATADIRECTORY(pNtHeader, nIndex) &(pNtHeader)->OptionalHeader.DataDirectory[(nIndex)]
#define VALIDRANGE(value, base, size) (((DWORD)(value) >= (DWORD)(base)) && ((DWORD)(value)<((DWORD)(base)+(DWORD)(size))))
#define DLLENTRY(hModule) ((DllEntryProc)RVATOVA ((DWORD)(hModule), NTHEADER(hModule)->OptionalHeader.AddressOfEntryPoint))

#define ENTRYRVA(hModule) (NTHEADER(hModule)->OptionalHeader.AddressOfEntryPoint)
#define SIZEOFIMAGE(hModule) (NTHEADER(hModule)->OptionalHeader.SizeOfImage)
#define IMAGEBASE(hModule) (NTHEADER(hModule)->OptionalHeader.ImageBase)

/*
   __inline__ unsigned long __readfsdword(const unsigned long Offset)
   {
   unsigned long value;
   __asm__("movl %%fs:%a[Offset], %k[value]" : [value] "=q" (value) : [Offset] "irm" (Offset));
   return value;
   }
 */

__inline__ unsigned long readfsteb()
{
	unsigned long value;
	__asm__("movl %%fs:0x18, %k[value]" : [value] "=q" (value));
	return value;
}

__inline__ unsigned long readfspeb()
{
	unsigned long value;
	__asm__("movl %%fs:0x30, %k[value]" : [value] "=q" (value));
	return value;
}

__inline__ void* get_peb_imagebase()
{
	PPEB peb = (PPEB) readfspeb();
	return peb->ImageBaseAddress;
}

__inline__ void set_peb_imagebase(void* imagebase)
{
	PPEB peb = (PPEB) readfspeb();
	peb->ImageBaseAddress = imagebase;
}

__inline__ HMODULE getKernelBase()
{
	PPEB peb = (PPEB) readfspeb();

	PLIST_ENTRY iterEntry 	= peb->Ldr->InInitializationOrderModuleList.Flink;
	PLIST_ENTRY Last = iterEntry;

	PLDR_DATA_TABLE_ENTRY LdrDataEntry;

	do{
		LdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(iterEntry,LDR_DATA_TABLE_ENTRY,InInitializationOrderLinks);

		if (LdrDataEntry->BaseDllName.Length == 24){
			if (LdrDataEntry->BaseDllName.Buffer[0] == 'k'){
				return (HMODULE)LdrDataEntry->DllBase;
			}
		}
		iterEntry = iterEntry->Flink;
	}while (iterEntry != Last);

	return 0;
}


__inline__ int my_stricmp(const char *dst, const char *src)
{
	int ch1, ch2;
	do{
		if ( ((ch1 = (unsigned char)(*(dst++))) >= 'A') &&(ch1 <= 'Z') )
			ch1 += 0x20;
		if ( ((ch2 = (unsigned char)(*(src++))) >= 'A') &&(ch2 <= 'Z') )
			ch2 += 0x20;
	} while ( ch1 && (ch1 == ch2) );
	return(ch1 - ch2);
}

__inline__ int my_imemcpy(char *dest,char *src,int len)
{
	while(--len)
		dest[len] = src[len];
	return 0;
}

__inline__ int my_memcpy(char *dest,char *src,int len)
{
	while(len--)
		*(dest++) = *(src++);
	return 0;
}

__inline__ void * my_memset(void *buffer, int c, int count)
{
	char* p = (char*)buffer;
	while(count--) *p++ = (char)c;
	return buffer;
}

__inline__ wchar_t * my_wstrcpy(wchar_t *pDst, wchar_t *pSrc)
{
	wchar_t *r = pDst;
	while ((*pDst++ = *pSrc++) != '\0')
		continue;
	return r;
}

__inline__ char * my_strcpy(char *pDst, char *pSrc)
{
	char * r = pDst;
	while ((*pDst++ = *pSrc++) != '\0')
		continue;
	return r;
}

__inline__ size_t my_strlen(const char *s)
{
	size_t ret = 0;
	while (s[ret]) 
	{
		ret++;
		continue;
	}
	return ret;
}

__inline__ char * my_strend(char *s)
{
	char * pScan = s;
	while (*pScan)
	{
		pScan++;
		continue;
	}
	return pScan;
}

#define INT_DIGITS 19		/* enough for 64 bit integer */

__inline__ char * my_inttostr(int i, char* buf)
{
	/* Room for INT_DIGITS digits, - and '\0' */
	char *p = buf + INT_DIGITS + 1;	/* points to terminating '\0' */
	*p = '\0';
	if (i >= 0) {
		do {
			*--p = '0' + (i % 10);
			i /= 10;
		} while (i != 0);
		return p;
	}
	else {			/* i < 0 */
		do {
			*--p = '0' - (i % 10);
			i /= 10;
		} while (i != 0);
		*--p = '-';
	}
	return p;
}

//FIXME-FIXME-FIXME-FIXME-FIXME-FIXME-FIXME-FIXME-FIXME-
__inline__ char* my_inttohex(int value, char* buf)
{
	int i,a,b,val;
	unsigned char doval;
	char buffer[2];
	char *p = buf + INT_DIGITS + 1;	/* points to terminating '\0' */
	*p = '\0';

	for (i=0; i<4; i++)
	{
		switch (i){
			case 0: doval = value >> 24 & 0xFF;break;
			case 1: doval = value >> 16 & 0xFF;break;
			case 2: doval = value >> 8  & 0xFF;break;
			case 3: doval = value & 0xFF;break;
		}
		a = doval&16;  //low
		b = (doval>>4)&16; //high

		*--p = (b<10)?'0'+b:'A'-(b-10);
		*--p = (a<10)?'0'+a:'A'-(a-10);
	}

	return p;
}


typedef struct {
	__int64 a;
	__int64 b;
	__int64 c;
	char e;
} __attribute__ ((packed, aligned(1))) INTSTRING;

__inline__ void FillCodeStr(void *fillto, __int64 Astr, __int64 Bstr, __int64 Cstr) 
{	
	INTSTRING *constr = (INTSTRING*)fillto;
	constr->a = Astr;
	constr->b = Bstr;
	constr->c = Cstr;
	constr->e = '\0';
}

__inline__ void PrintHexNumber(PROCLIST *f, int number) {
#ifdef DEBUG_MSG_MODE
	char intbuff[32];
	char *errstr = my_inttohex(number, intbuff);
	char buffer[64];
	INTSTRING *constr = (INTSTRING*)buffer;
	constr->a = 0X6568206775626564LL;
	constr->b = 0X3A65756C61762078LL;
	constr->c = 0X2420LL;
	constr->e = '\0';

	my_strcpy(my_strend(buffer), errstr);
	f->xOutputDebugStringA(buffer);
#endif
}
__inline__ void PrintNumber(PROCLIST *f, int number) {
#ifdef DEBUG_MSG_MODE
	char intbuff[32];
	char *errstr = my_inttostr(number, intbuff);
	char buffer[64];
	INTSTRING *constr = (INTSTRING*)buffer;
	constr->a = 0X756E206775626564LL;
	constr->b = 0X3A7265626DLL;
	constr->c = 0LL;
	constr->e = '\0';

	my_strcpy(my_strend(buffer), errstr);
	f->xOutputDebugStringA(buffer);
#endif
}
__inline__ void PrintString(PROCLIST *f, char *errstr) {
#ifdef DEBUG_MSG_MODE
	char buffer[64];
	INTSTRING *constr = (INTSTRING*)buffer;
	constr->a = 0X7473206775626564LL;
	constr->b = 0X3A676E6972LL;
	constr->c = 0LL;
	constr->e = '\0';

	my_strcpy(my_strend(buffer), errstr);
	f->xOutputDebugStringA(buffer);
#endif
}
__inline__ void PrintLastErr(PROCLIST *f) {
#ifdef DEBUG_MSG_MODE
	char intbuff[32];
	char *errstr = my_inttostr(f->xGetLastError(), intbuff);

	char buffer[64];
	INTSTRING *constr = (INTSTRING*)buffer;
	constr->a = 0X457473614C746547LL;
	constr->b = 0X3A726F7272LL;
	constr->c = 0LL;
	constr->e = '\0';

	my_strcpy(my_strend(buffer), errstr);
	f->xOutputDebugStringA(buffer);
#endif
}

__inline__ void PrintCode(PROCLIST *f, __int64 Astr, __int64 Bstr, __int64 Cstr) {
#ifdef DEBUG_MSG_MODE
	char msgstr[sizeof(INTSTRING)];
	INTSTRING *comint = (INTSTRING*)msgstr;
	comint->a = Astr;
	comint->b = Bstr;
	comint->c = Cstr;
	comint->e = '\0';
	f->xOutputDebugStringA(msgstr);
#endif
}

__inline__ PCHAR lGetModuleName(HMODULE hModule)
{
	PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY) DATADIRECTORY (NTHEADER (hModule), IMAGE_DIRECTORY_ENTRY_EXPORT);
	//if it's a exe file
	if (directory->Size == 0) {
		return NULL;
	}
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) RVATOVA (hModule, directory->VirtualAddress);
	return (PCHAR) RVATOVA(hModule, exports->Name);
}


__inline__ LPDWORD lGetProcEATAddress(HMODULE hModule, PCHAR lpFunName)
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
		pName = (char* ) RVATOVA (hModule, pAddressOfNames[i]);
		if (my_stricmp(pName, lpFunName) == 0)
		{
			return pAddressOfFunctions + pAddressOfOrdinals[i]; 
		}
	}
	return NULL;
}

__inline__ FARPROC lGetProcAddress(HMODULE hModule, PCHAR lpFunName)
{
	LPDWORD pdwEATAddr = lGetProcEATAddress(hModule, lpFunName);
	return (FARPROC) RVATOVA (hModule, *pdwEATAddr);
}

#define id_start	    	0
#define id_virtualAlloc     	0
#define id_virtualFree      	1
#define id_virtualQuery	    	2
#define id_virtualProtect   	3
#define id_loadLibrary      	4
#define id_freeLibrary      	5
#define id_getProcAddress   	6
#define id_getModuleHandle  	7
#define id_outputDebugStringA 	8
#define id_getLastError		9
#define id_unmapViewOfFile 	10 
#define id_closeHandle 		11
#define id_end              	12

__inline__ BOOL initProcList(PROCLIST * f)
{
	HMODULE kernelBase = getKernelBase();
	if (kernelBase == NULL)
		asm ("int $3\n\t" :::);

	typedef char TFunList[id_end][sizeof(INTSTRING)];
	TFunList funNameArray;

	FillCodeStr(&funNameArray[id_virtualAlloc], 0X416C617574726956LL, 0X636F6C6CLL, 0LL);
	FillCodeStr(&funNameArray[id_virtualFree], 0X466C617574726956LL, 0X656572LL, 0LL);
	FillCodeStr(&funNameArray[id_virtualQuery], 0X516C617574726956LL, 0X79726575LL, 0LL);
	FillCodeStr(&funNameArray[id_virtualProtect], 0X506C617574726956LL, 0X746365746F72LL, 0LL);
	FillCodeStr(&funNameArray[id_loadLibrary], 0X7262694C64616F4CLL, 0X41797261LL, 0LL);
	FillCodeStr(&funNameArray[id_getProcAddress],0X41636F7250746547LL, 0X737365726464LL, 0LL);
	FillCodeStr(&funNameArray[id_freeLibrary], 0X7262694C65657246LL, 0X797261LL, 0LL);
	FillCodeStr(&funNameArray[id_getModuleHandle], 0X6C75646F4D746547LL, 0X41656C646E614865LL, 0LL);
	FillCodeStr(&funNameArray[id_outputDebugStringA], 0X654474757074754FLL, 0X6E69727453677562LL, 0X4167LL);
	FillCodeStr(&funNameArray[id_getLastError], 0X457473614C746547LL, 0X726F7272LL, 0LL);
	FillCodeStr(&funNameArray[id_unmapViewOfFile], 0X65695670616D6E55LL, 0X656C6946664F77LL, 0LL);
	FillCodeStr(&funNameArray[id_closeHandle], 0X6E614865736F6C43LL, 0X656C64LL, 0LL);

	PVOID funArray[id_end]; 
	int i;
	for (i = id_start; i < id_end; i++) {
		funArray[i] = NULL;
	}

	funArray[id_getProcAddress] = (void*)lGetProcAddress(kernelBase, (PCHAR)&funNameArray[id_getProcAddress]);   
	if (funArray[id_getProcAddress] == NULL) {return FALSE;}

	GETPROCADDRESS iGetProcAddress = (GETPROCADDRESS)funArray[id_getProcAddress];

	for (i=id_start; i<id_end; i++){
		if (funArray[i] == NULL){
			funArray[i] = (PVOID)iGetProcAddress(kernelBase, (PCHAR)&funNameArray[i]);
		}
	}


	for (i=id_start; i<id_end; i++){
		//        printf("function %s is %p \n", funNameArray[i], funArray[i]);
		if (funArray[i] == NULL) {return FALSE;}
	}

	f->xVirtualAlloc = (VIRTUALALLOC) funArray[id_virtualAlloc];
	f->xVirtualFree = (VIRTUALFREE)funArray[id_virtualFree];
	f->xVirtualQuery = (VIRTUALQUERY)funArray[id_virtualQuery];
	f->xVirtualProtect = (VIRTUALPROTECT)funArray[id_virtualProtect];
	f->xLoadLibrary = (LOADLIBRARY)funArray[id_loadLibrary];
	f->xFreeLibrary = (FREELIBRARY)funArray[id_freeLibrary];
	f->xGetProcAddress = (GETPROCADDRESS)funArray[id_getProcAddress];
	f->xGetModuleHandle = (GETMODULEHANDLE)funArray[id_getModuleHandle];
	f->xOutputDebugStringA = (OUTPUTDEBUGSTRINGA)funArray[id_outputDebugStringA];
	f->xGetLastError = (GETLASTERROR)funArray[id_getLastError];
	f->xUnmapViewOfFile = (UNMAPVIEWOFFILE)funArray[id_unmapViewOfFile];
	f->xCloseHandle= (CLOSEHANDLE)funArray[id_closeHandle];
	return TRUE;
}

__inline__ long reset_proclist(PROCLIST* local, PROCLIST* input)
{	
	do {
		if (input != NULL) {            
			if (input->xVirtualAlloc != NULL) {
				*local = *input;
				break;
			}
		}
		if (!initProcList(local)) {
			return (0);
		}
		if (input != NULL) {
			*input = *local;
		}
	} while (FALSE);
	return (1);
}

__inline__ DWORD Rva2FileRva(LPVOID pFileBase, DWORD Rva)
{
	if (Rva == 0) {
		return 0;
	}

	PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER (pFileBase);
	PIMAGE_SECTION_HEADER enumSection = IMAGE_FIRST_SECTION (pNtHeader_File);

	int i, size;
	for (i=0; i<pNtHeader_File->FileHeader.NumberOfSections; i++, enumSection++){
		if (enumSection->SizeOfRawData == 0){
			continue;
		}
		if (VALIDRANGE (Rva, enumSection->VirtualAddress, enumSection->SizeOfRawData)) {
			return (enumSection->PointerToRawData + (Rva - enumSection->VirtualAddress));
		}
	}
	return 0; 
}

__inline__ HMODULE CallDllFileEntry (LPVOID pFileBase, LPVOID lpReserved)
{
	PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER (pFileBase);
	DWORD dwEntryOfFile = Rva2FileRva (pFileBase, pNtHeader_File->OptionalHeader.AddressOfEntryPoint);
	if (dwEntryOfFile == 0) {
		return 0;
	}
	DllEntryProcH fnEntry = (DllEntryProcH) RVATOVA (pFileBase, dwEntryOfFile);
	HMODULE dwRet = fnEntry ((HINSTANCE) pFileBase, DLL_PROCESS_ATTACH, lpReserved);
	return dwRet;
}

#define E_SYMNMLEN	8	/* # characters in a symbol name	*/
typedef struct  {
	union {
		char e_name[E_SYMNMLEN];
		struct {
			unsigned long e_zeroes;
			unsigned long e_offset;
		} e;
	} e;
	unsigned long e_value;
	short e_scnum;
	unsigned short e_type;
	unsigned char e_sclass;
	unsigned char e_numaux;
} __attribute__((packed,aligned(2))) SYMENT;

__inline__ int GuessFileSize (LPVOID lpFileBase) 
{
	PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER(lpFileBase);
	PIMAGE_SECTION_HEADER enumSection = IMAGE_FIRST_SECTION(pNtHeader_File);

	int nResultSize = pNtHeader_File->OptionalHeader.SizeOfHeaders;
	int i;

	for (i=0; i<pNtHeader_File->FileHeader.NumberOfSections; i++) {
		nResultSize += enumSection[i].SizeOfRawData;
	}

	if ( pNtHeader_File->FileHeader.NumberOfSymbols == 0){
		return nResultSize;
	}

	int nSymbolSize = pNtHeader_File->FileHeader.NumberOfSymbols * sizeof(SYMENT);
	int nStringsSize = *(PDWORD)((DWORD)lpFileBase + pNtHeader_File->FileHeader.PointerToSymbolTable + nSymbolSize);

	return nResultSize + nSymbolSize + nStringsSize;
}


typedef struct _SECTION_BACKUP {
	void *address;
	size_t size;
	long characteristics;
} SECTION_BACKUP, *LPSECTION_BACKUP;

__inline__  LPSECTION_BACKUP MapSections (PROCLIST *f, PCHAR pImageBase, PCHAR pFileBase)
{
	LPSECTION_BACKUP backup = (LPSECTION_BACKUP)f->xVirtualAlloc(NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	my_memset(backup, 0, 1024);

	PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER(pFileBase);
	PIMAGE_SECTION_HEADER enumSection = IMAGE_FIRST_SECTION(pNtHeader_File);

	PCHAR destCopy;
	int i, size;
	void* address;
	LPSECTION_BACKUP enumbk = backup;
	for (i=0; i<pNtHeader_File->FileHeader.NumberOfSections; i++, enumSection++, enumbk++)
	{
		size = enumSection->SizeOfRawData;
		if (size < enumSection->Misc.VirtualSize) {
			size = enumSection->Misc.VirtualSize;
		}

		address = f->xVirtualAlloc(pImageBase + enumSection->VirtualAddress, size, MEM_COMMIT, PAGE_READWRITE);
		if (address == NULL){
			PrintCode(f, 0X416C617574726956LL, 0X72726520636F6C6CLL, 0X726FLL);//VirtualAlloc error
		}

		my_memset(address, 0, size);
		if (enumSection->PointerToRawData != 0)
			my_memcpy((char*)address, pFileBase + enumSection->PointerToRawData, enumSection->SizeOfRawData);

		enumbk->address = address;
		enumbk->size = size;
		enumbk->characteristics = enumSection->Characteristics;
	}

	return backup;
}

// Protection flags for memory pages (Executable, Readable, Writeable)
//static int ProtectionFlags[2][2][2] = {
//	{
//		// not executable
//		{PAGE_NOACCESS, PAGE_WRITECOPY},
//		{PAGE_READONLY, PAGE_READWRITE},
//	}, {
//		// executable
//		{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
//		{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
//	},
//};

__inline__ void FinalizeSections(PROCLIST * f, LPSECTION_BACKUP backup)
{
	LPSECTION_BACKUP enumbk = backup;

	while (enumbk->address) {
		if (enumbk->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			// section is not needed any more and can safely be freed
			MEMORY_BASIC_INFORMATION mbi;
			f->xVirtualQuery(enumbk->address, &mbi, sizeof(mbi));

			if (FALSE == f->xVirtualFree(mbi.BaseAddress, mbi.RegionSize, MEM_DECOMMIT)) {
				PrintCode(f, 0X7369642065657266LL, 0X6D656D2064726163LL, 0X726F72726520LL);//free discard mem error
			}
			enumbk++;
			continue;
		}

		DWORD protect, oldProtect, size;
		int executable = (enumbk->characteristics & IMAGE_SCN_MEM_EXECUTE) ?1:0;
		int readable =   (enumbk->characteristics & IMAGE_SCN_MEM_READ) ?1:0;
		int writeable =  (enumbk->characteristics & IMAGE_SCN_MEM_WRITE) ?1:0;

		// determine protection flags based on characteristics
		DWORD flags[2][2][2];
		flags[0][0][0] = PAGE_NOACCESS;
		flags[0][0][1] = PAGE_WRITECOPY;
		flags[0][1][0] = PAGE_READONLY;
		flags[0][1][1] = PAGE_READWRITE;
		flags[1][0][0] = PAGE_EXECUTE;
		flags[1][0][1] = PAGE_EXECUTE_WRITECOPY;
		flags[1][1][0] = PAGE_EXECUTE_READ;
		flags[1][1][1] = PAGE_EXECUTE_READWRITE;

		protect = flags[executable][readable][writeable];
		if (enumbk->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
			protect |= PAGE_NOCACHE;
		}


		MEMORY_BASIC_INFORMATION mbi;
		f->xVirtualQuery(enumbk->address, &mbi, sizeof(mbi));

		if (FALSE == f->xVirtualProtect(mbi.BaseAddress, mbi.RegionSize, protect, &oldProtect)){
			PrintCode(f, 0X727020726F727245LL, 0X676E69746365746FLL, 0X79726F6D656D20LL);//Error protecting memory
			PrintNumber(f, (int)protect);
		}
		enumbk++;
	}
	f->xVirtualFree(backup, 0, MEM_RELEASE);
}

__inline__ void PerformBaseRelocation(HMODULE hModule, SIZE_T delta)
{
	PIMAGE_NT_HEADERS pNtHeader = NTHEADER(hModule);
	PIMAGE_DATA_DIRECTORY pDirectory = DATADIRECTORY(pNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	if (pDirectory->Size > 0) {
		PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)RVATOVA(hModule, pDirectory->VirtualAddress);
		for (; relocation->VirtualAddress > 0; ) {
			unsigned char *dest = (unsigned char *)RVATOVA(hModule, relocation->VirtualAddress);  
			unsigned short *relInfo = (unsigned short *)((unsigned char *)relocation + IMAGE_SIZEOF_BASE_RELOCATION);
			DWORD i;
			for (i=0; i<((relocation->SizeOfBlock-IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
				DWORD *patchAddrHL;
#ifdef _WIN64
				ULONGLONG *patchAddr64;
#endif
				int type, offset;
				// the upper 4 bits define the type of relocation
				type = *relInfo >> 12;
				// the lower 12 bits define the offset
				offset = *relInfo & 0xfff;
				switch (type)
				{
					case IMAGE_REL_BASED_ABSOLUTE:
						// skip relocation
						break;
					case IMAGE_REL_BASED_HIGHLOW:
						// change complete 32 bit address
						patchAddrHL = (DWORD *) (dest + offset);
						*patchAddrHL += delta;
						break;
#ifdef _WIN64
					case IMAGE_REL_BASED_DIR64:
						patchAddr64 = (ULONGLONG *) (dest + offset);
						*patchAddr64 += delta;
						break;
#endif
					default:
						//printf("Unknown relocation: %d\n", type);
						break;
				}
			}
			// advance to next relocation block
			relocation = (PIMAGE_BASE_RELOCATION) (((char *) relocation) + relocation->SizeOfBlock);
		}
	}
}

__inline__ void HandleTls(PROCLIST *f, HMODULE hModule)
{
	PIMAGE_NT_HEADERS pNtHeaders = NTHEADER(hModule);
	PIMAGE_DATA_DIRECTORY directory = DATADIRECTORY(pNtHeaders, IMAGE_DIRECTORY_ENTRY_TLS);
	if (directory->Size == 0) return;
	int tls_section_count = directory->Size / sizeof(IMAGE_TLS_DIRECTORY);
	PIMAGE_TLS_DIRECTORY32 pTlsDir = (PIMAGE_TLS_DIRECTORY)RVATOVA(hModule, directory->VirtualAddress);

	PrintNumber(f, directory->Size);

//	ULONG TlsInitDataSize = pTlsDir->EndAddressOfRawData - pTlsDir->StartAddressOfRawData; 
//	ULONG TlsSize = (pTlsDir->EndAddressOfRawData - pTlsDir->StartAddressOfRawData) + pTlsDir->SizeOfZeroFill;
//	PVOID *ThreadLocalStoragePointer = (PVOID*)f->xVirtualAlloc(NULL, TlsSize + sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//
//	UCHAR *pData = (UCHAR*)ThreadLocalStoragePointer + sizeof(PVOID);
//	my_memcpy((char*)pData, (char*)(pTlsDir->StartAddressOfRawData), TlsInitDataSize);
//	my_memset( (char*)pData + TlsInitDataSize, 0, pTlsDir->SizeOfZeroFill );
	
//	PTEB teb = (PTEB)readfsteb();
//	teb->ThreadLocalStoragePointer = ThreadLocalStoragePointer;
//	ThreadLocalStoragePointer[0] = (PVOID)pData;

	//asm ("int $3\n\t" :::);

	int i;
	for (i=0; i<tls_section_count; i++)
	{
		if (pTlsDir[i].AddressOfCallBacks)
		{
			PVOID * pCallbacks = (PVOID*)(pTlsDir[i].AddressOfCallBacks);
			PrintNumber(f, (long)pCallbacks);
			PrintNumber(f, (long)*pCallbacks);
			while (*pCallbacks)
			{
				PIMAGE_TLS_CALLBACK  pTlsCallback = (PIMAGE_TLS_CALLBACK)*pCallbacks;
				PrintCode(f, 0X20736C74206E7572LL, 0X6B6361626C6C6163LL, 0X7972746E6520LL);//run tls callback entry
				pTlsCallback(hModule, DLL_PROCESS_ATTACH, 0);
				pCallbacks++;
			}
		}
	}
}

__inline__ void FreeImportedDll(PROCLIST *f, HMODULE hModule)
{
	PIMAGE_NT_HEADERS pNtHeaders = NTHEADER(hModule);
	PIMAGE_DATA_DIRECTORY directory = DATADIRECTORY(pNtHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size == 0){
		return;
	}
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)RVATOVA(hModule, directory->VirtualAddress);
	DWORD nSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;

	while (VALIDRANGE(importDesc, hModule, nSizeOfImage) && (importDesc->Name)){
		LPCSTR pName = (LPCSTR)RVATOVA(hModule, importDesc->Name);
		HMODULE handle = f->xGetModuleHandle(pName);
		if (handle != INVALID_HANDLE_VALUE) {
			f->xFreeLibrary(handle);
		}
		importDesc++;
	}
	return;
}

	__inline__ BOOL
BuildImportTable(PROCLIST *f, HMODULE hModule)
{
	PIMAGE_NT_HEADERS pNtHeaders = NTHEADER(hModule);
	PIMAGE_DATA_DIRECTORY directory = DATADIRECTORY(pNtHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size == 0){
		return TRUE;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)RVATOVA(hModule, directory->VirtualAddress);
	DWORD nSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;

	POINTER_TYPE *thunkRef;
	FARPROC *funcRef;
	char* lib_name;
	char* fun_name;
	int fun_is_ordinal;
	HMODULE hLib_import;
	while (VALIDRANGE(importDesc, hModule, nSizeOfImage) && (importDesc->Name))
	{
		lib_name = (char*)RVATOVA(hModule, importDesc->Name);

		hLib_import = f->xGetModuleHandle(lib_name);
		if (hLib_import == NULL)
		{
			PrintString(f, lib_name);
			hLib_import = f->xLoadLibrary(lib_name);
		}

		if (hLib_import == NULL) {
			PrintLastErr(f);
			PrintCode(f, 0X6C2074726F706D69LL, 0X6520797261726269LL, 0X726F7272LL);//import library error
			return FALSE;
		}

		if (importDesc->OriginalFirstThunk)
		{
			thunkRef = (POINTER_TYPE *) RVATOVA (hModule, importDesc->OriginalFirstThunk);
		}
		else
		{
			thunkRef = (POINTER_TYPE *) RVATOVA (hModule, importDesc->FirstThunk);
		}
		funcRef = (FARPROC *) RVATOVA (hModule, importDesc->FirstThunk);

		for (; *thunkRef; thunkRef++, funcRef++) 
		{
			fun_is_ordinal = IMAGE_SNAP_BY_ORDINAL(*thunkRef); 	

			if (fun_is_ordinal) 
			{
				fun_name =  (char*)IMAGE_ORDINAL(*thunkRef);
			}
			else 
			{
				PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME) RVATOVA (hModule, *thunkRef);
				fun_name = (char*)thunkData->Name;
			}

			*funcRef = (FARPROC)f->xGetProcAddress(hLib_import, fun_name);

			if (*funcRef == 0) 
			{
				if (fun_is_ordinal) 
					PrintNumber(f, (long)fun_name);
				else
					PrintString(f, fun_name);
				PrintCode(f, 0X662074726F706D69LL, 0X206E6F6974636E75LL, 0X726F727265LL);//import function error
				return FALSE;
			}
		}
		importDesc++;
	}
	return TRUE;
}


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

__inline__ HMODULE lLoadLibrary(LPVOID lpFileBase, LPVOID lpReserved)
{
	return __lLoadLibrary (NULL, NULL, lpFileBase, lpReserved);
}

__inline__ HMODULE __lLoadLibrary(PROCLIST *fns, LPMODITEM NotifyMods, LPVOID lpFileBase, LPVOID lpReserved)
{
	//relocation main function from peb structure
	PROCLIST f;
	do {
		if (fns != NULL) {            
			if (fns->xVirtualAlloc != NULL) {
				f = *fns;
				break;
			}
		}
		if (!initProcList(&f)) {
			return ERROR_INITIAL_FUNCTIONS;
		}
		if (fns != NULL) {
			*fns = f;
		}
	} while (FALSE);

	PrintCode(&f, 0X65746E65202D2D2DLL, 0X696C64616F6C2072LL, 0X2D2D207972617262LL);//--- enter loadlibrary --

	if (lpFileBase == NULL) {
		return ERROR_INVALID_IMAGE;
	}

	PrintCode(&f, 0X7361626567616D69LL, 0X6C61762073692065LL, 0X6469LL); //imagebase is valid:

	//define all needs var
	PIMAGE_DOS_HEADER pDosHeader_File = (PIMAGE_DOS_HEADER)lpFileBase;
	PIMAGE_NT_HEADERS pNtHeader_File, pNtHeaders;
	SIZE_T locationDelta;
	PCHAR pImageBase, headers;

	//check the image file
	if (pDosHeader_File->e_magic != IMAGE_DOS_SIGNATURE){
		return ERROR_DOS_HEADER;
	}
	pNtHeader_File = (PIMAGE_NT_HEADERS)&((PCHAR)(lpFileBase))[pDosHeader_File->e_lfanew];
	if (pNtHeader_File->Signature != IMAGE_NT_SIGNATURE){
		return ERROR_NT_HEADERS;
	}
	PrintCode(&f, 0X5020612073277469LL, 0X74616D726F662045LL, 0X656C696620LL);//it's a PE format file

	//alloc memory for the whole image
	pImageBase = (PCHAR)f.xVirtualAlloc(NULL, pNtHeader_File->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
	if (pImageBase == NULL) {
		return ERROR_ALLOC_RESERVE;
	}
	PrintCode(&f, 0X6D6920636F6C6C61LL, 0X656D207327656761LL, 0X6B6F2079726F6DLL);//alloc image's memory ok

	//    //alloc and copy PE header to memory
	//    f.xVirtualAlloc(pImageBase, pNtHeader_File->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	//    PrintCode(&f, 0X2045502079706F63LL, 0X726564616568LL, 0LL);//copy PE header

	headers = (PCHAR)f.xVirtualAlloc(pImageBase, pNtHeader_File->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);

	PrintCode(&f, 0X6165682079706F63LL, 0X73726564LL, 0LL);//copy headers
	my_memcpy(headers, (PCHAR)pDosHeader_File, pNtHeader_File->OptionalHeader.SizeOfHeaders);

	PrintCode(&f, 0X506C617574726956LL, 0X6820746365746F72LL, 0X7265646165LL);//VirtualProtect header
	DWORD OldProtect;
	f.xVirtualProtect(headers, pNtHeader_File->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &OldProtect);

	PrintCode(&f, 0X6F63207472617473LL, 0X6974636573207970LL, 0X736E6FLL);//start copy sections
	pNtHeaders = (PIMAGE_NT_HEADERS)&((PCHAR)(headers))[pDosHeader_File->e_lfanew];
	HMODULE nErrCode = 0;
	LPSECTION_BACKUP backup;
	do{
		//copy all sections from dll to the new image base address 
		backup = MapSections (&f, pImageBase, (PCHAR)lpFileBase);
		if (!backup){
			nErrCode = ERROR_COPYSECTIONS;
			break;
		}

		PrintCode(&f, 0X6168207472617473LL, 0X6C657220656C646ELL, 0X736E6F697461636FLL);//start handle relocations
		//adjust the base address of imported data
		locationDelta = (SIZE_T)(pImageBase - pNtHeader_File->OptionalHeader.ImageBase);
		if (locationDelta != 0) {
			PerformBaseRelocation ((HMODULE)pImageBase, locationDelta);
		} 

		PrintCode(&f, 0X7562207472617473LL, 0X6F706D6920646C69LL, 0X656C626174207472LL);//start build import table
		// load required dlls and adjust function table of imports
		if (!BuildImportTable(&f, (HMODULE)pImageBase)) {
			nErrCode = ERROR_FIX_IMPORTTABLE;
			break;
		}

		PrintCode(&f, 0X7463657320746573LL, 0X6D207327736E6F69LL, 0X67616C66206D65LL);//setsections's mem flag
		do{
			// set sections that are marked as "discardable"
			FinalizeSections(&f, backup);
			PrintCode(&f, 0X72746E6520746567LL, 0X7365726464612079LL, 0X73LL);//get entry address

			// get entry point of loaded library
			if (pNtHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
				DllEntryProc DllEntry = (DllEntryProc) RVATOVA (pImageBase, pNtHeaders->OptionalHeader.AddressOfEntryPoint);
				if (DllEntry == 0) {
					nErrCode = ERROR_NOTFOUND_ENTRY;
					break; 
				}

				PrintCode(&f, 0X6F20796669746F6ELL, 0X646F6D2072656874LL, 0X73656C75LL);//notify other modules

				//notify other modules: i am here, plese fixed me.
				if (NotifyMods) {
					while (NotifyMods->hModule) {
						if ((DWORD)(NotifyMods->hModule) != (DWORD)(NotifyMods->fnEntry)) 
							NotifyMods->fnEntry (NotifyMods->hModule, DLL_MODULE_ATTACH, (LPVOID)pImageBase);
						NotifyMods++;
					}
				}

				PrintCode(&f, 0X6C6C64206C6C6163LL, 0X7972746E6520LL, 0LL);//call dll entry

				// notify library about attaching to process
				BOOL successfull = DllEntry ((HINSTANCE) pImageBase, DLL_PROCESS_ATTACH, lpReserved);
				if (!successfull) {
					nErrCode = ERROR_ENTRY_RET_FALSE;
					break;
				}
			}

			PrintCode(&f, 0X68206873696E6966LL, 0X6F7220656C646E61LL, 0X656E697475LL);//finish handle routine
			//run to the end ,succeed.
			return (HMODULE) pImageBase;
		}while (FALSE);

		PrintCode(&f, 0X6F72726520736168LL, 0X2065657266202C72LL, 0X736C6C64LL);//has error, free dlls

		FreeImportedDll (&f, (HMODULE)pImageBase);
	}while (FALSE);

	PrintCode(&f, 0X6F72726520736168LL, 0X2065657266202C72LL, 0X79726F6D656DLL);//has error, free memory

	//collect the error and retren.
	f.xVirtualFree (pImageBase, 0, MEM_RELEASE);
	return nErrCode;
}

#define EXE_LOADER_RESERVE_SIZE (0x1000 * 0x1000)

typedef 
int (APIENTRY *WINMAIN)(
		HINSTANCE hInstance,
		HINSTANCE hPrevInstance,
		LPSTR lpCmdLine,
		int nCmdShow
		);


__inline__ long get_ebproot()
{
	long output = 0;
	asm (
		"movl %%ebp, %0\n"
		:"=r" (output): :
	);
	return output;
}

__inline__ void recall_ebproot(long root_val, long callto)
{
	asm (
		"movl %0, %%esp\n"
		"popl %%ebp\n"
		"pushl %1\n"
		"ret\n"
		:: "r"(root_val),"r"(callto):
	);
}

__inline__ void back_ebproot(long root_val)
{
	asm (
		"movl %0, %%esp\n"
		"popl %%ebp\n"
		"ret\n"
		:: "r"(root_val):
	);
}

__inline__ void* hook_ebproot(long root_val, void *hookto)
{
	long *retaddr = (long*)(root_val + sizeof(long));
	void *ori_addr = (void*)*retaddr;
	*retaddr = (long)hookto;
	return ori_addr;
}

__inline__ void* get_whocallme()
{
	long ebp_val = get_ebproot();
	void *retaddr = (void*)  *((long*)(ebp_val+sizeof(void*)));
	return retaddr;

}

DWORD __inline__ __round_up(DWORD val,DWORD alignment)
{
	if( val % alignment )
		return (val + (alignment - (val % alignment)));
	return val;
}


__inline__ HMODULE iLoadExeImage(PROCLIST *fns, LPMODITEM NotifyMods, long ebp_root, LPVOID lpFileBase, LPSTR lpCmdLine, int nCmdShow)
{
	//relocation main function from peb structure
	PROCLIST f;
	do {
		if (fns != NULL) {            
			if (fns->xVirtualAlloc != NULL) {
				f = *fns;
				break;
			}
		}
		if (!initProcList(&f)) {
			return ERROR_INITIAL_FUNCTIONS;
		}
		if (fns != NULL) {
			*fns = f;
		}
	} while (FALSE);

	PrintCode(&f, 0X65746E65202D2D2DLL, 0X696C64616F6C2072LL, 0X2D2D207972617262LL);//--- enter loadlibrary --

	if (lpFileBase == NULL) {
		return ERROR_INVALID_IMAGE;
	}

	//define all needs var
	PIMAGE_DOS_HEADER pDosHeader_File = (PIMAGE_DOS_HEADER)lpFileBase;
	PIMAGE_NT_HEADERS pNtHeader_File, pNtHeaders;
	SIZE_T locationDelta;
	PCHAR pImageBase, headers;

	//check the image file
	if (pDosHeader_File->e_magic != IMAGE_DOS_SIGNATURE){
		return ERROR_DOS_HEADER;
	}
	pNtHeader_File = (PIMAGE_NT_HEADERS)&((PCHAR)(lpFileBase))[pDosHeader_File->e_lfanew];
	if (pNtHeader_File->Signature != IMAGE_NT_SIGNATURE){
		return ERROR_NT_HEADERS;
	}
	PrintCode(&f, 0X5020612073277469LL, 0X74616D726F662045LL, 0X656C696620LL);//it's a PE format file

	int need_image_size = pNtHeader_File->OptionalHeader.SizeOfImage;
	char *reserved_base = (char*)pNtHeader_File->OptionalHeader.ImageBase;
	MEMORY_BASIC_INFORMATION mbi;

	if (f.xVirtualQuery(reserved_base, &mbi, sizeof(mbi)) == 0)
	{
		PrintCode(&f, 0X516C617574726956LL, 0X5252452079726575LL, 0X524FLL);//VirtualQuery ERROR
		PrintLastErr(&f);
		return ERROR_ALLOC_RESERVE;
	}

	void* old_imagebase = get_peb_imagebase();
	//f.xCloseHandle((HANDLE)4);
	if (FALSE == f.xUnmapViewOfFile(old_imagebase))
	{
		PrintLastErr(&f);
		PrintCode(&f, 0X65695670616D6E55LL, 0X20656C6946664F77LL, 0X726F727265LL);//UnmapViewOfFile error
		return ERROR_ALLOC_RESERVE;
	}

	//alloc memory for the whole image, this exe, must be uses the defined value
	pImageBase = (PCHAR)f.xVirtualAlloc((LPVOID)pNtHeader_File->OptionalHeader.ImageBase, need_image_size, MEM_RESERVE, PAGE_NOACCESS);
	if (pImageBase == NULL) {
		PrintLastErr(&f);
		PrintCode(&f, 0X6D4920636F6C6C41LL, 0X2065736142656761LL, 0X726F727265LL);//Alloc ImageBase error
		return ERROR_ALLOC_RESERVE;
	}
	PrintCode(&f, 0X6D6920636F6C6C61LL, 0X656D207327656761LL, 0X6B6F2079726F6DLL);//alloc image's memory ok

	headers = (PCHAR)f.xVirtualAlloc(pImageBase, pNtHeader_File->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
	set_peb_imagebase((void*)headers);

	PrintCode(&f, 0X6165682079706F63LL, 0X73726564LL, 0LL);//copy headers
	my_memcpy(headers, (PCHAR)pDosHeader_File, pNtHeader_File->OptionalHeader.SizeOfHeaders);

	PrintCode(&f, 0X506C617574726956LL, 0X6820746365746F72LL, 0X7265646165LL);//VirtualProtect header
	DWORD OldProtect;
	f.xVirtualProtect(headers, pNtHeader_File->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &OldProtect);

	PrintCode(&f, 0X6F63207472617473LL, 0X6974636573207970LL, 0X736E6FLL);//start copy sections
	pNtHeaders = (PIMAGE_NT_HEADERS)&((PCHAR)(headers))[pDosHeader_File->e_lfanew];
	HMODULE nErrCode = 0;
	LPSECTION_BACKUP backup;
	do{
		//copy all sections from dll to the new image base address 
		backup = MapSections (&f, pImageBase, (PCHAR)lpFileBase);
		if (!backup){
			nErrCode = ERROR_COPYSECTIONS;
			break;
		}

		PrintCode(&f, 0X6168207472617473LL, 0X6C657220656C646ELL, 0X736E6F697461636FLL);//start handle relocations
		//adjust the base address of imported data
		locationDelta = (SIZE_T)(pImageBase - pNtHeader_File->OptionalHeader.ImageBase);
		if (locationDelta != 0) {
			PerformBaseRelocation ((HMODULE)pImageBase, locationDelta);
		} 

		PrintCode(&f, 0X7562207472617473LL, 0X6F706D6920646C69LL, 0X656C626174207472LL);//start build import table
		// load required dlls and adjust function table of imports
		if (!BuildImportTable(&f, (HMODULE)pImageBase)) {
			nErrCode = ERROR_FIX_IMPORTTABLE;
			break;
		}

		PrintCode(&f, 0X7463657320746573LL, 0X6D207327736E6F69LL, 0X67616C66206D65LL);//setsections's mem flag
		do{
			// set sections that are marked as "discardable"
			FinalizeSections(&f, backup);
			PrintCode(&f, 0X72746E6520746567LL, 0X7365726464612079LL, 0X73LL);//get entry address

			HandleTls(&f, (HMODULE)pImageBase);

			// get entry point of loaded library
			if (pNtHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
				WINMAIN winmain = (WINMAIN) RVATOVA (pImageBase, pNtHeaders->OptionalHeader.AddressOfEntryPoint);
				if (winmain== 0) {
					nErrCode = ERROR_NOTFOUND_ENTRY;
					break; 
				}

				PrintCode(&f, 0X6F20796669746F6ELL, 0X646F6D2072656874LL, 0X73656C75LL);//notify other modules

				//notify other modules: i am here, plese fixed me.
				if (NotifyMods) {
					while (NotifyMods->hModule) {
						if ((DWORD)(NotifyMods->hModule) != (DWORD)(NotifyMods->fnEntry)) 
							NotifyMods->fnEntry (NotifyMods->hModule, DLL_MODULE_ATTACH, (LPVOID)pImageBase);
						NotifyMods++;
					}
				}

				PrintCode(&f, 0X6C6C64206C6C6163LL, 0X7972746E6520LL, 0LL);//call dll entry

				if (ebp_root)	
				{
					//asm ("int $3\n\t" :::);
					//this call will run without return.
					recall_ebproot(ebp_root, (long)winmain);
				} 
				else
				{
					// notify library about attaching to process
					BOOL successfull = winmain((HINSTANCE) pImageBase, NULL, lpCmdLine, nCmdShow);
					if (!successfull) {
						nErrCode = ERROR_ENTRY_RET_FALSE;
						break;
					}
				}
			}

			PrintCode(&f, 0X68206873696E6966LL, 0X6F7220656C646E61LL, 0X656E697475LL);//finish handle routine
			//run to the end ,succeed.
			return (HMODULE) pImageBase;
		}while (FALSE);

		PrintCode(&f, 0X6F72726520736168LL, 0X2065657266202C72LL, 0X736C6C64LL);//has error, free dlls

		FreeImportedDll (&f, (HMODULE)pImageBase);
	}while (FALSE);

	PrintCode(&f, 0X6F72726520736168LL, 0X2065657266202C72LL, 0X79726F6D656DLL);//has error, free memory

	//collect the error and retren.
	f.xVirtualFree (pImageBase, 0, MEM_RELEASE);
	return nErrCode;
}

__inline__ HMODULE only_map_exe(PROCLIST *fns, char* lpFileBase, void* parameter)
{
	//relocation main function from peb structure
	PROCLIST f;
	if (0 == reset_proclist(&f, fns))
		return ERROR_INITIAL_FUNCTIONS;

	void* old_imagebase = get_peb_imagebase();

	PrintCode(&f, 0X65746E65202D2D2DLL, 0X70616D6578652072LL, 0X2D2D2D20726570LL);//--- enter exemapper ---
	if (FALSE == f.xUnmapViewOfFile(old_imagebase))
	{
		PrintLastErr(&f);
		PrintCode(&f, 0X65695670616D6E55LL, 0X20656C6946664F77LL, 0X726F727265LL);//UnmapViewOfFile error
		return ERROR_ALLOC_RESERVE;
	}

	//alloc memory for the whole image, this exe, must be uses the defined value
	void* new_imagebase = (void*)IMAGEBASE(lpFileBase);
	char* pImageBase = (char*)f.xVirtualAlloc(new_imagebase, SIZEOFIMAGE(lpFileBase), MEM_RESERVE, PAGE_NOACCESS);
	if (pImageBase == NULL) {
		PrintLastErr(&f);
		PrintCode(&f, 0X6D4920636F6C6C41LL, 0X2065736142656761LL, 0X726F727265LL);//Alloc ImageBase error
		return ERROR_ALLOC_RESERVE;
	}

	PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER(lpFileBase);
	new_imagebase = (PCHAR)f.xVirtualAlloc(pImageBase, pNtHeader_File->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
	set_peb_imagebase(new_imagebase);

	my_memcpy(pImageBase, lpFileBase, pNtHeader_File->OptionalHeader.SizeOfHeaders);

	HMODULE nErrCode = 0;
	DWORD OldProtect;
	f.xVirtualProtect(new_imagebase, pNtHeader_File->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &OldProtect);

	do{
		PrintCode(&f, 0X6F63207472617473LL, 0X6974636573207970LL, 0X736E6FLL);//start copy sections
		//copy all sections from dll to the new image base address 
		LPSECTION_BACKUP backup = MapSections (&f, pImageBase, (PCHAR)lpFileBase);
		if (!backup){
			nErrCode = ERROR_COPYSECTIONS;
			break;
		}

		PrintCode(&f, 0X6168207472617473LL, 0X6C657220656C646ELL, 0X736E6F697461636FLL);//start handle relocations
		//adjust the base address of imported data
		long locationDelta = (long)(pImageBase - pNtHeader_File->OptionalHeader.ImageBase);
		if (locationDelta != 0) {
			PerformBaseRelocation ((HMODULE)pImageBase, locationDelta);
		} 

		PrintCode(&f, 0X7562207472617473LL, 0X6F706D6920646C69LL, 0X656C626174207472LL);//start build import table
		// load required dlls and adjust function table of imports
		if (!BuildImportTable(&f, (HMODULE)pImageBase)) {
			nErrCode = ERROR_FIX_IMPORTTABLE;
			break;
		}

		PrintCode(&f, 0X7463657320746573LL, 0X6D207327736E6F69LL, 0X67616C66206D65LL);//setsections's mem flag
		// set sections that are marked as "discardable"
		FinalizeSections(&f, backup);

		HandleTls(&f, (HMODULE)pImageBase);

		return (HMODULE)pImageBase;
	}while (FALSE);

	PrintCode(&f, 0X6F72726520736168LL, 0X2065657266202C72LL, 0X79726F6D656DLL);//has error, free memory
	return nErrCode;
}


/*  
    __inline__ void* readMyAddr()
    {
    void* value;
    __asm__("call next\n"
    "next:\n\t"
    "popl %0\n\t" 
    :"=m" (value):);
    return value;
    }
 */
#define HANDLES_BUFFER_LENGTH 0x1000

__inline__ HMODULE __LoadFromTail (LPVOID pAddrOfBlock, DWORD dwSizeOfOurself,  LPVOID lpReserved)
{
	PROCLIST fns;
	fns.xVirtualAlloc = NULL;

	int i;
	PCHAR lpFileBase = (PCHAR)pAddrOfBlock + dwSizeOfOurself;
	LPMODITEM ModLists = NULL;
	DWORD dwModuleCount = 0;
	DWORD dwFileSize = 0;
	HMODULE hModule = NULL;
	DWORD dwHandledSize = dwSizeOfOurself;
	PCHAR szBaseOfCode = lpFileBase - dwSizeOfOurself;

	do {
		//load up the library
		hModule = __lLoadLibrary (&fns, ModLists, (void*)lpFileBase, lpReserved);
		if ((DWORD)hModule < 32) {
			break;
		}

		PrintCode(&fns, 0X65756E69746E6F63LL, 0X746F2064616F6C20LL, 0X736C6C6420726568LL);//continue load other dlls

		//buile the return module list 
		if (ModLists == NULL) {
			ModLists = (LPMODITEM)fns.xVirtualAlloc (NULL, HANDLES_BUFFER_LENGTH, MEM_COMMIT, PAGE_READWRITE);
			//if we can't return multi-modules, then break. 
			if (ModLists == NULL) {
				PrintCode(&fns, 0X657220636F6C6C61LL, 0X6D656D20746C7573LL, 0X726F72726520LL);//alloc result mem error
				return (HMODULE)lpFileBase;
			}
		}

		PrintCode(&fns, 0X6D20797469666F6ELL, 0X666F20666C657379LL, 0X676E696E6E757220LL);//nofity myself of running

		//get new entry, to receive module notify info.
		DllEntryProc fnNewEntry = DLLENTRY (hModule);
		//notify who has already in.
		for (i=0; i<dwModuleCount; i++) {
			if ((DWORD)(ModLists[i].hModule) != (DWORD)(ModLists[i].fnEntry)) {
				fnNewEntry (hModule, DLL_MODULE_ATTACH, ModLists[i].hModule);
			}
		}
		//recode the new module 
		ModLists[dwModuleCount].hModule = hModule;
		ModLists[dwModuleCount++].fnEntry = fnNewEntry;
		//fill a NULL item in tail.
		ModLists[dwModuleCount].hModule = NULL;
		ModLists[dwModuleCount].fnEntry = NULL;

		PrintCode(&fns, 0X78656E20646E6966LL, 0X656C75646F6D2074LL, 0X6573616220LL);//find next module base

		//need to find the next module, first, take a long step.         
		dwHandledSize += GuessFileSize ((LPVOID)lpFileBase); 
		//second, scan the left
		lpFileBase = NULL;
		if (*(LPWORD)(szBaseOfCode + dwHandledSize) == IMAGE_DOS_SIGNATURE) {
			lpFileBase = szBaseOfCode + dwHandledSize;
		}
	}while (lpFileBase);

	PrintCode(&fns, 0X646F6D2064616F6CLL, 0X6E69662073656C75LL, 0X687369LL);//load modules finish

	return (HMODULE)ModLists;
}

__inline__  BOOL lFreeLibrary(HMODULE hModule, LPVOID lpReserved)
{
	BOOL bResult = TRUE;
	//relocation main function from peb structure
	PROCLIST f;
	if (initProcList(&f)) {
		LPMODITEM ModLists = NULL;
		if (*((LPWORD)hModule) == IMAGE_DOS_SIGNATURE) {
			ModLists = (LPMODITEM)f.xVirtualAlloc (NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
			ModLists[0].hModule = hModule;
			ModLists[0].fnEntry = DLLENTRY (hModule);
			ModLists[1].hModule = NULL;
			ModLists[1].fnEntry = NULL;
		} else {
			ModLists = (LPMODITEM)hModule;
		}

		int i,j;
		for (i=0; ModLists[i].hModule; i++) {
			//taget the aim module
			HMODULE hDetachMod = ModLists[i].hModule;
			//notify other module: i'm exit.
			for (j=i+1; ModLists[j].hModule; j++) {
				if ((DWORD)(ModLists[j].hModule) != (DWORD)(ModLists[j].fnEntry)) {
					ModLists[j].fnEntry (ModLists[j].hModule, DLL_MODULE_DETACH, hDetachMod);
				}
			}
			//real exit and free
			if ((DWORD)(hDetachMod) != (DWORD)(ModLists[i].fnEntry)) {
				bResult = bResult && ModLists[i].fnEntry (hDetachMod, DLL_PROCESS_DETACH, lpReserved);
			}
			//recycle memory 
			FreeImportedDll (&f, hDetachMod);
			f.xVirtualFree(hDetachMod, 0, MEM_RELEASE);
		}

		f.xVirtualFree(ModLists, 0, MEM_RELEASE);
		return bResult;
	}
}

#endif


