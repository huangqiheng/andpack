#include <string.h>
#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include "LightLoader.h"

#include "../log/logclient.inc"


HMODULE* AppendHandles(HMODULE* Ori, HMODULE hModule)
{

}

__declspec(dllexport) HMODULE Mod_LoadLibrarys(void* Image, ...)
{
    va_list ap;
    int next;
    va_start(ap,Image);
    //handle...
    next=va_arg(ap,int);
    while(next!=0)
    {
        next=va_arg(ap,int);
    }
    va_end(ap);  
}

__declspec(dllexport) BOOL Mod_FreeLibrarys(HMODULE hModule, ...)
{

}

__declspec(dllexport) void* Mod_GetProcAddress (HMODULE hModule, PCHAR lpFunName)
{

}

int BlockEnd();



//This function is the same with LPTHREAD_START_ROUTINE, as a thread's entry function.
WINAPI HMODULE ThreadEntry (LPVOID lpReserved)
{
	PCHAR MeAddr;
    __asm__("call _next\n_next:\n\tpopl %0\n\t" : "=r" (MeAddr) : );
    for (; *(LPWORD)MeAddr != 0x8955; MeAddr--) {}
    LPVOID pAddrOfBlock = (LPVOID)MeAddr;

    DWORD dwSizeOfLeader = (DWORD)&BlockEnd - (DWORD)&ThreadEntry;
    return __LoadFromTail(pAddrOfBlock, dwSizeOfLeader, lpReserved);
}
int BlockEnd() {return 10;}

WINAPI LPVOID GetDllLeader (LPDWORD lpSizeOfCode)
{
    *lpSizeOfCode = (DWORD)&BlockEnd - (DWORD)&ThreadEntry;
    return (LPVOID)(&ThreadEntry);
}


__declspec(dllexport) HMODULE Inject_MakeCopiedCodeRunner(void* Image, ...)
{

}

__declspec(dllexport) HMODULE Inject_MakeCopiedCodeWithdrawer(HMODULE hModule)
{

}

__declspec(dllexport) void* Hook_EATHook (HMODULE hModule, char* szFuncName, void* fnHooker)
{
    LPDWORD pEATAddr = lGetProcEATAddress(hModule, szFuncName);
    if (pEATAddr == NULL)
        return NULL;

    DWORD nNewOffset = (DWORD)fnHooker - (DWORD)hModule;
    DWORD nOldOffset = *pEATAddr;

    DWORD dwOLD;
    VirtualProtect((PVOID)pEATAddr, sizeof(DWORD), PAGE_READWRITE, &dwOLD);
    *pEATAddr = nNewOffset;
    VirtualProtect((PVOID)pEATAddr, sizeof(DWORD), dwOLD, &dwOLD);

    return (void*)RVATOVA(hModule, nOldOffset);
}

__declspec(dllexport) void* Hook_IATHook(HMODULE hModuleToFix, PCHAR szLibName, PCHAR szFunName, void* Hooker)
{
	LPVOID pTargetFun = (LPVOID)GetProcAddress(GetModuleHandle(szLibName), szFunName);
	if (!pTargetFun) 
		return NULL;

	PIMAGE_NT_HEADERS pNtHeaders = NTHEADER(hModuleToFix);
	PIMAGE_DATA_DIRECTORY directory = DATADIRECTORY(pNtHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size == 0)
		return NULL;

	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)RVATOVA(hModuleToFix, directory->VirtualAddress);
	DWORD nSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;

	POINTER_TYPE *thunkRef;
	FARPROC *funcRef;
	LPVOID pOriFun;
	while (VALIDRANGE(importDesc, hModuleToFix, nSizeOfImage) && (importDesc->Name))
	{
		PCHAR szScanLib = (PCHAR)RVATOVA(hModuleToFix, importDesc->Name);

		if (stricmp(szScanLib, szLibName) == 0)
		{
			if (importDesc->OriginalFirstThunk) 
			{
				thunkRef = (POINTER_TYPE *) RVATOVA (hModuleToFix, importDesc->OriginalFirstThunk);
				funcRef = (FARPROC *) RVATOVA (hModuleToFix, importDesc->FirstThunk);
			} 
			else 
			{
				// no hint table
				thunkRef = (POINTER_TYPE *) RVATOVA (hModuleToFix, importDesc->FirstThunk);
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
					VirtualProtect((LPVOID)funcRef, sizeof(FARPROC), PAGE_READWRITE, &dwOLD);
					*funcRef = (FARPROC)Hooker;
					VirtualProtect((LPVOID)funcRef, sizeof(FARPROC), dwOLD, 0);
					return pOriFun;
				}
			}
		}
		importDesc++;
	}
	return NULL;
}


typedef	unsigned __int8		u8;
typedef unsigned __int16	u16;
typedef unsigned __int32	u32;
typedef unsigned __int64	u64;

typedef signed __int8		s8;
typedef signed __int16		s16;
typedef signed __int32		s32;
typedef signed __int64		s64;
//#define _WIN32_WINNT 0x0600

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))
#define MakeDelta(cast, x, y) (cast) ( (DWORD_PTR)(x) - (DWORD_PTR)(y))

#define INSTR_NEAR_PREFIX 0x0F
#define INSTR_FARJMP 0x2D			//	Far jmp prefixed with INSTR_FAR_PREFIX
#define INSTR_SHORTJCC_BEGIN 0x70
#define INSTR_SHORTJCC_END 0x7F
#define INSTR_NEARJCC_BEGIN 0x80	//	Near's are prefixed with INSTR_NEAR_PREFIX byte
#define INSTR_NEARJCC_END 0x8F
#define INSTR_RET 0xC2
#define INSTR_RETN 0xC3
#define INSTR_RETFN 0xCA
#define INSTR_RETF 0xCB
#define INSTR_INT3 0xCC
#define INSTR_RELJCX 0xE3
#define INSTR_RELCALL 0xE8
#define INSTR_RELJMP 0xE9
#define INSTR_SHORTJMP 0xEB
#define INSTR_FAR_PREFIX 0xFF

typedef struct {
    u32 sign;
    void * fnHookFrom;
    void * fnHookTo;
    u32 stubLen;
    u8 entryStub[256];
    u8 oldbytes[32];
    u8 patchbytes[32];
    
} HOOKINLINE, *LPHOOKINLINE;


#include "ADE32.CPP"


DWORD codeLen(u8 * opcode)
{
    disasm_struct s = {4,4};
    return disasm((BYTE*)opcode, &s);
}
    
u32 InsertBranch(LPHOOKINLINE hookinfo, u8 branchType, void *to)
{
	u8 *instr = &hookinfo->entryStub[hookinfo->stubLen];
	if(branchType != INSTR_RELJMP && branchType != INSTR_RELCALL && branchType != INSTR_RELJCX)
	{
		*instr = INSTR_NEAR_PREFIX;
		++instr;
	}
	*instr = branchType;
	++instr;
    u32 CodeSize = codeLen(&hookinfo->entryStub[hookinfo->stubLen]);
    u32 CodeOffset = MakeDelta(u32, to, &hookinfo->entryStub[hookinfo->stubLen]);
	*(u32 *)instr = CodeOffset - CodeSize;
	return CodeSize;
}

void PrintMem(char* szTitle, void* Base, u32 uSize)
{
    u8 *pBase = (u8*)Base;
    printf("%s: ", szTitle);
    int i;
    for (i=0; i<uSize; i++) {
        printf("%x ", pBase[i]);
    }
    printf("\n");
}

void PrintMemory(char* szTitle, void* Base, u32 uSize)
{
    printf("%s: \n", szTitle);
    int nLine = uSize / 16;
    int nLast = uSize % 16;
    int ii, jj;
    PBYTE sScan = (PBYTE)Base;

    for (ii=0; ii<nLine; ii++) {
        printf ("0x%.8x  ", ii+(u32)Base);
        for (jj=0; jj<16; jj++) {
            printf ("%.2X ", sScan [ii*16 + jj]);
        }
        printf ("\n");
    }

    printf ("0x%.8x  ", ii+(u32)Base);
    for (jj=0; jj<nLast; jj++) {
        printf ("%x ", sScan [ii*16 + jj]);
    }
    printf ("\n");
}


u32 InsertInstruction(LPHOOKINLINE hookinfo, u8 *codeptr)
{
	//	This code will determine what type of branch it is, and
	//	increment the pointer to point to the relative branch's
	//	offset.  This has to be modified in the same way for every
	//	instruction.
	s32 offset = 0;
	u8 opcode = *codeptr;
	switch(*codeptr)
	{
	case INSTR_SHORTJMP:
		//	Short offset values are only 1 byte long, and they are signed
		offset = *(s8 *)(codeptr + 1);
		offset = MakePtr(s32, codeptr, offset);
		break;
	case INSTR_RELJCX:
	case INSTR_RELCALL:
	case INSTR_RELJMP:
		//	Near jmps have only a 1 byte opcode
		offset = *MakePtr(s32 *, codeptr, 1);
		offset = MakePtr(s32, codeptr, offset);
		break;
	case INSTR_NEAR_PREFIX:
		//	Near conditional jumps have a 2 byte opcode
		offset = *MakePtr(s32 *, codeptr, 2);
		offset = MakePtr(s32, codeptr, offset);
		opcode = *(codeptr + 1);
		break;
	case INSTR_INT3:
		opcode = INSTR_RELJMP;
		hookinfo->entryStub[hookinfo->stubLen] = INSTR_INT3;
		return 1;
		break;
	default:
		//	Check to see if it's in the valid range of JCC values.
		//	e.g. ja, je, jne, jb, etc..
		if(*codeptr >= INSTR_SHORTJCC_BEGIN && *codeptr <= INSTR_SHORTJCC_END)
		{
			offset = *(s8*)(codeptr + 1);
			offset = MakePtr(s32, codeptr, offset);
			//	Convert it to a NEAR condition code
			opcode += INSTR_NEARJCC_BEGIN - INSTR_SHORTJCC_BEGIN;
		}
		else
		{
			//	Non-Branching, non-int3 instruction
            u32 CodeSize = codeLen(codeptr);
			memcpy(&hookinfo->entryStub[hookinfo->stubLen], codeptr, CodeSize);
            return CodeSize;
		}
	}

	return InsertBranch(hookinfo, opcode, (void *)offset);
}

BOOL IsRet(u8 *instr)
{
	switch(*instr){
		case INSTR_RET:
		case INSTR_RETN:
		case INSTR_RETFN:
		case INSTR_RETF:
			return TRUE;
	}
	return FALSE;
}


BOOL BuildStub(LPHOOKINLINE hookinfo)
{
    u8 *codeptr = (u8 *)hookinfo->fnHookFrom; 
    BOOL retval = TRUE;
    u32 oldprot;
    VirtualProtect(hookinfo->entryStub, sizeof(hookinfo->entryStub), PAGE_EXECUTE_READWRITE, &oldprot);

    u32 len,instrLen;
    for(len=0, instrLen=0; len<5; instrLen = InsertInstruction(hookinfo, codeptr)) {
        if (IsRet(codeptr))
            retval = FALSE;
        codeptr += instrLen;
        len += instrLen;
        hookinfo->stubLen += instrLen;
    }

    void* JmpBAckAddr = MakePtr(void *, hookinfo->fnHookFrom, hookinfo->stubLen);
    hookinfo->stubLen += InsertBranch(hookinfo, INSTR_RELJMP, JmpBAckAddr);
/*
    PrintMemory("fnHookFrom memory", hookinfo->fnHookFrom, 32);
    PrintMemory("fnHookTo memory", hookinfo->fnHookTo, 32);
    PrintMemory("stub memory", hookinfo->entryStub, 32);
*/
    return retval;
}

void WriteJump(void *from, void *to)
{
	u32 oldprot;
	u8 relJmp[] = {INSTR_RELJMP, 0, 0, 0, 0};

	VirtualProtect(from, sizeof(relJmp), PAGE_EXECUTE_READWRITE, (DWORD *)&oldprot);
	//	Build the relative jump that will be patched onto from
	u32 offset = MakeDelta(u32, to, from) - 5;
	//	Build the relative jump
	*(u32 *)(relJmp + 1) = offset;
	memcpy(from, relJmp, sizeof(relJmp));
	//	If this one fails, it won't effect the operation of the hook.
	//	So, I don't think it's necessary for Hook() to fail if this
	//	VirtualProtect() does.
	u32 oldprot2;
	VirtualProtect(from, sizeof(relJmp), oldprot, (DWORD *)&oldprot2);
	//	Flush the CPU's instruction cache.  This should always be done
	//	when writing self-modifying code, because the CPU will cache
	//	instructions, and may not detect our newly modified code.
	FlushInstructionCache(GetCurrentProcess(), NULL, 0);
}

__declspec(dllexport) HMODULE Hook_InlineHookInstall(void* fnHookFrom, void* fnHookTo)
{
	if ((!fnHookFrom) || (!fnHookTo))
		return NULL;

	LPHOOKINLINE hookinfo = (LPHOOKINLINE)VirtualAlloc(NULL, sizeof(HOOKINLINE), MEM_COMMIT, PAGE_READWRITE);
	memset(hookinfo, 0, sizeof(HOOKINLINE));
	hookinfo->fnHookFrom = fnHookFrom;
	hookinfo->fnHookTo = fnHookTo;

	memcpy(hookinfo->oldbytes, fnHookFrom, 5);

	if (BuildStub(hookinfo))
		WriteJump(hookinfo->fnHookFrom, hookinfo->fnHookTo);
	else {
		VirtualFree (hookinfo, 0, MEM_RELEASE);
		return NULL;
	}

	memcpy(hookinfo->patchbytes, hookinfo->fnHookFrom, 5);
	return (HMODULE)hookinfo;
}

__declspec(dllexport) void* Hook_InlineHookGetOri(HMODULE hHooker)
{
	if (!hHooker)
		return NULL;
	LPHOOKINLINE hookinfo = (LPHOOKINLINE)hHooker;
	return (void*)&hookinfo->entryStub[0]; 
}

__declspec(dllexport) void Hook_InlineHookRemove(HMODULE hHooker)
{
	if (!hHooker)
		return;
	LPHOOKINLINE hookinfo = (LPHOOKINLINE)hHooker;

	u32 oldprot, oldprot2;
	VirtualProtect(hookinfo->fnHookFrom, 5, PAGE_EXECUTE_READWRITE, (DWORD *)&oldprot);
	memcpy(hookinfo->fnHookFrom, hookinfo->oldbytes, 5);
	VirtualProtect(hookinfo->fnHookFrom, 5, oldprot, (DWORD *)&oldprot2);

	VirtualFree (hookinfo, 0, MEM_RELEASE);
}

BOOL WINAPI DllMain (HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
    PCHAR ImportModName;
    char szBuffer[256];
    DWORD dwLen ;

    switch( fdwReason ) 
    { 
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:     break;
    case DLL_THREAD_DETACH:     break;
    case DLL_PROCESS_DETACH:    break;
    case DLL_MODULE_ATTACH:
        dwLen = GetModuleFileNameA((HMODULE)lpReserved, &szBuffer[0], 256);
        show_msg(MSGDEBUG, "CodeTrick.dll found new module running [%s]\n", &szBuffer[0]);
        break;
    case DLL_MODULE_DETACH:
        dwLen = GetModuleFileNameA((HMODULE)lpReserved, &szBuffer[0], 256);
        show_msg(MSGDEBUG, "CodeTrick.dll found module exiting [%s]\n", &szBuffer[0]);
        break;
    }
    SetLastError(0);
    return (TRUE);
}
