/* Header Files */
#include <windows.h>
#include <windns.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

typedef DNS_STATUS (WINAPI *LPFN_DNSQUERY_A) (PCSTR,WORD,DWORD,PIP4_ARRAY,PDNS_RECORD*,PVOID*);
typedef DNS_STATUS (WINAPI *LPFN_DNSQUERY_W) (PCWSTR,WORD,DWORD,PIP4_ARRAY,PDNS_RECORD*,PVOID*);
typedef DNS_STATUS (WINAPI *LPFN_DNSQUERY_UTF8) (PCSTR,WORD,DWORD,PIP4_ARRAY,PDNS_RECORD*,PVOID*);
typedef BOOL (WINAPI *LPFN_DNSFLUSHRESOLVERCACHE) (VOID);  



LPFN_DNSQUERY_A realdnsquerya;
LPFN_DNSQUERY_W realdnsqueryw;
LPFN_DNSQUERY_UTF8 realdnsqueryutf8;
LPFN_DNSFLUSHRESOLVERCACHE DnsFlushResolverCache; 

typedef HMODULE (*LPFN_Hook_InlineHookInstall)(void* fnHookFrom, void* fnHookTo);
typedef void*   (*LPFN_Hook_InlineHookGetOri)(HMODULE hHooker);
typedef void    (*LPFN_Hook_InlineHookRemove)(HMODULE hHooker);
LPFN_Hook_InlineHookInstall Hook_InlineHookInstall;
LPFN_Hook_InlineHookGetOri Hook_InlineHookGetOri;
LPFN_Hook_InlineHookRemove Hook_InlineHookRemove;

HMODULE hCodeTrick, hDnsapi;

//XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-

void DebugMsg(const char *szFormat, ...)
{
    char szData[512] = {0};
    va_list args;
    va_start(args, szFormat);
    _vsnprintf(szData, sizeof(szData) - 1, szFormat, args);
    va_end(args);
    OutputDebugString(szData);
}

void* HookDnsapi(char *name, HMODULE *hHook, void *fHooker) 
{
	if (!hDnsapi) {
		hDnsapi = LoadLibrary("dnsapi.dll");
		if (!hDnsapi) {
			DebugMsg ("can't load dnsapi.dll");
			return NULL;
		}
		DnsFlushResolverCache = (LPFN_DNSFLUSHRESOLVERCACHE) GetProcAddress(hDnsapi, "DnsFlushResolverCache"); 
	}

	*hHook = Hook_InlineHookInstall((void*)GetProcAddress(hDnsapi, name), fHooker);
	if (*hHook) 
		return Hook_InlineHookGetOri(*hHook);
	
	DebugMsg( "Hook ERROR on: %s", name);
	return NULL;
}

char* ip2str(DWORD ip)
{
	struct in_addr addr;
	addr.S_un.S_addr = ip;
	return inet_ntoa(addr);
}

DNS_STATUS WINAPI hook_DnsQuery_A(PCSTR lpstrName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD *ppQueryResultsSet, PVOID *pReserved)
{
	DebugMsg("DnsQuery_A: %s", lpstrName);
	Options |= DNS_QUERY_USE_TCP_ONLY;
	DNS_STATUS ret = realdnsquerya(lpstrName, wType, Options, pExtra, ppQueryResultsSet, pReserved);
	DebugMsg("Result: from %ls to %s", (*ppQueryResultsSet)->pName, ip2str((*ppQueryResultsSet)->Data.A.IpAddress));
	return ret;
}

DNS_STATUS WINAPI hook_DnsQuery_W(PCWSTR lpwstrName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD *ppQueryResultsSet, PVOID *pReserved)
{
	DebugMsg("DnsQuery_W: %ls", lpwstrName);
	Options |= DNS_QUERY_USE_TCP_ONLY;
	DNS_STATUS ret = realdnsqueryw(lpwstrName, wType, Options, pExtra, ppQueryResultsSet, pReserved);
	DebugMsg("Result: from %ls to %s", (*ppQueryResultsSet)->pName, ip2str((*ppQueryResultsSet)->Data.A.IpAddress));
	return ret;
}

DNS_STATUS WINAPI hook_DnsQuery_UTF8(PCSTR lpstrName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD *ppQueryResultsSet, PVOID *pReserved)
{
	DebugMsg("DnsQuery_UTF8: %s", lpstrName);
	Options |= DNS_QUERY_USE_TCP_ONLY;
	DNS_STATUS ret = realdnsqueryutf8(lpstrName, wType, Options, pExtra, ppQueryResultsSet, pReserved);
	DebugMsg("Result: from %ls to %s", (*ppQueryResultsSet)->pName, ip2str((*ppQueryResultsSet)->Data.A.IpAddress));
	return ret;
}

HMODULE hHookdnsquerya, hHookdnsqueryw, hHookdnsqueryutf8;

int installhook() 
{
	DebugMsg( "start install winsock hook");

        if (!hCodeTrick) {
            hCodeTrick = LoadLibrary("CodeTrick.dll");
            if (hCodeTrick) {
		Hook_InlineHookInstall = (LPFN_Hook_InlineHookInstall)GetProcAddress(hCodeTrick, "Hook_InlineHookInstall");
		Hook_InlineHookGetOri = (LPFN_Hook_InlineHookGetOri)GetProcAddress(hCodeTrick, "Hook_InlineHookGetOri");
		Hook_InlineHookRemove = (LPFN_Hook_InlineHookRemove)GetProcAddress(hCodeTrick, "Hook_InlineHookRemove");

		realdnsquerya = (LPFN_DNSQUERY_A) HookDnsapi("DnsQuery_A", &hHookdnsquerya, (void*)hook_DnsQuery_A); 
		realdnsqueryw = (LPFN_DNSQUERY_W) HookDnsapi("DnsQuery_W", &hHookdnsqueryw, (void*)hook_DnsQuery_W); 
		realdnsqueryutf8 = (LPFN_DNSQUERY_UTF8) HookDnsapi("DnsQuery_UTF8", &hHookdnsqueryutf8, (void*)hook_DnsQuery_UTF8); 

		do {
			if (!realdnsquerya) break;
			if (!realdnsqueryw) break;
			if (!realdnsqueryutf8) break;
			return 1;
		} while (0);
            }
        }
	DebugMsg( "installhook error");
	return 0;
}

int removehook() 
{
        if (hCodeTrick) {
		removehook();
		Hook_InlineHookRemove(hHookdnsquerya); 
		Hook_InlineHookRemove(hHookdnsqueryw); 
		Hook_InlineHookRemove(hHookdnsqueryutf8); 
		return 1;
        }
	DebugMsg( "removehook error");
	return 0;
}


BOOL WINAPI DllMain (HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
    switch(fdwReason) 
    { 
    case DLL_PROCESS_ATTACH: 
	installhook();
	if (DnsFlushResolverCache)
		DnsFlushResolverCache();
        break;

    case DLL_PROCESS_DETACH: 
	removehook();
        break;
    }
    SetLastError(0);
    return (TRUE);
}
