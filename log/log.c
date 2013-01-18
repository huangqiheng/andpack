#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <windows.h>
#include <tlhelp32.h>
#include <global.h>
#include <message_comm.h>
#include "log.h"

/* Globals */
int loglevel = MSGERR;    /* The default logging level is to only log
                             error messages */
char logfilename[256];    /* Name of file to which log messages should
                             be redirected */
FILE *logfile = NULL;     /* File to which messages should be logged */
int logstamp = 0;         /* Timestamp (and pid stamp) messages */
static int suid = 0;
char *me_modulename = "log.dll";
enum VIEW_METHOD view_method = vm_log_file;


/* Set logging options, the options are as follows:             */
/*  level - This sets the logging threshold, messages with      */
/*          a higher level (i.e lower importance) will not be   */
/*          output. For example, if the threshold is set to     */
/*          MSGWARN a call to log a message of level MSGDEBUG   */
/*          would be ignored. This can be set to -1 to disable  */
/*          messages entirely                                   */
/*  filename - This is a filename to which the messages should  */
/*             be logged instead of to standard error           */
/*  timestamp - This indicates that messages should be prefixed */
/*              with timestamps (and the process id)            */
void set_log_options(int level, char *filename, int timestamp) 
{

   loglevel = level;
   if (loglevel < MSGERR)
      loglevel = MSGNONE;

   if (filename) 
   {
      strncpy(logfilename, filename, sizeof(logfilename));
      logfilename[sizeof(logfilename) - 1] = '\0';
   }

   logstamp = timestamp;
}


int make_dbg_msg(char *modname, int level, const char *fmt, va_list ap, char* out_buff, size_t out_buff_size) 
{
	int saveerr;
	char prefixstring[64];
	char timestring[20];
	char szData[512];
	time_t timestamp;

	if ((loglevel == MSGNONE) || (level > loglevel))
	{
		return (0);
	}

	saveerr = errno;

	if (logstamp) 
	{
		timestamp = time(NULL);
		strftime(timestring, sizeof(timestring) - 1,  "%H:%M:%S", localtime(&timestamp));
		snprintf(prefixstring, sizeof(prefixstring) - 1, "%s %s(%d): ", timestring, modname, getpid());
	}
	else 
	{
		snprintf(prefixstring, sizeof(prefixstring) - 1, "%s: ", modname);
	}

	_vsnprintf(szData, sizeof(szData) - 1, fmt, ap);
	int made_size = snprintf(out_buff, out_buff_size - 1, "%s %s", prefixstring, szData);

	errno = saveerr;
	return (made_size);
} 

void vshow_msg_dbgview(char *modname, int level, const char *fmt, va_list ap) 
{
	char szOutMsg[512];
	make_dbg_msg(modname, level, fmt, ap, szOutMsg, sizeof(szOutMsg));
	OutputDebugStringA(szOutMsg);
} 

char* daemon_message_name = NULL;

void vshow_msg_daemon(char *modname, int level, const char *fmt, va_list ap)
{
	if (daemon_message_name)
	{
		char szOutMsg[512];
		make_dbg_msg(modname, level, fmt, ap, szOutMsg, sizeof(szOutMsg));
		thread_msg_post_str(daemon_message_name, daemon_message_debug, szOutMsg);
	}
	else
	{
		vshow_msg_dbgview(modname, level, fmt, ap);
	}
}

void vshow_msg_logfile(char *modname, int level, const char *fmt, va_list ap) 
{
	int saveerr;
	char timestring[20];
	time_t timestamp;

	if ((loglevel == MSGNONE) || (level > loglevel))
		return;

	if (!logfile) 
	{
		if (logfilename[0]) 
		{
			 logfile = fopen(logfilename, "a");
			 if (logfile == NULL) 
			 {
				 logfile = stderr;
				 show_msg(modname, MSGERR, "Could not open log file, %s, %s\n", logfilename, strerror(errno));
			 }
		} 
		else
		{
			logfile = stderr;
		}
	}

	if (logstamp) 
	{
		timestamp = time(NULL);
		strftime(timestring, sizeof(timestring),  "%H:%M:%S", localtime(&timestamp));
		fprintf(logfile, "%s ", timestring);
	}

	fputs(modname, logfile);

	if (logstamp) 
	{
		fprintf(logfile, "(%d)", getpid());
	}

	fputs(": ", logfile);

	/* Save errno */
	saveerr = errno;
	vfprintf(logfile, fmt, ap);
	fflush(logfile);
	errno = saveerr;
}

void vshow_msg(char *modname, int level, const char *fmt, va_list ap)
{
	switch (view_method)
	{
		case vm_log_file:
			vshow_msg_logfile(modname, level, fmt, ap);
			break;
		case vm_debug_view:
			vshow_msg_dbgview(modname, level, fmt, ap);
			break;
		case vm_daemon_console:
			vshow_msg_daemon(modname, level, fmt, ap);
			break;
		default:
			break;
	}
}

void show_msg(char *modname, int level, const char *fmt, ...) 
{
	va_list ap;
	va_start(ap, fmt);
	vshow_msg(modname, level, fmt, ap);
	va_end(ap);
}

char* get_file_name(char* ori_full_name, char* name_replaced, char* ext_replaced)
{
        int orilen = strlen(ori_full_name);
        char buffer[256];
        strncpy(buffer, ori_full_name, 256);

        int len;
        if (name_replaced) {
                for (len = orilen; len>0; len--) {
                        if (buffer[len] == '\\') {
                                strncpy(&buffer[++len], name_replaced, 256-len);
                                len = strlen(buffer);
                                buffer[len++] = '.';
                                strncpy(&buffer[len], ext_replaced, 256-len);
                                return strdup(buffer);
                        }
                }
        } else {
                for (len = orilen; len>0; len--) {
                        if (buffer[len] == '.') {
                                strncpy(&buffer[++len], ext_replaced, 256-len);
                                return strdup(buffer);
                        }
                        if (buffer[len] == '\\') {
                                strncpy(&buffer[orilen], ext_replaced, 256-orilen);
                                return strdup(buffer);
                        }
                }
        }
        return NULL;
}


char* get_filename_byext(char* ext_replaced)
{
        char szfilename[256];

        GetModuleFileName(NULL, szfilename, sizeof(szfilename));
        return get_file_name(szfilename, NULL, ext_replaced);
}

char* get_filename_bypath(char* name_replaced, char* ext_replaced)
{
        char szfilename[256];

        GetModuleFileName(NULL, szfilename, sizeof(szfilename));
        return get_file_name(szfilename, name_replaced, ext_replaced);
}

int getset_log_option(int log_level) 
{
        int loglevel = log_level;
        char *logfile = NULL;
        char *env;

        if ((env = getenv("TSOCKS_DEBUG")))
                loglevel = atoi(env);
        if (((env = getenv("TSOCKS_DEBUG_FILE"))) && !suid)
                logfile = env;

        if (!logfile) {
                logfile = get_filename_byext("xlog");
        }

        set_log_options(loglevel, logfile, 1);
        show_msg(me_modulename, MSGDEBUG, "logfile=%s\n", logfile);
        return(1);
}


void __stdcall _show_msg(char *modname, int level, const char *msg)
{
	show_msg(modname, level, msg);
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

int init_parameters(HINSTANCE dll_instance)
{
	HINSTANCE session_dll = LoadLibraryA("session.dll");
	if (session_dll == NULL)
	{
		return (0);
	}

	typedef const char** (__stdcall *lpfn_get_parameters)(HINSTANCE image, const char* catelog_name);
	typedef const char** (__stdcall *lpfn_get_parameter)(HINSTANCE image, const char* catelog_name, const char* key_name);
	typedef PACKAGE* (__stdcall *lpfn_get_package)();
	typedef STARTUP* (__stdcall *lpfn_get_startup)();
	lpfn_get_parameters get_parameters = (lpfn_get_parameters)GetProcAddress(session_dll, "get_parameters@8");
	lpfn_get_parameter  get_parameter  = (lpfn_get_parameter)GetProcAddress(session_dll, "get_parameter@12");
	lpfn_get_package get_package = (lpfn_get_package)GetProcAddress(session_dll, "get_package@0");
	lpfn_get_startup get_startup = (lpfn_get_startup)GetProcAddress(session_dll, "get_startup@0");

	STARTUP* startup = get_startup();

	if ((startup == NULL) || (startup->daemon_dbg_name.length == 0))
	{
		return (0);
	}

	char* msg_name = (char*)STARTUP(startup->daemon_dbg_name);
	if (msg_name == NULL)
	{
		OutputDebugStringA("can't get daemon_dbg_name from \"package\" of section");
		return (0);
	}

	//成功获取到daemon控制台的msg名
	daemon_message_name = strdup(msg_name);

	if ((get_parameters == NULL) || (get_parameter == NULL))
	{
		OutputDebugStringA("can't init address of get_parameter()");
		return (0);
	}

	//确定日志的层次
	const char** log_level_s = get_parameter(dll_instance, "parameter", "loglevel");
	if (log_level_s)
	{
		const char* log_level = log_level_s[1];
		if (!stricmp(log_level, "MSGNONE"))
		{
			loglevel = MSGNONE;
			OutputDebugStringA("set loglevel = MSGNONE");
		}
		else if (!stricmp(log_level, "MSGERR"))
		{
			loglevel = MSGERR;
			OutputDebugStringA("set loglevel = MSGERR");
		}
		else if (!stricmp(log_level, "MSGWARN"))
		{
			loglevel = MSGWARN;
			OutputDebugStringA("set loglevel = MSGWARN");
		}
		else if (!stricmp(log_level, "MSGNOTICE"))
		{
			loglevel = MSGNOTICE;
			OutputDebugStringA("set loglevel = MSGNOTICE");
		}
		else if (!stricmp(log_level, "MSGDEBUG"))
		{
			loglevel = MSGDEBUG;
			OutputDebugStringA("set loglevel = MSGDEBUG");
		}
	}


	//确定日志模式
	const char** logmode_s = get_parameter(dll_instance, "parameter", "logmode");
	if (logmode_s)
	{
		const char* logmode = strdup(logmode_s[1]);

		if (!stricmp(logmode, "log_to_file"))
		{
			view_method = vm_log_file;
			OutputDebugStringA("set mode = vm_log_file");
		}
		else if (!stricmp(logmode, "log_to_dbgview"))
		{
			view_method = vm_debug_view;
			OutputDebugStringA("set mode = vm_debug_view");
		}
		else if (!stricmp(logmode, "log_to_console"))
		{
			view_method = vm_daemon_console;
			OutputDebugStringA("set mode = vm_daemon_console");
		}
	}

	//确定日志文件名
	const char** logfile_s = get_parameter(dll_instance, "parameter", "logfile");
	if (logfile_s)
	{
		const char* logfile = logfile_s[1];
		if (logfile == NULL)
		{
			logfile = get_filename_byext("xlog");
		}

		strcpy(&logfilename[0], logfile);
		OutputDebugStringA("set log file name:");
		OutputDebugStringA(logfilename);
	}

	//确定是否使用时间戳
	const char** time_stamp_s = get_parameter(dll_instance, "parameter", "timestamp");
	if (time_stamp_s)
	{
		const char* timestamp = time_stamp_s[1];
		if (!stricmp(timestamp, "true"))
		{
			logstamp = 1;
			OutputDebugStringA("set timestamp = 1");
		}
	}
}

#define DLL_MODULE_ATTACH  DLL_PROCESS_DETACH + 10
#define DLL_MODULE_DETACH  DLL_MODULE_ATTACH + 1


BOOL WINAPI DllMain (HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
        switch(fdwReason)
        {
                case DLL_PROCESS_ATTACH:
			init_parameters(hinstDll);
                        break;
                case DLL_THREAD_ATTACH:
                        break;
                case DLL_THREAD_DETACH:
                        break;
                case DLL_PROCESS_DETACH:
                        break;
                case DLL_MODULE_ATTACH:
                        break;
                case DLL_MODULE_DETACH:
                        break;
        }
        SetLastError(0);
        return (TRUE);
}

