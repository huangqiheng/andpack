#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Browser.H>
#include <FL/fl_ask.H>
#include <FL/Fl_Box.H>
#include <FL/fl_utf8.h>

//#include <iconv.h>
#include <wchar.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <assert.h>

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include "srvlist.h"

#include "../log/logclient.inc"


/*宽字符转换为多字符Unicode - ANSI*/
char* w2m(const wchar_t* wcs)
{
      int len;
      char* buf;
      len =wcstombs(NULL,wcs,0);
      if (len == 0)
          return NULL;
      buf = (char *)malloc(sizeof(char)*(len+1));
      memset(buf, 0, sizeof(char) *(len+1));
      len =wcstombs(buf,wcs,len+1);
      return buf;
}

/*多字符转换为宽字符ANSI - Unicode*/
wchar_t* m2w(const char* mbs)
{
      int len;
      wchar_t* buf;
      len =mbstowcs(NULL,mbs,0);
      if (len == 0)
          return NULL;
      buf = (wchar_t *)malloc(sizeof(wchar_t)*(len+1));
      memset(buf, 0, sizeof(wchar_t) *(len+1));
      len =mbstowcs(buf,mbs,len+1);
      return buf;
}

char* _utf8(const wchar_t *src)
{
	int srclen = wcslen(src);
	int len = fl_utf8fromwc(NULL, 0, src, srclen);
	if (len) {
		int outputlen = len + sizeof(wchar_t) * 1;
		char * output = (char*)malloc(outputlen);
		if (output) {
			fl_utf8fromwc(output, outputlen, src, srclen);
			return output;
		}
	}
	return NULL; 
}

char* __utf8(const char *src)
{
	wchar_t * wsrc = m2w(src);
	char* runret = _utf8(wsrc);
	free(wsrc);
	return runret;
}
/*
char * EncodingConv(  const char * in, char *encFrom, char *encTo )
{

	char *buff, *sin, *sout;
	int lenin, lenout;
	iconv_t ct;

	if( (ct=iconv_open(encTo, encFrom)) == (iconv_t)-1 )
	{
		show_msg(MSGDEBUG, "%s|%d| iconv_open error! %s", __FILE__,
				__LINE__, strerror(errno) );
		return( NULL );
	}

	iconv( ct, NULL, NULL, NULL, NULL );

	sin = (char *)in;
	lenin  = strlen(in) + 1;

	if( (buff = (char*)malloc(lenin*2))==NULL )
	{
		show_msg(MSGDEBUG, "%s|%d| malloc error! %s", __FILE__, __LINE__,
				strerror(errno) );
		iconv_close( ct );
		return( NULL );
	}
	sout   = buff;
	lenout = lenin*2;

	if( iconv( ct, &sin, (size_t *)&lenin, &sout, (size_t *)&lenout) == -1 )
	{
		show_msg(MSGDEBUG, "%s|%d| iconv() error! errno=%d %s", __FILE__,
				__LINE__, errno, strerror(errno) );
		free( buff );
		iconv_close( ct );
		return NULL;
	}

	iconv_close( ct );

	sout=strdup(buff);
	free( buff );

	return( sout );
}

int utf8togb2312(char *sourcebuf,size_t sourcelen,char *destbuf,size_t destlen)
{
	iconv_t cd;
	if( (cd = iconv_open("gb2312","utf-8")) ==0 )
		return -1;
	memset(destbuf,0,destlen);
	char **source = &sourcebuf;
	char **dest = &destbuf;

	if(-1 == iconv(cd,source,&sourcelen,dest,&destlen))
		return -1;
	iconv_close(cd);
	return 0;

}

int gb2312toutf8(char *sourcebuf,size_t sourcelen,char *destbuf,size_t destlen)
{
	iconv_t cd;
	if( (cd = iconv_open("utf-8","gb2312")) ==0 )
		return -1;
	memset(destbuf,0,destlen);
	char **source = &sourcebuf;
	char **dest = &destbuf;

	if(-1 == iconv(cd,source,&sourcelen,dest,&destlen))
		return -1;
	iconv_close(cd);
	return 0;

}
*/

size_t my_write_func(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	return fwrite(ptr, size, nmemb, stream);
}

size_t my_read_func(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	return fread(ptr, size, nmemb, stream);
}


int my_progress_func(void *sender,
		double dltotal, /* dltotal */
		double dlnow, /* dlnow */
		double ultotal,
		double ulnow)
{
	DownloadFile *downloadui = (DownloadFile*)sender;

	if (dltotal) 
	{
		double persent = dlnow * 100 / dltotal;

		char textbuff[16];
		sprintf(textbuff, "%.2f%%", persent);

		Fl::lock();
		downloadui->set_progress(persent, textbuff);
		Fl::unlock();
		Fl::awake();

		show_msg(MSGDEBUG, "%.2f, %.2f, %.2f%%\n", dltotal, dlnow, persent);
	}
	return (downloadui->need_to_terminate)? 1 : 0;
}

void awake_hide_window(void *sender)
{
	DownloadFile *downloadui = (DownloadFile*)sender;
	downloadui->show_window(0);
	show_msg(MSGDEBUG, "awake mainthread to close downloadui\n");
}

void * curl_getfile_thread(void *param)
{
	CURL *curl;
	CURLcode res;
	FILE *outfile;
	DownloadFile *downloadui = (DownloadFile*)param;
	char *url = downloadui->fromurl;
	char *tofile = downloadui->tofile;

	show_msg(MSGDEBUG, "curl_getfile_thread start download to %s\n", tofile);
	curl = curl_easy_init();
	if(curl)
	{
		outfile = fopen(tofile, "w");

		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, outfile);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_write_func);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, my_read_func);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, my_progress_func);
		curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, downloadui);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 7);
//		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 7);

		res = curl_easy_perform(curl);

		fclose(outfile);
		curl_easy_cleanup(curl);
	}
	free(url);
	free(tofile);

	Fl::lock();
	downloadui->set_captions(NULL, "download complete!", NULL);
	Fl::unlock();
	Fl::awake(awake_hide_window, downloadui);
	show_msg(MSGDEBUG, "curl_getfile_thread finished!\n");
}

Fl_Font defined_font = FL_FREE_FONT + 1;

extern "C" __declspec(dllexport) 
void set_default_font(char *fontname) 
{
	//自定义字体
	const char *defaultname = fontname? fontname : "WenQuanYi Micro Hei";
	Fl::set_font(defined_font, defaultname);
}

char * UnicodeToUTF8( const wchar_t* str )
{                       
	char* result;      
	int textlen;               
	textlen = WideCharToMultiByte( CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL );
	result =(char *)malloc((textlen+1)*sizeof(char));
	memset(result, 0, sizeof(char) * ( textlen + 1 ) );
	WideCharToMultiByte( CP_UTF8, 0, str, -1, result, textlen, NULL, NULL );
	return result;
}               

extern "C" __declspec(dllexport) 
int download_file_withui(wchar_t *caption, wchar_t *button, wchar_t *from_url, wchar_t *to_file) 
{
	if ((caption==NULL) || (from_url==NULL) || (to_file==NULL)) 
	{
		show_msg(MSGDEBUG, "download_file_withui function param error!\n");
		return (0);
	}

	show_msg(MSGDEBUG, "start download_file_withui\n");

	DownloadFile *downloadui = new DownloadFile(defined_font);
	downloadui->set_captions(_utf8(caption), _utf8(from_url), _utf8(button));
	//downloadui->set_position(1,1);
	downloadui->show_window(1);
	pthread_t tid;
	void *threadret;

	Fl::lock();
	{
		downloadui->fromurl = w2m(from_url);
		downloadui->tofile = w2m(to_file);
		
		show_msg(MSGDEBUG, "fromurl :  %s\n", downloadui->fromurl);
		show_msg(MSGDEBUG, "tofile:  %s\n", downloadui->tofile);
		int error = pthread_create(&tid,NULL, curl_getfile_thread, downloadui);
		if(0 != error)
		{
			show_msg(MSGDEBUG, "Couldn't run thread, errno %d\n", error);
		}
	}

	show_msg(MSGDEBUG, "start msg loop\n");
	int runret = Fl::run();
	Fl::unlock();
	
	pthread_join(tid, &threadret);
	delete downloadui;

	show_msg(MSGDEBUG, "download ui finished![%d]\n", runret);
	return (1);
}

struct BROWSER_ITEM { 
	int raw_index;
	char *raw_text;
	char *ping_addr;
	char *server_stat_url;
};


void listbox_callback(Fl_Widget* o, void* v) 
{
	Fl_Browser *listbox = (Fl_Browser*)o;
	int index = listbox->value();
	if (index > 0)
	{
		SelectServer *selectui = (SelectServer*)v;
		const char *linetext = listbox->text(index);
		BROWSER_ITEM *item = (BROWSER_ITEM*)listbox->data(index);

		wchar_t wbuffer[128]={0};
		wchar_t *linetext_w = m2w(linetext);
		swprintf(wbuffer, L"您选择了：%s\n", linetext_w);
		free(linetext_w);
		selectui->set_captions(NULL,NULL,NULL,_utf8(wbuffer),item->raw_index);

		show_msg(MSGDEBUG, "callback, index = %d(%d), text = %s\n", index, item->raw_index, linetext);
	}
}


void * update_lines_thread(void *param)
{
	SelectServer *selectui = (SelectServer*)param;
	Fl_Browser *listbox = selectui->ServerBrowser;
  	listbox->callback(listbox_callback, selectui);
	BROWSER_ITEM *item;
	int argc = selectui->argc;
	char **argv = selectui->argv;
	int i;
	int linecount;
	int waitret;
	int index_run = 0;
	struct timeval now;
	struct timespec outtime;
	pthread_cond_t *cond = (pthread_cond_t*)selectui->thread_cond;
	pthread_mutex_t mutex;
	pthread_mutex_init(&mutex, NULL);
	pthread_mutex_lock(&mutex);

	assert(argc);
	assert(argv);
	assert(mutex);
	assert(*cond);

	//首次填写数据
	Fl::lock();
	{
		for (i=0; i<argc; i++)
		{
			item = (BROWSER_ITEM*)malloc(sizeof(BROWSER_ITEM));
			memset(item, 0, sizeof(BROWSER_ITEM));
			item->raw_index = i;
			item->raw_text = strdup(argv[i]);
			listbox->add(argv[i], item);
		}
	}
	Fl::unlock();
	Fl::awake();

	//服务器列表维护流程
	do {
		show_msg(MSGDEBUG, "check server static routine[%d].\n", ++index_run);

		Fl::lock();
		{


		}
		Fl::unlock();
		Fl::awake();

		gettimeofday(&now, NULL);
		outtime.tv_sec = now.tv_sec + 2;
		outtime.tv_nsec = now.tv_usec * 1000;
	} while (ETIMEDOUT == pthread_cond_timedwait(cond, &mutex, &outtime));

	//清理数据
	Fl::lock();
	{
		if (linecount = listbox->size())
		{
			for (i=1; i<linecount; i++)
			{
				item = (BROWSER_ITEM*)listbox->data(i);
				if (item->raw_text)
					free(item->raw_text);	
				if (item->ping_addr)
					free(item->ping_addr);	
				if (item->server_stat_url)
					free(item->server_stat_url);	
				free(item);
			}
		}
	}
	Fl::unlock();

	pthread_mutex_unlock(&mutex);
	pthread_mutex_destroy(&mutex);

	show_msg(MSGDEBUG, "updat_line_thread exit");
	return NULL;
}

//这时候，select_index的取值有3类：
//（1）：>=0，用户选择了列表中的服务器
//（2）：-1，用户没有选择任何的服务器
//（3）：-2，用户想忽略所有socks服务器
//（4）：-3，关闭进程
extern "C" __declspec(dllexport) 
int select_socks_server(int argc, char **argv) 
{
	SelectServer *selectui = new SelectServer(defined_font);
	selectui->set_captions(_utf8(L"请选择服务器"), _utf8(L"忽略"), _utf8(L"确定"), _utf8(L"未选择服务器"), -1);
	selectui->set_position(-1, -1);
	selectui->show_window();

	//--------------- 创建线程相关 ----------------//

	void *threadret = NULL;
	pthread_t tid;
	pthread_cond_t cond;
	pthread_cond_init(&cond, NULL);

	selectui->argc = argc;
	selectui->argv = argv;
	selectui->need_to_exit = 0;
	selectui->thread_cond= &cond;

	Fl::lock();
	{
		int error = pthread_create(&tid,NULL, update_lines_thread, selectui);
		if(0 != error)
			show_msg(MSGDEBUG, "Couldn't run select server thread, errno %d\n", error);
	}
	Fl::run();
	Fl::unlock();

	selectui->need_to_exit = 1;
	pthread_cond_signal(&cond);
	pthread_join(tid, &threadret);
	pthread_cond_destroy(&cond);

	//-------------- 创建线程结束------------------//
	int user_select_index = selectui->get_select_result();
	delete selectui;
	show_msg(MSGDEBUG, "select server finished![%d]\n", user_select_index);
	return user_select_index;
}


extern "C" BOOL WINAPI DllMain (HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
	switch(fdwReason)
	{
		case DLL_PROCESS_ATTACH:
			show_msg(MSGDEBUG, "Locale is: %s\n", setlocale(LC_ALL, NULL));
			curl_global_init(CURL_GLOBAL_ALL);			
			set_default_font(NULL);
			break;

		case DLL_PROCESS_DETACH:
			curl_global_cleanup();
			break;
	}
	SetLastError(0);
	return (TRUE);
}


