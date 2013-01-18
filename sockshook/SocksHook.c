/* PreProcessor Defines */
#include "config.h"

#ifdef USE_GNU_SOURCE
#define _GNU_SOURCE
#endif


/* Header Files */
#include <windows.h>
#include <windns.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include <string.h>
//#include <strings.h>
#include <sys/types.h>
#include <sys/time.h>

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <errno.h>

#ifdef USE_SOCKS_DNS
#include <resolv.h>
#endif

//#define NDEBUG
#include <assert.h>

#include "parser.h"
#include "tsocks.h"
#include "win32_compatibility.h"
#include "session_funcs.h"

#include "../log/logclient.inc"

typedef DWORD (WINAPI *LPFN_WAITFORMULTIPLEOBJECTSEX) (DWORD,const HANDLE*,BOOL,DWORD,BOOL);
typedef BOOL  (PASCAL *LPFN_CONNECTEX)(SOCKET s,const struct sockaddr* name,int namelen,	PVOID lpSendBuffer,DWORD dwSendDataLength,LPDWORD lpdwBytesSent,LPOVERLAPPED lpOverlapped);

LPFN_CONNECT realconnect;
LPFN_WSACONNECT realwsaconnect;
LPFN_CLOSESOCKET realclosesocket;
LPFN_GETPEERNAME realgetpeername;
LPFN_GETSOCKNAME realgetsockname;
LPFN_SELECT realselect;
LPFN_WSAASYNCSELECT realwsaasyncselect;
LPFN_SETSOCKOPT realsetsockopt;
LPFN_IOCTLSOCKET realioctlsocket;
LPFN_WSAIOCTL realwsaioctl;
LPFN_CONNECTEX realconnectex;

LPFN_WSAEVENTSELECT realwsaeventselect;
LPFN_WAITFORMULTIPLEOBJECTSEX realwaitformultipleobjectsex;
LPFN_WSAENUMNETWORKEVENTS realwsaenumnetworkevents;


//XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-
//XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-
/*
wchar_t * ANSIToUnicode( const char* str )
{
     int textlen ;
     wchar_t * result;
     textlen = MultiByteToWideChar( CP_ACP, 0, str,-1, NULL,0 ); 
     result = (wchar_t *)malloc((textlen+1)*sizeof(wchar_t)); 
     memset(result,0,(textlen+1)*sizeof(wchar_t)); 
     MultiByteToWideChar(CP_ACP, 0,str,-1,(LPWSTR)result,textlen ); 
     return result; 
}

char * UnicodeToANSI( const wchar_t* str )
{
     char* result;
     int textlen;
     textlen = WideCharToMultiByte( CP_ACP, 0, str, -1, NULL, 0, NULL, NULL );
     result =(char *)malloc((textlen+1)*sizeof(char));
     memset( result, 0, sizeof(char) * ( textlen + 1 ) );
     WideCharToMultiByte( CP_ACP, 0, str, -1, result, textlen, NULL, NULL );
     return result;
}

wchar_t * UTF8ToUnicode( const char* str )
{
     int textlen ;
     wchar_t * result;
     textlen = MultiByteToWideChar( CP_UTF8, 0, str,-1, NULL,0 ); 
     result = (wchar_t *)malloc((textlen+1)*sizeof(wchar_t)); 
     memset(result,0,(textlen+1)*sizeof(wchar_t)); 
     MultiByteToWideChar(CP_UTF8, 0,str,-1,(LPWSTR)result,textlen ); 
     return result; 
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

char* ANSIToUTF8(const char* str)
{
     return UnicodeToUTF8(ANSIToUnicode(str));
}

char* UTF8ToANSI(const char* str)
{
     return UnicodeToANSI(UTF8ToUnicode(str));
}
*/

//#include "gb2unicode.inc"

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

//XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-
//XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-


static struct connreq *requests = NULL;
const char* requests_list_cs = "requests_list_cs";
HANDLE socks_finish_event = NULL;

static struct parsedfile *config;
static int suid = 0;
static char *conffile = NULL;
static int selected_index = -1;


unsigned int resolve_ip(char *host, int showmsg, int allownames) 
{
	struct hostent *new;
	unsigned int	hostaddr;
	struct in_addr *ip;

	if ((hostaddr = inet_addr(host)) == (unsigned int) -1) 
	{
		/* We couldn't convert it as a numerical ip so */
		/* try it as a dns name                        */
		if (allownames) 
		{
#ifdef HAVE_GETHOSTBYNAME
			if ((new = gethostbyname(host)) == (struct hostent *) 0) 
			{
				if (showmsg) 
					show_msg(MSGDEBUG, "gethostbyname error\n");
#endif
				return(-1);
#ifdef HAVE_GETHOSTBYNAME
			} 
			else 
			{
				ip = ((struct in_addr *) * new->h_addr_list);
				hostaddr = ip -> s_addr;
				if (showmsg) 
					show_msg(MSGDEBUG, "Connecting to %s...\n", inet_ntoa(*ip));
			}
#endif
		} else
			return(-1);
	}

	return (hostaddr);
}

#define max_seat_num 10
void* seat_list[max_seat_num];
int sit_down_pos = -1;

const char* seat_list_cs = "seat_list_cs";

void free_delay(void* p)
{
	if (sit_down_pos == -1)
	{
		sit_down_pos = 0;
	}

	enter_cs(seat_list_cs);

	void* to_free = seat_list[sit_down_pos];
	if (to_free)
	{
		free(to_free);
	}
	seat_list[sit_down_pos++] = p;
	if (sit_down_pos == max_seat_num)
	{
		sit_down_pos = 0;
	}

	leave_cs(seat_list_cs);
}



static struct connreq *new_socks_request(int sockid, struct sockaddr_in *connaddr, 
                                         struct sockaddr_in *serveraddr, 
                                         struct serverent *path) 
{
	struct connreq *newconn;

	if ((newconn = malloc(sizeof(*newconn))) == NULL) 
	{
		show_msg(MSGERR, "Could not allocate memory for new socks request\n");
		return(NULL);
	}

	memset(newconn, 0x0, sizeof(*newconn));
	newconn->sockid = sockid;
	newconn->starttime = GetTickCount();
	newconn->state = UNSTARTED;
	newconn->path = path;
	memcpy(&(newconn->connaddr), connaddr, sizeof(newconn->connaddr));
	memcpy(&(newconn->serveraddr), serveraddr, sizeof(newconn->serveraddr));

	if (requests == NULL)
	{
		socks_finish_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	}

	enter_cs(requests_list_cs);
	newconn->next = requests;
	requests = newconn;
	leave_cs(requests_list_cs);

	show_msg(MSGDEBUG, "new socks request: %d\n", sockid);
	return(newconn);
}

static void kill_socks_request(struct connreq *conn) 
{
	struct connreq *connnode;

	enter_cs(requests_list_cs);

	if (requests == conn)
	{
		requests = conn->next;
	}
	else 
	{
		for (connnode = requests; connnode != NULL; connnode = connnode->next) 
		{
			if (connnode->next == conn) 
			{
				connnode->next = conn->next;
				break;
			}
		}
	}

	leave_cs(requests_list_cs);
	free_delay(conn);
}

static struct connreq *find_socks_request(int sockid, int includefinished) 
{
	if (!requests || !sockid)
	{
		return (NULL);
	}

	struct connreq *connnode;
	for (connnode = requests; connnode != NULL; connnode = connnode->next) 
	{
		if (connnode->sockid == sockid) 
		{
			if (((connnode->state == FAILURED) || (connnode->state == DONE)) && !includefinished)
			{
				break;
			}
			else 
			{
				return(connnode);
			}
		}
	}

	return(NULL);
}

static struct connreq *find_socks_request_event(HANDLE hEvent , int includefinished) 
{
	if (!hEvent || !requests)
	{
		return (NULL);
	}

	struct connreq *connnode;
	for (connnode = requests; connnode != NULL; connnode = connnode->next) 
	{
		if (connnode->hWsaEvent == hEvent) 
		{
			if (((connnode->state == FAILURED) || (connnode->state == DONE)) && !includefinished)
			{
				break;
			}
			else 
			{
				return(connnode);
			}
		}
	}
	return(NULL);
}


static int conn_list_count(int includefinished) 
{
	if (!requests)
	{
		return (0);
	}
	
	int ncount = 0;
	struct connreq *connnode;
	for (connnode = requests; connnode != NULL; connnode = connnode->next) 
	{
		ncount++;
		if (((connnode->state == FAILURED) || (connnode->state == DONE)) && !includefinished)
		{
			ncount--;
		}
	}
	return(ncount);
}

static int connect_server(struct connreq *conn) 
{
	int rc;

	/* Connect this socket to the socks server */
	show_msg(MSGDEBUG, " -- Connecting to %s port %d\n", inet_ntoa(conn->serveraddr.sin_addr), ntohs(conn->serveraddr.sin_port));

	if (conn->spec_connect)
	{
		rc = conn->spec_connect(conn->sockid, (CONNECT_SOCKARG) &(conn->serveraddr),sizeof(conn->serveraddr));
	}
	else
	{
		rc = realconnect(conn->sockid, (CONNECT_SOCKARG) &(conn->serveraddr),sizeof(conn->serveraddr));
	}


	DWORD last_err = WSAGetLastError();

	show_msg(MSGDEBUG, " -- Connect returned %d, last_err is %d\n", rc, last_err); 
	if (rc == SOCKET_ERROR) 
	{
	
		if (last_err == WSAEWOULDBLOCK) 
		{
			 show_msg(MSGDEBUG, " -- Connection in progress\n");
			 conn->state = CONNECTING;
		} 
		else 
		{
			 show_msg(MSGERR, " -- socket:%d Error %d attempting to connect to SOCKS server (%s)\n", conn->sockid, last_err, gai_strerror(last_err));
			 conn->state = FAILURED;
		}
	} 
	else 
	{
		show_msg(MSGDEBUG, " -- Socket %d connected to SOCKS server\n", conn->sockid);
		conn->state = CONNECTED;
	}

	return ((rc ? last_err : 0));
}

static int send_socksv4_request(struct connreq *conn) 
{
	struct passwd *user;
	struct sockreq *thisreq;

	/* Determine the current username */
	user = getpwuid(getuid());	

	thisreq = (struct sockreq *) conn->buffer;

	/* Check the buffer has enough space for the request  */
	/* and the user name                                  */
	conn->datalen = sizeof(struct sockreq) + (user == NULL ? 0 : strlen(user->pw_name)) + 1;
	if (sizeof(conn->buffer) < conn->datalen) 
	{
		show_msg(MSGERR, " -- The SOCKS username is too long\n");
		conn->state = FAILURED;
		return(WSAECONNREFUSED);
	}

	/* Create the request */
	thisreq->version = 4;
	thisreq->command = 1;
	thisreq->dstport = conn->connaddr.sin_port;
	thisreq->dstip   = conn->connaddr.sin_addr.s_addr;

	/* Copy the username */
	strcpy((char *) thisreq + sizeof(struct sockreq), (user == NULL ? "" : user->pw_name));

	conn->datadone = 0;
	conn->state = SENDING;
	conn->nextstate = SENTV4REQ;

	return(0);   
}			

static int send_socksv5_method(struct connreq *conn) 
{
	char verstring[] = { 0x05,    /* Version 5 SOCKS */
			0x02,    /* No. Methods     */
			0x00,    /* Null Auth       */
			0x02 };  /* User/Pass Auth  */

	show_msg(MSGDEBUG, " -- Constructing V5 method negotiation\n");
	conn->state = SENDING;
	conn->nextstate = SENTV5METHOD;
	memcpy(conn->buffer, verstring, sizeof(verstring)); 
	conn->datalen = sizeof(verstring);
	conn->datadone = 0;

	return(0);
}			

static int send_socks_request(struct connreq *conn) 
{
	int rc = 0;

	if (conn->path->type == 4) 
		rc = send_socksv4_request(conn);
	else
		rc = send_socksv5_method(conn);

	return(rc);
}			

static int send_socksv5_connect(struct connreq *conn) 
{
	char constring[] = { 0x05,    /* Version 5 SOCKS */
			0x01,    /* Connect request */
			0x00,    /* Reserved        */
			0x01 };  /* IP Version 4    */

	show_msg(MSGDEBUG, " -- Constructing V5 connect request\n");
	conn->datadone = 0;
	conn->state = SENDING;
	conn->nextstate = SENTV5CONNECT;
	memcpy(conn->buffer, constring, sizeof(constring)); 
	conn->datalen = sizeof(constring);
	memcpy(&conn->buffer[conn->datalen], &(conn->connaddr.sin_addr.s_addr), sizeof(conn->connaddr.sin_addr.s_addr));
	conn->datalen += sizeof(conn->connaddr.sin_addr.s_addr);
	memcpy(&conn->buffer[conn->datalen], &(conn->connaddr.sin_port), sizeof(conn->connaddr.sin_port));
	conn->datalen += sizeof(conn->connaddr.sin_port);

	return(0);
}			

void print_hexstring(char* title, void *p, int len)
{
	unsigned char buffer[256];
	unsigned char *s = p;
	int cplen = 0;

	memset(buffer, 0, 256);
	while (len--) 
	{
		sprintf(&buffer[cplen], "%02x \0", *s++);
		cplen += 3;
	}

	show_msg(MSGDEBUG, "%s : %s\n", title, buffer);
}

char* state2str(int state)
{
	switch (state) {
		case UNSTARTED: return "UNSTARTED";
		case CONNECTING: return "CONNECTING";  
		case CONNECTED : return "CONNECTED";
		case SENDING : return "SENDING";
		case RECEIVING : return "RECEIVING";
		case SENTV4REQ : return "SENTV4REQ";
		case GOTV4REQ  : return "GOTV4REQ";
		case SENTV5METHOD : return "SENTV5METHOD";
		case GOTV5METHOD : return "GOTV5METHOD";
		case SENTV5AUTH : return "SENTV5AUTH";
		case GOTV5AUTH : return "GOTV5AUTH";
		case SENTV5CONNECT: return "SENTV5CONNECT";
		case GOTV5CONNECT: return "GOTV5CONNECT";
		case DONE: return "DONE";
		case FAILURED : return "FAILURED";
		case DONEFINISH : return "DONEFINISH";
		case FAILFINISH : return "FAILFINISH";
	}
	return "UNKNOW";
}

static int send_buffer(struct connreq *conn) 
{
	int rc = 0;

	show_msg(MSGDEBUG, " -- Writing to server (sending %d bytes)\n", conn->datalen);
	while ((rc == 0) && (conn->datadone != conn->datalen)) 
	{
		rc = send(conn->sockid, conn->buffer + conn->datadone, conn->datalen - conn->datadone, 0);
		if (rc > 0) 
		{
			conn->datadone += rc;
			rc = 0;
		} 
		else 
		{
			DWORD last_err = WSAGetLastError();
			if (last_err != WSAEWOULDBLOCK)
			{
				show_msg(MSGDEBUG, " -- Write failed, %s\n", gai_strerror(last_err));
			}
			rc = last_err;
		}
	}

	if (conn->datadone == conn->datalen) 
	{
		conn->state = conn->nextstate;
		print_hexstring(" -- send_buffer OK >>>>>>", conn->buffer, conn->datadone);
	}

	show_msg(MSGDEBUG, " -- Sent %d bytes of %d bytes in buffer, return code is %d\n", conn->datadone, conn->datalen, rc);
	return(rc);
}

static int recv_buffer(struct connreq *conn) 
{
	int rc = 0;

	show_msg(MSGDEBUG, " -- Reading from server (expecting %d bytes)\n", conn->datalen);
	while (conn->datadone != conn->datalen) 
	{
		rc = recv(conn->sockid, conn->buffer + conn->datadone, conn->datalen - conn->datadone, 0);

		if (rc > 0) 
		{
			conn->datadone += rc;
			show_msg(MSGDEBUG, " -- had read from server (done %d bytes)\n", conn->datadone);
		} 
		else if (rc == 0) 
		{
			conn->state = FAILURED;
			show_msg(MSGDEBUG, " -- recv=0, socket(%d) gracefully closed(%d).\n", conn->sockid, WSAGetLastError());
			break;
		} 
		else 
		{
			rc = WSAGetLastError();
			if (rc != WSAEWOULDBLOCK)
			{
				show_msg(MSGDEBUG, "Read failed(%d), %s\n", rc, gai_strerror(rc));
			}
			break;
		}
	}

	if (conn->datadone == conn->datalen) 
	{
		print_hexstring(" -- recv_buffer OK <<<<<<", conn->buffer, conn->datadone);
		conn->state = conn->nextstate;
		rc = 0;
	}

	show_msg(MSGDEBUG, " -- Received %d bytes of %d bytes expected, return code is %d\n", conn->datadone, conn->datalen, rc);
	return(rc);
}

static int read_socksv5_method(struct connreq *conn) 
{
	struct passwd *nixuser;
	char *uname, *upass;

	/* See if we offered an acceptable method */
	if (conn->buffer[1] == '\xff') 
	{
		show_msg(MSGERR, " -- SOCKS V5 server refused authentication methods\n");
		conn->state = FAILURED;
		return(WSAECONNREFUSED);
	}

	/* If the socks server chose username/password authentication */
	/* (method 2) then do that                                    */
	if ((unsigned short int) conn->buffer[1] == 2) 
	{
		show_msg(MSGDEBUG, " -- SOCKS V5 server chose username/password authentication\n");

		/* Determine the current *nix username */
		nixuser = getpwuid(getuid());	

		if (((uname = conn->path->defuser) == NULL) && ((uname = getenv("TSOCKS_USERNAME")) == NULL) &&
		    ((uname = (nixuser == NULL ? NULL : nixuser->pw_name)) == NULL)) 
		    {
			show_msg(MSGERR, " -- Could not get SOCKS username from local passwd file, tsocks.conf "
				   "or $TSOCKS_USERNAME to authenticate with\n"); 
			conn->state = FAILURED;
			return(WSAECONNREFUSED);
		} 

		if (((upass = getenv("TSOCKS_PASSWORD")) == NULL) && ((upass = conn->path->defpass) == NULL)) 
		{
			show_msg(MSGERR, " -- Need a password in tsocks.conf or $TSOCKS_PASSWORD to authenticate with\n");
			conn->state = FAILURED;
			return(WSAECONNREFUSED);
		} 

		/* Check that the username / pass specified will */
		/* fit into the buffer				                */
		if ((3 + strlen(uname) + strlen(upass)) >= sizeof(conn->buffer)) 
		{
			show_msg(MSGERR, " -- The supplied socks username or password is too long\n");
			conn->state = FAILURED;
			return(WSAECONNREFUSED);
		}
		
		conn->datalen = 0;
		conn->buffer[conn->datalen] = '\x01';
		conn->datalen++;
		conn->buffer[conn->datalen] = (int8_t) strlen(uname);
		conn->datalen++;
		memcpy(&(conn->buffer[conn->datalen]), uname, strlen(uname));
		conn->datalen = conn->datalen + strlen(uname);
		conn->buffer[conn->datalen] = (int8_t) strlen(upass);
		conn->datalen++;
		memcpy(&(conn->buffer[conn->datalen]), upass, strlen(upass));
		conn->datalen = conn->datalen + strlen(upass);

		conn->state = SENDING;
		conn->nextstate = SENTV5AUTH;
		conn->datadone = 0;
	} else
		return(send_socksv5_connect(conn));

   return(0);
}

static int read_socksv5_auth(struct connreq *conn) 
{
	if (conn->buffer[1] != '\x00') 
	{
		show_msg(MSGERR, " -- SOCKS authentication failed, check username and password\n");
		conn->state = FAILURED;
		return(WSAECONNREFUSED);
	}

	/* Ok, we authenticated ok, send the connection request */
	return(send_socksv5_connect(conn));
}

static int read_socksv5_connect(struct connreq *conn) {

	/* See if the connection succeeded */
	if (conn->buffer[1] != '\x00') 
	{
		show_msg(MSGERR, " -- SOCKS V5 connect failed: \n");
		conn->state = FAILURED;
		switch ((int8_t) conn->buffer[1]) {
			case 1:
				show_msg(MSGERR, " -- General SOCKS server failure\n");
				return(WSAECONNABORTED);
			case 2:
				show_msg(MSGERR, " -- Connection denied by rule\n");
				return(WSAECONNABORTED);
			case 3:
				show_msg(MSGERR, " -- Network unreachable\n");
				return(WSAENETUNREACH);
			case 4:
				show_msg(MSGERR, " -- Host unreachable\n");
				return(WSAEHOSTUNREACH);
			case 5:
				show_msg(MSGERR, " -- Connection refused\n");
				return(WSAECONNREFUSED);
			case 6: 
				show_msg(MSGERR, " -- TTL Expired\n");
				return(WSAETIMEDOUT);
			case 7:
				show_msg(MSGERR, " -- Command not supported\n");
				return(WSAECONNABORTED);
			case 8:
				show_msg(MSGERR, " -- Address type not supported\n");
				return(WSAECONNABORTED);
			default:
				show_msg(MSGERR, " -- Unknown error\n");
				return(WSAECONNABORTED);
		}	
	} 

   conn->state = DONE;

   return(0);
}

static int read_socksv4_req(struct connreq *conn) 
{
	struct sockrep *thisrep;

	thisrep = (struct sockrep *) conn->buffer;

	if (thisrep->result != 90) 
	{
		show_msg(MSGERR, " -- SOCKS V4 connect rejected:\n");
		conn->state = FAILURED;
		switch(thisrep->result) {
			case 91:
				show_msg(MSGERR, " -- SOCKS server refused connection\n");
				return(WSAECONNREFUSED);
			case 92:
				show_msg(MSGERR, " -- SOCKS server refused connection because of failed connect to identd on this machine\n");
				return(WSAECONNREFUSED);
			case 93:
				show_msg(MSGERR, " -- SOCKS server refused connection because identd and this library reported different user-ids\n");
				return(WSAECONNREFUSED);
			default:
				show_msg(MSGERR, " -- Unknown reason\n");
				return(WSAECONNREFUSED);
		}
	}

	conn->state = DONE;

	return(0);
}

static int handle_request(struct connreq *conn) 
{
	int rc = 0;
	int i = 0;

	show_msg(MSGDEBUG, "handle_request===Beginning loop for socket %d\n", conn->sockid);

	while ((rc == 0) && (conn->state != FAILURED) && (conn->state != DONE) && (i++ < 20)) 
	{
		show_msg(MSGDEBUG, " -- In request handle loop for socket %d,current state of request is %s\n", conn->sockid, state2str(conn->state));
		switch(conn->state) 
		{
			 case UNSTARTED:
			 case CONNECTING:
				 rc = connect_server(conn);
				 break;
			 case CONNECTED: //key point
				 rc = send_socks_request(conn);
				 break;
			 case SENDING:
				 rc = send_buffer(conn);
				 break;
			 case RECEIVING:
				 rc = recv_buffer(conn);
				 break;
			 case SENTV4REQ:
				 show_msg(MSGDEBUG, " -- Receiving reply to SOCKS V4 connect request\n");
				 conn->datalen = sizeof(struct sockrep);
				 conn->datadone = 0;
				 conn->state = RECEIVING;
				 conn->nextstate = GOTV4REQ;
				 break;
			 case GOTV4REQ:
				 rc = read_socksv4_req(conn);
				 break;
			 case SENTV5METHOD:
				 show_msg(MSGDEBUG, " -- Receiving reply to SOCKS V5 method negotiation\n");
				 conn->datalen = 2;
				 conn->datadone = 0;
				 conn->state = RECEIVING;
				 conn->nextstate = GOTV5METHOD;
				 break; 
			 case GOTV5METHOD:
				 rc = read_socksv5_method(conn);
				 break;
			 case SENTV5AUTH:
				 show_msg(MSGDEBUG, " -- Receiving reply to SOCKS V5 authentication negotiation\n");
				 conn->datalen = 2;
				 conn->datadone = 0;
				 conn->state = RECEIVING;
				 conn->nextstate = GOTV5AUTH;
				 break;
			 case GOTV5AUTH:
				 rc = read_socksv5_auth(conn);
				 break;
			 case SENTV5CONNECT:
				 show_msg(MSGDEBUG, " -- Receiving reply to SOCKS V5 connect request\n");
				 conn->datalen = 10;
				 conn->datadone = 0;
				 conn->state = RECEIVING;
				 conn->nextstate = GOTV5CONNECT;
				 break;
			 case GOTV5CONNECT:
				 rc = read_socksv5_connect(conn);
				 break;
		}

		conn->err = WSAGetLastError();
	}

	if (i == 20)
	{
		show_msg(MSGERR, " -- Ooops, state loop while handling request %d\n", conn->sockid);
	}

	show_msg(MSGDEBUG, "handle_request===loop completed for socket %d in state %s, returning %d\n", conn->sockid, state2str(conn->state), rc);

	return(rc);
}



int send_request(struct sockaddr_in *server, void *req, int reqlen, void *rep, int replen) 
{
	int sock;
	int rc = 0;

	if ((sock = socket(server->sin_family, SOCK_STREAM, 0)) < 0) 
	{
		show_msg(MSGERR, "Could not create socket (%s)\n",  gai_strerror(WSAGetLastError()));
		return(0);
	}
	
	do 
	{
		if (connect(sock, (struct sockaddr *) server, sizeof(struct sockaddr_in)) != -1) 
		{
		} 
		else 
		{
			show_msg(MSGERR, "Connect failed! (%s)\n", gai_strerror(WSAGetLastError()));
			break;
		}

		if (send(sock, (void *) req, reqlen,0) < 0) 
		{
			show_msg(MSGERR, "Could not send to server (%s)\n",  gai_strerror(WSAGetLastError()));
			break;
		}

		/* Now wait for reply */
		if ((rc = recv(sock, (void *) rep, replen, 0)) < 0) 
		{
			show_msg(MSGERR, "Could not read from server\n", gai_strerror(WSAGetLastError()));
			break;
		}
		
	} while (FALSE);

	closesocket(sock);
	return(rc);
}

/* Global configuration variables */ 
int defaultport	= 1080;			   /* Default SOCKS port       */

int inspecsocks(char* hoststr, char* portstr) {
	char *usage = "Usage: <socks server name/ip> [portno]";
	char req[9];
	char resp[100];
	unsigned short int portno = defaultport;
	int ver = 0;
	int read_bytes;
	struct sockaddr_in server;

	portno = (unsigned short int) strtol(portstr, (char **) 0, 10);
	if ((portno == 0) || (errno == EINVAL)) {
		show_msg(MSGERR, "%s\n", usage);
		return 1;
	}
	if ((server.sin_addr.s_addr = resolve_ip(hoststr, 1,HOSTNAMES)) ==  -1) {
		show_msg(MSGERR, "Invalid IP/host specified (%s)\n", hoststr);
		return 1;
	}

	server.sin_family = AF_INET; /* host byte order */
	server.sin_port = htons(portno);     /* short, network byte order */
	bzero(&(server.sin_zero), 8);/* zero the rest of the struct */

	/* Now, we send a SOCKS V5 request which happens to be */
	/* the same size as the smallest possible SOCKS V4     */
	/* request. In this packet we specify we have 7 auth   */
	/* methods but specify them all as NO AUTH.            */
	bzero(req, sizeof(req));
	req[0] = '\x05';
	req[1] = '\x07';
	read_bytes = send_request(&server, req, sizeof(req), resp, sizeof(resp));
	if (read_bytes > 0) {
		if ((int) resp[0] == 0) {
			ver = 4;
		} else if ((int) resp[0] == 5) {
			ver = 5;
		} 
		if (ver != 0) {
			show_msg(MSGNONE, "Reply indicates server is a version %d socks server\n", ver);
		} else {
			show_msg(MSGERR, "Invalid SOCKS version reply (%d), probably not a socks server\n", ver);
		}
		return 0;
	}	

	/* Hmmm.... disconnected so try a V4 request */
	printf("Server disconnected V5 request, trying V4\n");
	req[0] = '\x04';
	req[1] = '\x01';
	read_bytes = send_request(&server, req, sizeof(req), resp, sizeof(resp));	
	if (read_bytes > 0) {
		if ((int) resp[0] == 0) {
			ver = 4;
		} 
		if (ver == 4) {
			printf("Reply indicates server is a version 4 socks server\n");
		} else {
			show_msg(MSGERR, "Invalid SOCKS version reply (%d), probably not a socks server\n", (int) resp[0]);
		}
		return(0);
	} else {
		show_msg(MSGERR, "Server disconnected, probably not a socks server\n");
	}

	return(0);  
}


//XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-
//XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-XXX-

int PASCAL hook_closesocket(SOCKET s) 
{
	int rc;
	struct connreq *conn;

	if (realclosesocket == NULL) 
	{
		show_msg(MSGERR, "Unresolved symbol: close\n");
		return(-1);
	}

//	show_msg(MSGDEBUG, "Call to close(%d)\n", s);

	rc = realclosesocket(s);

	/* If we have this fd in our request handling list we 
	 * remove it now */
	if ((conn = find_socks_request(s, 1))) 
	{
		show_msg(MSGNOTICE, "closesocket: s=%d conn status %s\n", conn->sockid, state2str(conn->state));
		kill_socks_request(conn);
	}

	return(rc);
}


char * event2str_select(int events)
{
	char buffer[256];
	memset(buffer, 0, sizeof(buffer));

	if (events & WRITE)
		strcat(buffer, "WRITE | ");
	if (events & READ)
		strcat(buffer, "READ | ");
	if (events & EXCEPT)
		strcat(buffer, "EXCEPT | ");

	if (strlen(buffer) == 0)
	{
		sprintf(buffer, "UNKNOW(%d) | ", events);
	}

	int len = strlen(buffer);
	if (len > 3)
	{
		buffer[len-3] = '\0';
	}
	return strdup(buffer);
}

int subcall_select(struct connreq *conn, long sec, long usec) 
{
	fd_set mywritefds, myreadfds, myexceptfds;
	int subret, nfds=0;
	struct timeval timeout;
	int runret = 0;

	FD_ZERO(&myreadfds);
	FD_ZERO(&mywritefds);
	FD_ZERO(&myexceptfds); 
	FD_SET(conn->sockid, &myexceptfds);

	if ((conn->state == SENDING) || (conn->state == CONNECTING))
	{
		FD_SET(conn->sockid,&mywritefds);
	}
	if (conn->state == RECEIVING) 
	{
		FD_SET(conn->sockid,&myreadfds);
	}
	nfds++;

	fd_set *rr = (myreadfds.fd_count) ? &myreadfds : NULL;
	fd_set *ww = (mywritefds.fd_count) ? &mywritefds : NULL;
	fd_set *ee = (myexceptfds.fd_count) ? &myexceptfds : NULL;
	timeout.tv_sec = sec;
	timeout.tv_usec = usec;

	subret = realselect(nfds, rr, ww, ee, &timeout);

	//请求发生错误了。
	if (subret = SOCKET_ERROR) 
	{
		DWORD last_err = WSAGetLastError();
		if (last_err) 
		{
			show_msg(MSGDEBUG, "sub_realselect: socket=%d, error=%s\n", conn->sockid, gai_strerror(last_err));
			runret |= (FD_ISSET(conn->sockid, &myexceptfds)) ? EXCEPT : 0;
		} 
		else 
		{
			runret |= (FD_ISSET(conn->sockid, &myexceptfds)) ? EXCEPT : 0;
			runret |= (FD_ISSET(conn->sockid, &mywritefds)) ? WRITE : 0;
			runret |= (FD_ISSET(conn->sockid, &myreadfds)) ? READ : 0;
		}
	}

	//看看有那些状态改变了？
	if (subret > 0) 
	{
		runret |= (FD_ISSET(conn->sockid, &myexceptfds)) ? EXCEPT : 0;
		runret |= (FD_ISSET(conn->sockid, &mywritefds)) ? WRITE : 0;
		runret |= (FD_ISSET(conn->sockid, &myreadfds)) ? READ : 0;
	}

	return runret;
}

DWORD WINAPI socks_thread_select(struct connreq *conn)
{
	assert(conn);

	show_msg(MSGDEBUG, "select_thread: enter socks_thread_select. %s\n", state2str(conn->state));

	assert(conn->state == CONNECTING);
	conn->state = CONNECTED;

	SetEvent(conn->threadevent_select);

	int rc;
	int nfds;
	int selectrc;
	int times = 0;

	do {
		rc = handle_request(conn);

		if (rc)
		{
			if (rc != WSAEWOULDBLOCK) 
			{
				conn->state == FAILURED;
				conn->donetime = GetTickCount();
				show_msg(MSGNOTICE, "select_thread: ERROR: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
				break;
			}		
		}

		if (conn->state == DONE) 
		{
			conn->donetime = GetTickCount();
			show_msg(MSGNOTICE, "select_thread DONE: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
			break;
		}

		if (conn->state == FAILURED) 
		{
			conn->donetime = GetTickCount();
			show_msg(MSGNOTICE, "select_thread FAILURED: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
			break;
		}

		selectrc = subcall_select(conn, 3, 0);

		if (selectrc & EXCEPT)
		{
			conn->donetime = GetTickCount();
			show_msg(MSGNOTICE, "select_thread select FAILURED: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
			break;
		}

		if (++times > 3) 
		{
			conn->donetime = GetTickCount();
			show_msg(MSGNOTICE, "select_thread select times out: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
			break;
		}
		
	} while (TRUE);

	if (conn->state != DONE) 
	{
		conn->state = FAILURED;
		show_msg(MSGDEBUG, "select_thread: fixed FAILURED. %s\n", state2str(conn->state));
	}

	show_msg(MSGDEBUG, "select_thread: finished. %s\n", state2str(conn->state));
	conn->waitup = 1;

	SetEvent(socks_finish_event);
	return 0;
}

void print_fd_set(char* title, fd_set *fds)
{
	char print_buff[MAX_PATH];
	int i;

	if ((fds) && (fds->fd_count)) 
	{
		sprintf(print_buff, "fd_set\"%s\":", title);
		for (i=0; i<fds->fd_count; i++)
		{
			sprintf(print_buff, "%s %d", print_buff, fds->fd_array[i]); 
		}
		show_msg(MSGDEBUG, "%s\n", print_buff);
	} 
}

int PASCAL hook_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout) 
{
	int rc = 0;
	int runret = 0;
	int new_thread_counter = 0;
	struct connreq *conn, *nextconn;
	fd_set mywritefds, myreadfds, myexceptfds;

	//检查是否经过conenct的初始化。
	if (!requests)
	{
		return realselect(nfds, readfds, writefds, exceptfds, timeout);
	}

	print_fd_set("ori readfds", readfds);
	print_fd_set("ori writefds", writefds);
	print_fd_set("ori exceptfds", exceptfds);
	
	//看看宿主期待什么事件
	int has_waitups = 0;
	for (conn = requests; conn != NULL; conn = conn->next) 
	{
		//select唤醒辅助标记
		if (conn->master_bypass)
		{
			continue;
		}

		//看看有没有已经搞定了的？记录一下
		if (conn->waitup)
		{
			show_msg(MSGDEBUG, "socket %d was waitup", conn->sockid);
 			has_waitups++;
		}

		//记录原始请求
		show_msg(MSGDEBUG, "hook_select: check ori expect_events: %d\n", conn->sockid);
		conn->expect_events = 0;

		if (readfds)
		{
			if (FD_ISSET(conn->sockid, readfds))
			{
				show_msg(MSGDEBUG, "hook_select: %d event has READ", conn->sockid);
				conn->expect_events |= READ;
			}
		}
		if (writefds)
		{
			if (FD_ISSET(conn->sockid, writefds))
			{
				show_msg(MSGDEBUG, "hook_select: %d event has WRITE", conn->sockid);
				conn->expect_events |= WRITE;
			}
		}
		if (exceptfds)
		{
			if (FD_ISSET(conn->sockid, exceptfds))
			{
				show_msg(MSGDEBUG, "hook_select: %d event has EXCEPT", conn->sockid);
				conn->expect_events |= EXCEPT;
			}
		}

		//从待连接列表中，已经找出这个conn是需要处理的
		if (conn->expect_events) 
		{
			//将需要向socks服务器发出CONNECT请求的，判断出来
			if ((conn->expect_events & WRITE) && (conn->state == CONNECTING) && (conn->tid == 0)) 
			{
				//单独检测该socket的状态
				int subevents = subcall_select(conn, 1, 0);
				show_msg(MSGDEBUG, "hook_select: Socket %d was connection events:%s -> %s\n", conn->sockid, event2str_select(conn->expect_events), event2str_select(subevents));
				if (subevents & WRITE) 
				{
					if (new_thread_counter++ == 0)
					{
						ResetEvent(socks_finish_event);
					}

					show_msg(MSGDEBUG, "hook_select: CreateThread socket=%d\n", conn->sockid);
					//创建新线程单独处理socks逻辑
					conn->threadevent_select = CreateEvent(NULL, FALSE, FALSE, NULL);
					CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&socks_thread_select, conn, 0, &conn->tid));
					WaitForSingleObject(conn->threadevent_select, INFINITE);
					CloseHandle(conn->threadevent_select);
				}
			}
		}

		//未完成socket握手前，不准查询
		show_msg(MSGDEBUG, "hook_select: clear src request: %d\n", conn->sockid);

		if (readfds)
		{
			FD_CLR(conn->sockid, readfds);
		}
		if (writefds)
		{
			FD_CLR(conn->sockid, writefds);
		}
		if (exceptfds)
		{
			FD_CLR(conn->sockid, exceptfds);
		}
		nfds--;
	}

	show_msg(MSGDEBUG, "hook_select: enter select routine (sec:%d, usec:%d)\n", timeout->tv_sec, timeout->tv_usec);

	//所谓other sockets，就是那些正常的封包了。
	int has_other_sockets = 0;
	has_other_sockets += ((readfds) && (readfds->fd_count))? readfds->fd_count : 0;
	has_other_sockets += ((writefds) && (writefds->fd_count))? writefds->fd_count : 0;
	has_other_sockets += ((exceptfds) && (exceptfds->fd_count))? exceptfds->fd_count : 0;

	if (has_other_sockets) 
	{
		fd_set enum_writefds, enum_readfds, enum_exceptfds;
		fd_set *ww, *rr, *ee;
		FD_ZERO(&enum_writefds);
		FD_ZERO(&enum_readfds);
		FD_ZERO(&enum_exceptfds);

		struct timeval perrun;
		perrun.tv_sec = 0;
		perrun.tv_usec = 10*1000;
		long maxtime = timeout->tv_sec * 1000 + timeout->tv_usec / 1000 + GetTickCount();

		do {
			if ((readfds) && (readfds->fd_count)) 
			{
				enum_readfds = *readfds;
				rr = &enum_readfds;
			} 
			else 
			{
				rr = NULL;
			}

			if ((writefds) && (writefds->fd_count)) 
			{
				enum_writefds = *writefds;
				ww = &enum_writefds;
			} 
			else
			{
				ww = NULL;
			}

			if ((exceptfds) && (exceptfds->fd_count)) 
			{
				enum_exceptfds = *exceptfds;
				ee = &enum_exceptfds;
			} 
			else
			{
				ee = NULL;
			}

			runret = realselect(nfds, rr, ww, ee, &perrun);

			for (conn = requests; conn != NULL; conn = conn->next) 
			{
				if ((conn->waitup) && (!(conn->master_bypass))) 
				{
					show_msg(MSGDEBUG, "hook_select: realselect waitup = %d\n", conn->sockid);
					maxtime = 0;
					break;
				}
			}

			if (runret == SOCKET_ERROR) 
			{
				show_msg(MSGDEBUG, "hook_select: realselect errno = %d(%s)\n", WSAGetLastError(),  gai_strerror(WSAGetLastError()));
				runret = 0;
				break;
			}

			if (runret > 0)
			{
				show_msg(MSGDEBUG, "hook_select: realselect signed %d result\n", runret);
				break;
			}
		} while (GetTickCount() < maxtime);
		
		if (readfds)
		{
			*readfds = enum_readfds;
		}

		if (writefds)
		{
			*writefds = enum_writefds;
		}

		if (exceptfds)
		{
			*exceptfds = enum_exceptfds;
		}

	} 
	else 
	{
		show_msg(MSGDEBUG, "hook_select: emptey exit, must wait\n");
		if (has_waitups == 0)
		{
			if (new_thread_counter)
			{
				DWORD begin_tick = GetTickCount();
				DWORD wait_time = (timeout->tv_sec)? timeout->tv_sec * 1000 : 1000;
				WaitForSingleObject(socks_finish_event, wait_time);
				show_msg(MSGDEBUG, "hook_select: been waited %d\n", GetTickCount()-begin_tick);
			}
			else
			{
				return (0);
			}
		}
	}

	//检查这个selec请求是否有我们关心的socket，并打上宿主的请求意愿。
	int add_count = 0;
	int setevents = 0;
	for (conn = requests; conn != NULL; conn = conn->next) 
	{
		if (conn->master_bypass) continue;
		if (!(conn->waitup)) continue;

		show_msg(MSGDEBUG, "hook_select: start get result %d (%s)\n", conn->sockid, event2str_select(conn->expect_events));

		//if (conn->expect_events) 
		{
			if (conn->state == DONE) 
			{
				show_msg(MSGDEBUG, "hook_select: feedback DONE result: %d\n", conn->sockid);
				if (writefds) FD_SET(conn->sockid, writefds);
				if (readfds) FD_CLR(conn->sockid, readfds);
				if (exceptfds) FD_CLR(conn->sockid, exceptfds);
				
				conn->master_bypass = 1;
				add_count++;
				continue;
			}

			if (conn->state == FAILURED) 
			{
				show_msg(MSGDEBUG, "hook_select: feedback FAILURED result: %d\n", conn->sockid);
				if (writefds) FD_CLR(conn->sockid, writefds);
				if (readfds) FD_CLR(conn->sockid, readfds);
				if (exceptfds) FD_SET(conn->sockid, exceptfds);

				conn->master_bypass = 1;
				add_count++;
				continue;
			}
		}
	}

	int total_ret = runret + add_count;
	show_msg(MSGDEBUG, "hook_select: result %d (extra_add: %d)\n", total_ret, add_count);

	if (total_ret)
	{
		print_fd_set("readfds", readfds);
		print_fd_set("writefds", writefds);
		print_fd_set("exceptfds", exceptfds);
	}

	return (total_ret);
}



char* cmd2str(long cmd) 
{
	switch (cmd) 
	{
		case FIONBIO: return "FIONBIO";
		case FIONREAD: return "FIONREAD";
		case SIOCATMARK: return "SIOCATMARK";
	}
	return "UNKNOW";
}


int PASCAL hook_ioctlsocket(SOCKET s, long cmd, u_long *argp) 
{
	//show_msg(MSGDEBUG, "ioctlsocket: s:%d, cmd:%s, argp:%d\n", s, cmd2str(cmd), *argp);
	return realioctlsocket(s, cmd, argp);
}

int PASCAL hook_getpeername(SOCKET s, struct sockaddr *name, int *namelen) 
{
	show_msg(MSGDEBUG, "getpeername: s:%d\n", s);
	return realgetpeername(s, name, namelen);
}

int PASCAL hook_getsockname(SOCKET s, struct sockaddr *name, int *namelen) 
{
	show_msg(MSGDEBUG, "getsockname: s:%d\n", s);
	return realgetsockname(s, name, namelen);
}

char* eventstrs(DWORD cEvents, const WSAEVENT *lphEvents) 
{
	char buffer[256];
	int i, len;
	buffer[0] = '\0';
	for (i=0; i<cEvents; i++) {
		len = strlen(buffer);
		sprintf(&buffer[len], "%#x|\n", lphEvents[i]);
	}

	len = strlen(buffer);
	if (len > 2) 
		buffer[len-1] = '\0';
	return strdup(buffer);
}


char* event2str(u_long argp) 
{
	char buffer[256];
	memset(buffer, 0, sizeof(buffer));
	if (FD_READ & argp)
		strcat(buffer, "FD_READ | ");
	if (FD_WRITE & argp)
		strcat(buffer, "FD_WRITE | ");
	if (FD_OOB & argp)
		strcat(buffer, "FD_OOB | ");
	if (FD_ACCEPT & argp)
		strcat(buffer, "FD_ACCEPT | ");
	if (FD_CONNECT & argp)
		strcat(buffer, "FD_CONNECT | ");
	if (FD_CLOSE & argp)
		strcat(buffer, "FD_CLOSE | ");
	if (FD_QOS & argp)
		strcat(buffer, "FD_QOS | ");
	if (FD_GROUP_QOS & argp)
		strcat(buffer, "FD_GROUP_QOS | ");
	if (FD_ROUTING_INTERFACE_CHANGE & argp)
		strcat(buffer, "FD_ROUTING_INTERFACE_CHANGE | ");
	if (FD_ADDRESS_LIST_CHANGE & argp)
		strcat(buffer, "FD_ADDRESS_LIST_CHANGE | ");

	int len = strlen(buffer);
	if (len > 2)
		buffer[len-2] = '\0';
	return strdup(buffer);
}

typedef struct _hooked_win
{
	HWND hWnd;
	WNDPROC	ori_winproc;
	struct _hooked_win* next;
} hooked_win;

hooked_win* win_item_chain = NULL;
const char* win_item_cs = "win_item_cs";


hooked_win* new_hooked_window(HWND hWnd)
{
	hooked_win* hw = (hooked_win*)malloc(sizeof(hooked_win));
	hw->hWnd = hWnd;
	hw->ori_winproc = (WNDPROC)GetWindowLong(hWnd,GWL_WNDPROC);
	hw->next = NULL;
	return (hw);
}

hooked_win* find_hooked_window(HWND h)
{
	if (win_item_chain == NULL)
	{
		return (NULL);
	}

	hooked_win* scan = win_item_chain;

	for(; scan; scan=scan->next)
	{
		if (scan->hWnd == h)
		{
			return (scan);
		}
	}
	return (NULL);
}

hooked_win* add_hooked_window(HWND hWnd)
{
	if (win_item_chain == NULL)
	{
		win_item_chain = new_hooked_window(hWnd);
		return (win_item_chain);
	}

	hooked_win* found = find_hooked_window(hWnd);

	if (found)
	{
		return (found);
	}

	hooked_win* new_item = new_hooked_window(hWnd);

	enter_cs(win_item_cs);
	new_item->next = win_item_chain;
	win_item_chain = new_item;
	leave_cs(win_item_cs);

	return (win_item_chain);
}


LRESULT CALLBACK WindowProc_Mine(HWND hWnd,UINT uMsg,WPARAM wParam,LPARAM lParam) 
{ 
	struct connreq *conn;
	SOCKET s = (SOCKET)wParam;
	hooked_win* item = find_hooked_window(hWnd);

	if (item == NULL) 
	{
		return DefWindowProc(hWnd,uMsg,wParam,lParam); 
	}

	do
	{
		if (uMsg == WM_CLOSE)
		{
			show_msg(MSGDEBUG, "window(%d) got WM_CLOSE message\n", hWnd);
		}

		if (uMsg == WM_DESTROY)
		{
			show_msg(MSGDEBUG, "window(%d) got WM_DESTROY message\n", hWnd);
			//SetWindowLong(hWnd, GWL_WNDPROC, (long)item->ori_winproc);
			//removehook();
		}

		if (uMsg == WM_QUIT)
		{
			show_msg(MSGDEBUG, "window(%d) got WM_QUIT message\n", hWnd);
		}

		if (uMsg < WM_USER)
		{
			break;
		}

		if (WSAGETSELECTERROR(lParam)) 
		{ 
			break;
		} 

		if ((conn = find_socks_request(s, 1)) == NULL)
		{
			break;
		}
		
		WORD wEvent = WSAGETSELECTEVENT(lParam);

		char* printstr = event2str(wEvent);
		show_msg(MSGNOTICE, "WindowProc_Mine begin: socket(%d) in state:%s\n", s, printstr);
		free(printstr);

		if (conn->master_bypass)
		{
			break;
		}

		int handle = 0;
		int rc;

		switch (wEvent)
		{
			case FD_CONNECT:
				conn->state = CONNECTED;
				return (0);
			case FD_READ:
				realwsaasyncselect(s, hWnd, uMsg, 0);
				rc = handle_request(conn);
				handle = 1;
				break;
			case FD_WRITE:
				realwsaasyncselect(s, hWnd, uMsg, 0);
				rc = handle_request(conn);
				handle = 1;
				break;
			case FD_CLOSE:
				break;
			default:
				break;
		}

		if (handle == 0)
		{
			break;
		}

		long new_event = ((rc == WSAEWOULDBLOCK) && (conn->state == RECEIVING))? FD_READ | FD_CLOSE : FD_WRITE | FD_CLOSE;
		realwsaasyncselect(s, hWnd, uMsg, new_event);

		if (conn->state == DONE) 
		{
			conn->master_bypass = 1;
			conn->donetime = GetTickCount();
			lParam = FD_CONNECT;
			realwsaasyncselect(s, hWnd, uMsg, FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE);
			show_msg(MSGNOTICE, "async_select DONE: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );

			SetEvent(socks_finish_event);
			break;
		}

		if (conn->state == FAILURED) 
		{
			conn->master_bypass = 1;
			conn->donetime = GetTickCount();
			lParam = FD_CLOSE;
			realwsaasyncselect(s, hWnd, uMsg, FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE);
			show_msg(MSGNOTICE, "async_select FAILURED: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );

			SetEvent(socks_finish_event);
			break;
		}

		return (0);

	} while(0);

	return CallWindowProc(item->ori_winproc, hWnd, uMsg, wParam, lParam);
}

int PASCAL hook_WSAAsyncSelect(SOCKET s, HWND hWnd, u_int wMsg, long lEvent) 
{
	char* printstr = event2str(lEvent);
	show_msg(MSGDEBUG, "WSAAsyncSelect: %d HWND:%d, u_int:%d, lEvent:%d(%s)\n", s, hWnd, wMsg, lEvent, printstr);
	free(printstr);

	//一个新的连接，还没connect的，就需要打上窗口过程hook
	hooked_win* win_item = find_hooked_window(hWnd);
	if (win_item == NULL)
	{
		win_item = add_hooked_window(hWnd);
		SetWindowLong(hWnd, GWL_WNDPROC, (long)WindowProc_Mine);
	}
	
	return realwsaasyncselect(s, hWnd, wMsg, lEvent);
}

int hook_WSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents)
{
	struct connreq *conn;
	if (conn = find_socks_request(s, 1)) 
	{
		//找到后，关联一下就可以了
		conn->hWsaEvent = hEventObject;
		if ((conn->tid) && (!(conn->master_bypass))) 
		{
			char* printstr = event2str(lNetworkEvents);
			show_msg(MSGDEBUG, "WSAEventSelect filter: s=%d hEvent=%#x NetEvent=%s\n", s, hEventObject, printstr);
			free(printstr);
			return 0;
		}
	}

	return realwsaeventselect(s, hEventObject, lNetworkEvents);
}


DWORD WINAPI hook_WaitForMultipleObjectsEx (DWORD cEvents, HANDLE *lphEvents, BOOL fWaitAll, DWORD dwTimeout, BOOL fAlertable)
{
	if (!requests)
		return realwaitformultipleobjectsex(cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable);

	struct connreq *conn, *nextconn;
	int i;
	HANDLE *lphMyEvents = NULL;
	HANDLE henum;

	for (i=0; i<cEvents; i++) 
	{
		if (conn = find_socks_request_event(lphEvents[i], 1)) 
		{
			if ((conn->tid) && (!(conn->master_bypass))) 
			{
				if (lphMyEvents == NULL) 
				{
					lphMyEvents = malloc(cEvents * (sizeof(HANDLE)+1));
					memcpy(lphMyEvents, lphEvents, cEvents * sizeof(HANDLE));
					lphMyEvents[cEvents] = NULL;
				}

				if (conn->hWsaEvent_Fake == NULL)
				{
					conn->hWsaEvent_Fake = WSACreateEvent();
				}
				lphMyEvents[i] = conn->hWsaEvent_Fake;
				WSAResetEvent(conn->hWsaEvent_Fake);
			}
		}
	}

	if (lphMyEvents) 
	{
		DWORD runret = realwaitformultipleobjectsex(cEvents, lphMyEvents, fWaitAll, dwTimeout, fAlertable);
		free(lphMyEvents);
		return runret;
	} 
	else 
	{
		return realwaitformultipleobjectsex(cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable);
	}
}

int is_connect_event(long lNetworkEvents)
{
	if ((lNetworkEvents & FD_WRITE) && (lNetworkEvents & FD_CONNECT))
		return 1;
	return 0;
}

void select_wait(long sec, long usec)
{
	struct timeval tv;
	tv.tv_sec = sec;
	tv.tv_usec = usec;
	realselect(0,NULL,NULL,NULL,&tv);
}

DWORD WINAPI socks_thread_enumevents(struct connreq *conn)
{
	assert(conn);
	assert(conn->state == CONNECTING);

	show_msg(MSGDEBUG, "enum_thread: enter socks_thread_enumevents. %s\n", state2str(conn->state));

	conn->state = CONNECTED;
	SetEvent(conn->threadevent);

	int subindex, rc, selectrc, enumrc;
	long netevents;
	long errorcount = 0, timeouts = 0;
	struct timeval tv;

	rc = handle_request(conn);
	do 
	{
		if (errorcount > 9)
		{
			conn->state = FAILURED;
			conn->donetime = GetTickCount();
			show_msg(MSGNOTICE, "enum_thread errorcount FAILURED: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
			break;
		}

		if (timeouts > 3)
		{
			conn->state = FAILURED;
			conn->donetime = GetTickCount();
			show_msg(MSGNOTICE, "enum_thread timeout FAILURED: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
			break;
		}

	
		if (conn->state == DONE) 
		{
			conn->donetime = GetTickCount();
			show_msg(MSGNOTICE, "enum_thread DONE: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
			break;
		}

		if (conn->state == FAILURED) 
		{
			conn->donetime = GetTickCount();
			show_msg(MSGNOTICE, "enum_thread FAILURED: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
			break;
		}

		if (rc == WSAEWOULDBLOCK) 
		{
			netevents = 0;
			netevents |= (conn->state == RECEIVING) ? FD_READ : 0;
			netevents |= (conn->state == SENDING) ? FD_WRITE : 0;
			netevents |= FD_CLOSE;

			selectrc = realwsaeventselect(conn->sockid, conn->hWsaEvent, netevents);
			if (selectrc == SOCKET_ERROR) 
			{
				show_msg(MSGDEBUG, "enum_thread: error WsaEventSelect() - %s\n", gai_strerror(WSAGetLastError()));
				select_wait(0, 50*1000);
				errorcount++;
				continue;
			}

			subindex = realwaitformultipleobjectsex(1, &conn->hWsaEvent, TRUE, 3000, FALSE);

			if (subindex == WSA_WAIT_TIMEOUT) 
			{
				timeouts++;
				continue;
			}

			timeouts = 0;

			if (subindex == WSA_WAIT_FAILED) 
			{
				conn->donetime = GetTickCount();
				show_msg(MSGNOTICE, "enum_thread WSA_WAIT_FAILED: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
				break;
			}

			WSANETWORKEVENTS event;
			enumrc = realwsaenumnetworkevents(conn->sockid, conn->hWsaEvent, &event);
			if (enumrc == SOCKET_ERROR) 
			{
				show_msg(MSGDEBUG, "enum_thread: error WsaEnumNetworkEvents() - %s\n", gai_strerror(WSAGetLastError()));
				select_wait(0, 50*1000);
				errorcount++;
				continue;
			}

			if ((event.lNetworkEvents & FD_WRITE) || (event.lNetworkEvents & FD_READ)) 
			{
				rc = handle_request(conn);
				continue;
			}

			if (event.lNetworkEvents & FD_CLOSE) 
			{
				conn->donetime = GetTickCount();
				show_msg(MSGNOTICE, "enum_thread FD_CLOSE: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
				break;
			}
		}		

		break;
	} while (TRUE);

	show_msg(MSGDEBUG, "enum_thread: finished. %s, errno:%s\n", state2str(conn->state), gai_strerror(WSAGetLastError()));
	conn->waitup = 1;

	SetEvent(socks_finish_event);
	return (conn->state == DONE);
}

int hook_WSAEnumNetworkEvents(SOCKET s, WSAEVENT hEventObject, LPWSANETWORKEVENTS lpNetworkEvents) 
{
	//从我们的连接表对照，找出对应的数据
	int ret = 0;
	struct connreq *conn = find_socks_request(s, 1);

	//不是连接列表中的，就忽略
	if (!conn)
	{
		return realwsaenumnetworkevents(s, hEventObject, lpNetworkEvents);
	}

	//已经成功处理了的，退出
	conn->hWsaEvent = hEventObject;
	if (conn->master_bypass)
	{
		return realwsaenumnetworkevents(s, hEventObject, lpNetworkEvents);
	}

	do 
	{
		if (conn->tid) break;

		ret = realwsaenumnetworkevents(s, hEventObject, lpNetworkEvents);

		if (SOCKET_ERROR == ret) 
		{
			show_msg(MSGDEBUG, "WSAEnumNetworkEvents ERROR: s=%d hEvent=%#x err=%s\n", s, hEventObject, WSAGetLastError());
			return ret;
		}
	} while (FALSE);
	

	//如果是连接完成通知，需手动设置标记，再执行socks逻辑
	if (conn->state == CONNECTING) 
	{
		if (is_connect_event(lpNetworkEvents->lNetworkEvents)) 
		{
			show_msg(MSGDEBUG, "WSAEnumNetworkEvents NEW: s=%d hEvent=%#x NetEvent=%s\n", s, hEventObject, event2str(lpNetworkEvents->lNetworkEvents));
			conn->threadevent = CreateEvent(NULL, FALSE, FALSE, NULL);
			CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&socks_thread_enumevents, conn, 0, &conn->tid));
			WaitForSingleObject(conn->threadevent, INFINITE);
			CloseHandle(conn->threadevent);
		}
		memset(lpNetworkEvents, 0, sizeof(WSANETWORKEVENTS));
		return 0;
	}

	//socks流程走完，通知宿主可以写入数据了。
	if (conn->state == DONE) 
	{
		lpNetworkEvents->lNetworkEvents = 0;
		lpNetworkEvents->lNetworkEvents |= FD_WRITE;
		lpNetworkEvents->lNetworkEvents |= FD_CONNECT;
		conn->donetime = GetTickCount();
		conn->master_bypass = 1;
		show_msg(MSGNOTICE, "WSAEnumNetworkEvents DONE: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
		WSAResetEvent(hEventObject);
		return 0;
	}

	//发生错误了，通知宿主关闭连接。
	if (conn->state == FAILURED) 
	{
		lpNetworkEvents->lNetworkEvents = 0;
		lpNetworkEvents->lNetworkEvents |= FD_CLOSE;
		conn->donetime = GetTickCount();
		show_msg(MSGNOTICE, "WSAEnumNetworkEvents FAILURED: socket(%d) use time: ---------> %d\n", conn->sockid, conn->donetime - conn->starttime );
		conn->master_bypass = 1;
		WSAResetEvent(hEventObject);
		return 0;
	}

	//当什么事都没有发生。
	memset(lpNetworkEvents, 0, sizeof(WSANETWORKEVENTS));
	WSAResetEvent(hEventObject);
	return 0;

}

int PASCAL hook_setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen) 
{
	show_msg(MSGDEBUG, "setsockopt: %d level:%d optname:%d\n", s, level, optname);
	return realsetsockopt(s, level, optname, optval, optlen);
}


int PASCAL hook_connect_raw(LPFN_CONNECT raw_connect, SOCKET s, const struct sockaddr *name, int namelen)
{
	struct sockaddr_in *connaddr;
	struct sockaddr_in peer_address;
	struct sockaddr_in server_address;
	int gotvalidserver = 0, rc, peernamelen = sizeof(peer_address);
	int sock_type = -1;
	int sock_type_len = sizeof(sock_type);
	unsigned int res = -1;
	struct serverent *path;
	struct connreq *newconn;

	//如果原始connect入口不存在，则退出。我们的hook出问题了。
	if (raw_connect == NULL) 
	{
		show_msg(MSGERR, "Unresolved symbol: connect\n");
		return(-1);
	}

	show_msg(MSGDEBUG, "connect: Got connection request: %d\n", s);

	//检查这个socket的类型
	getsockopt(s, SOL_SOCKET, SO_TYPE, (void *) &sock_type, &sock_type_len);

	//如果这不是一个TCP socket，立即放行。UDP咱们不管。
	connaddr = (struct sockaddr_in *) name;
   	if ((connaddr->sin_family != AF_INET) || (sock_type != SOCK_STREAM)) 
	{
	      	show_msg(MSGDEBUG, "Connection isn't a TCP stream ignoring\n");
		return(raw_connect(s, name, namelen));
   	}

	//看看这个socket我们是否已经曾经处理过？
 	if ((newconn = find_socks_request(s, 1))) 
	{
		if (memcmp(&newconn->connaddr, connaddr, sizeof(*connaddr))) 
		{
			//我们曾经处理过这个socket，但是宿主却又再次connect相同的地址？显然我们保存的旧socket已经无用,须清理。
			show_msg(MSGDEBUG, "Call to connect received on old tsocks request for socket %d but to "
					    "new destination, deleting old request\n", newconn->sockid);
			kill_socks_request(newconn);
		}
		else 
		{
			//这是一个对非阻塞式connect的状态检查,如果无异常则放行。
			if (newconn->state == FAILURED) 
			{
			    show_msg(MSGDEBUG, "Call to connect received on failed request %d, returning %d\n", newconn->sockid, newconn->err);
			    WSASetLastError(newconn->err);
			    rc = -1;
			} 
			else if (newconn->state == DONE) 
			{
			    show_msg(MSGERR, "Call to connect received on completed request %d\n", newconn->sockid, newconn->err);
			    rc = 0;
			} 
			else 
			{
			    show_msg(MSGDEBUG, "Call to connect received on current request %d\n", newconn->sockid);
			    rc = handle_request(newconn);
			    WSASetLastError(rc);
			}

			if ((newconn->state == FAILURED) || (newconn->state == DONE))
			{
				kill_socks_request(newconn);
			}

			return((rc ? -1 : 0));
		}
   	}

	//不在我们的列表中，却是使用中的socket。这个socket我们管不着，直接放行。
	if (!realgetpeername(s, (struct sockaddr *) &peer_address, &peernamelen)) 
	{
		show_msg(MSGDEBUG, "Socket is already connected, defering to real connect\n");
		return(raw_connect(s, name, namelen));
	}
      
	int ncount = conn_list_count(0);
	int allcount = conn_list_count(1);
	char* addstr = inet_ntoa(connaddr->sin_addr);
	show_msg(MSGNOTICE, "New for socket %d to %s (%d|%d)\n", s, addstr, ncount, allcount);

	//如果目标地址是“本地”的，不需要socks代理，直接放行。
	if (!(is_local(config, &(connaddr->sin_addr)))) 
	{
		show_msg(MSGDEBUG, "Connection for socket %d is local\n", s);
		return(raw_connect(s, name, namelen));
	}

	//用户选择了“忽略所有socks服务器”。
	if (selected_index == -2)
	{
		show_msg(MSGDEBUG, "user ignore all socket %d\n", s);
		return(raw_connect(s, name, namelen));
	}

	//接下来需要连接socks服务器，先选择一个
	pick_server(config, &path, &(connaddr->sin_addr), ntohs(connaddr->sin_port), selected_index);

	show_msg(MSGDEBUG, "Picked(%d) server %s for connection\n", selected_index, (path->address ? path->address : "(Not Provided)"));
	if (path->address == NULL) 
	{
		if (path == &(config->defaultserver)) 
		 	show_msg(MSGERR, "Connection needs to be made via default server but "
				  "the default server has not been specified\n");
		else 
			show_msg(MSGERR, "Connection needs to be made via path specified at line "
				  "%d in configuration file but the server has not been specified for this path\n",
			path->lineno);
	} 
	else if ((res = resolve_ip(path->address, 1, HOSTNAMES)) == -1) 
	{
		show_msg(MSGERR, "The SOCKS server (%s) listed in the configuration "
                       "file which needs to be used for this connection "
                       "is invalid\n", path->address);
	} 
	else 
	{	
		//构造socks服务器的addr结构
		server_address.sin_family = AF_INET; /* host byte order */
		server_address.sin_addr.s_addr = res;
		server_address.sin_port = htons(path->port);
		bzero(&(server_address.sin_zero), 8);

		//检查该socks服务器是否在本地网络上，做一个标记。
		if (is_local(config, &server_address.sin_addr)) 
		{
			show_msg(MSGERR, "SOCKS server %s (%s) is not on a local subnet!\n", 
			path->address, inet_ntoa(server_address.sin_addr));
		} 
		else 
		{
			gotvalidserver = 1;
		}
   	}

	//如果我们未能成功选到socks服务器，或者无法创建新对象，则退出。
	if (!gotvalidserver || !(newconn = new_socks_request(s, connaddr, &server_address, path))) 
	{
	      WSASetLastError(WSAECONNREFUSED);
	      return(-1);
	}

	//现在我们可以开始处理socks逻辑了
	newconn->spec_connect = raw_connect;
	rc = handle_request(newconn);

	//根据返回结果，我们会忽略一些socket：FAILURED的，
	if (newconn->state == FAILURED)
	{
		kill_socks_request(newconn);
	}

	//立即DONE的，不用后续跟踪了，可以放任不管
	if (newconn->state == DONE) 
	{
		newconn->donetime = GetTickCount();
		show_msg(MSGNOTICE, "connect instance DONE: socket(%d) use time: ---------> %d\n", newconn->sockid, newconn->donetime - newconn->starttime );
		kill_socks_request(newconn);
	}

	WSASetLastError(rc);
	return((rc ? -1 : 0));
}

int PASCAL hook_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
	return hook_connect_raw(realconnect, s, name, namelen);
}

int PASCAL wsa_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
	return realwsaconnect(s, name, namelen, NULL, NULL, NULL, NULL);
}


const char* wsa_connect_cs = "wsa_connect_cs";

int PASCAL hook_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
{
	show_msg(MSGNOTICE, "WSAConnect: %d, %p, %d, %p, %p, %p, %p\n", s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);

	enter_cs(wsa_connect_cs);
	int result = hook_connect_raw(wsa_connect, s, name, namelen);
	leave_cs(wsa_connect_cs);

	return (result);
}


HMODULE hCodeTrick;
typedef HMODULE (*LPFN_Hook_InlineHookInstall)(void* fnHookFrom, void* fnHookTo);
typedef void*   (*LPFN_Hook_InlineHookGetOri)(HMODULE hHooker);
typedef void    (*LPFN_Hook_InlineHookRemove)(HMODULE hHooker);
LPFN_Hook_InlineHookInstall Hook_InlineHookInstall;
LPFN_Hook_InlineHookGetOri Hook_InlineHookGetOri;
LPFN_Hook_InlineHookRemove Hook_InlineHookRemove;

int load_codetrick_dll() 
{
	if (hCodeTrick == 0) 
	{
		hCodeTrick = LoadLibrary("CodeTrick.dll");
		if (hCodeTrick) 
		{
			Hook_InlineHookInstall = (LPFN_Hook_InlineHookInstall)GetProcAddress(hCodeTrick, "Hook_InlineHookInstall");
			Hook_InlineHookGetOri = (LPFN_Hook_InlineHookGetOri)GetProcAddress(hCodeTrick, "Hook_InlineHookGetOri");
			Hook_InlineHookRemove = (LPFN_Hook_InlineHookRemove)GetProcAddress(hCodeTrick, "Hook_InlineHookRemove");
			return (1);
		}
	}
	return (0);
}

HMODULE hSocksUi;
typedef int (*lpfn_download_file_withui)(wchar_t *, wchar_t *, wchar_t *, wchar_t *);
typedef int (*lpfn_select_socks_server)(int , char **);
lpfn_download_file_withui download_file_withui;
lpfn_select_socks_server select_socks_server;

int load_socksui_dll()
{
	if (hSocksUi == 0) 
	{
		hSocksUi = LoadLibrary("socksui.dll");
		if (hSocksUi) 
		{
			download_file_withui = (lpfn_download_file_withui)GetProcAddress(hSocksUi, "download_file_withui");
			select_socks_server = (lpfn_select_socks_server)GetProcAddress(hSocksUi, "select_socks_server");
			return (1);
		}
	}
	return (0);
}

HMODULE hWinsock, hKernel32;

void* HookWinsock(char *name, HMODULE *hHook, void *fHooker) 
{
	if (!hWinsock) 
	{
		hWinsock = LoadLibrary("ws2_32.dll");
		if (!hWinsock) 
		{
			show_msg(MSGERR, "can't load ws2_32.dll\n");
			return NULL;
		}
	}

	*hHook = Hook_InlineHookInstall((void*)GetProcAddress(hWinsock, name), fHooker);

	if (*hHook) 
	{
		return Hook_InlineHookGetOri(*hHook);
	}
	
	show_msg(MSGERR, "Hook ERROR on: %s\n", name);
	return NULL;
}

void* HookKernel(char *name, HMODULE *hHook, void *fHooker) 
{
	if (!hKernel32) 
	{
		hKernel32 = LoadLibrary("kernel32.dll");
		if (!hKernel32) 
		{
			show_msg(MSGERR, "can't load kernel32.dll");
			return NULL;
		}
	}

	*hHook = Hook_InlineHookInstall((void*)GetProcAddress(hKernel32, name), fHooker);
	if (*hHook) 
	{
		return Hook_InlineHookGetOri(*hHook);
	}

	show_msg(MSGERR, "Hook ERROR on: %s\n", name);
	return NULL;
}

HMODULE hHookConnect, hHookWSAConnect, hHookclosesocket, hHookioctlsocket, hHookgetpeername, hHookgetsockname, hHookselect, hHookwsaasyncselect, hHookwsaeventselect, hHooksetsockopt, hHookWaitForMultipleObjectsEx, hHookwsaenumnetworkevents, hHookwsaioctl; 

#ifndef WSAID_CONNECTEX
#define WSAID_CONNECTEX {0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}}
#endif

BOOL PASCAL  hook_ConnectEx(
		SOCKET s,
		const struct sockaddr* name,
		int namelen,
		PVOID lpSendBuffer,
		DWORD dwSendDataLength,
		LPDWORD lpdwBytesSent,
		LPOVERLAPPED lpOverlapped
		)
{
	show_msg(MSGDEBUG, "enter %s", __FUNCTION__);
	return realconnectex(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
}

int WINAPI  hook_WSAIoctl(
		SOCKET s,
		DWORD dwIoControlCode,
		LPVOID lpvInBuffer,
		DWORD cbInBuffer,
		LPVOID lpvOutBuffer,
		DWORD cbOutBuffer,
		LPDWORD lpcbBytesReturned,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
		)
{
	int result = 0;
	GUID connectex = WSAID_CONNECTEX;
	show_msg(MSGDEBUG, "enter %s: %x", __FUNCTION__, dwIoControlCode);

	if ( dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER && cbInBuffer == 16 && memcmp(lpvInBuffer, (LPVOID)&connectex, sizeof(connectex)) == 0 )
	{
		result = realwsaioctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
		if (!result)
		{
			realconnectex = (LPFN_CONNECTEX)(*(DWORD*)lpvOutBuffer);
			*(DWORD *)lpvOutBuffer = (DWORD)hook_ConnectEx;
			show_msg(MSGDEBUG, "Setting new ConnectEx: %p -> %p", realconnectex, hook_ConnectEx);
			result = 0;
		}
	}
	else
	{
		result = realwsaioctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
	}

	return result;
}


int installhook() 
{
	show_msg(MSGNOTICE, "start install winsock hook\n");

	realconnect = (LPFN_CONNECT)HookWinsock("connect", &hHookConnect, (void*)hook_connect);
	realselect = (LPFN_SELECT) HookWinsock("select", &hHookselect, (void*)hook_select);
	realclosesocket = (LPFN_CLOSESOCKET) HookWinsock("closesocket", &hHookclosesocket, (void*)hook_closesocket);

	realwsaconnect = (LPFN_WSACONNECT)HookWinsock("WSAConnect", &hHookWSAConnect, (void*)hook_WSAConnect);
	realwsaasyncselect = (LPFN_WSAASYNCSELECT) HookWinsock("WSAAsyncSelect", &hHookwsaasyncselect, (void*)hook_WSAAsyncSelect);

	realioctlsocket = (LPFN_IOCTLSOCKET) HookWinsock("ioctlsocket", &hHookioctlsocket, (void*)hook_ioctlsocket);
	realgetpeername = (LPFN_GETPEERNAME) HookWinsock("getpeername", &hHookgetpeername, (void*)hook_getpeername);
	realgetsockname = (LPFN_GETSOCKNAME) HookWinsock("getsockname", &hHookgetsockname, (void*)hook_getsockname);
	realsetsockopt = (LPFN_SETSOCKOPT) HookWinsock("setsockopt", &hHooksetsockopt, (void*)hook_setsockopt);

	realwsaeventselect = (LPFN_WSAEVENTSELECT) HookWinsock("WSAEventSelect", &hHookwsaeventselect, (void*)hook_WSAEventSelect);
	realwaitformultipleobjectsex = (LPFN_WAITFORMULTIPLEOBJECTSEX) HookKernel("WaitForMultipleObjectsEx", &hHookWaitForMultipleObjectsEx, (void*)hook_WaitForMultipleObjectsEx);
	realwsaenumnetworkevents = (LPFN_WSAENUMNETWORKEVENTS) HookWinsock("WSAEnumNetworkEvents", &hHookwsaenumnetworkevents, (void*)hook_WSAEnumNetworkEvents);
	realwsaioctl = (LPFN_WSAIOCTL)HookWinsock("WSAIoctl", &hHookwsaioctl, (void*)hook_WSAIoctl);

	do {
		if (!realconnect) break;	
		if (!realwsaconnect) break;
		if (!realclosesocket) break;
		if (!realioctlsocket) break;
		if (!realgetpeername) break;
		if (!realgetsockname) break;
		if (!realselect) break;
		if (!realwsaasyncselect) break;
		if (!realsetsockopt) break;
		if (!realwaitformultipleobjectsex) break;
		if (!realwsaeventselect) break;
		if (!realwsaenumnetworkevents) break;
		show_msg(MSGERR, "installhook all done\n");
		return 1;
	} while (0);

	show_msg(MSGERR, "installhook error\n");
	return 0;
}

int removehook() 
{
        if (hCodeTrick) {
		removehook();
		Hook_InlineHookRemove(hHookConnect); 
		Hook_InlineHookRemove(hHookWSAConnect); 
		FreeLibrary(hWinsock);
		return 1;
        }
	show_msg(MSGERR, "removehook error\n");
	return 0;
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


static char* get_conf_file_name() 
{
	char *runret = NULL;

	do {
		/* Determine the location of the config file */
#ifdef ALLOW_ENV_CONFIG
		if (!suid) {
			runret = getenv("TSOCKS_CONF_FILE");
			show_msg(MSGDEBUG, "TSOCKS_CONF_FILE = %s\n", runret);
		}
#endif
		if (runret) {
			runret = strdup(runret);
			break;
		}

		runret = get_filename_bypath("sockshook", "xconf");
		if (runret) break;

		return runret;
	} while(0);

//	unsigned short wstr[128];
// 	gb2unicode(wstr, runret, strlen(runret));
//	free(runret);
//	runret = UnicodeToUTF8(wstr);

	return runret;
}


static int getset_conf_option () 
{
	conffile = get_conf_file_name();

	config = malloc(sizeof(*config));
	if (!config)
		return(0);

	read_config(conffile, config);

	if (config->paths)
		show_msg(MSGDEBUG, "First lineno for first path is %d\n", config->paths->lineno);

	return(1);
}

int get_random_num(int range)
{
	srand((int)time(0));
	return (int)(range*rand()/(RAND_MAX+1.0));
}

char* get_random_socks(int argc, char **argv)
{
	if (argc == 0) 
		return NULL;

	if (argc == 1)
		return argv[0];

	int index_url = get_random_num(argc);

	show_msg(MSGDEBUG, "random index=%d, argc=%d\n", index_url, argc);

	if (index_url >= argc)
		index_url = argc - 1;

	char *runret = argv[index_url];
	show_msg(MSGDEBUG, "random server is: %s\n", runret);
	
	return runret;	
}

/*
27.54.226.203:1080
27.54.226.203:1082
27.54.226.203:1084
27.54.226.203:1086
*/
int fill_servers_from_conf(char *conff, char ***argv)
{
	*argv = NULL;
	if (conff == NULL)
		return (0);

	struct parsedfile *parsed = malloc(sizeof(struct parsedfile));
	if (1 == read_config(conff, parsed)) 
		return (0); //读取配置文件有错，退出

	show_msg(MSGDEBUG, "start to list servers.\n");

	int runret = list_servers(parsed, argv);
	free_config(parsed);
	show_msg(MSGDEBUG, "finish free parsedfile(%d)\n", runret);
	return runret;
}

#define DEFAULT_CONF_URL "http://andpack.co.cc:8000/sockshook.xconf"

//27.54.226.203:1080 -> http://27.54.226.203:1081/sockshook.xconf
char *socks_server_to_confurl(char *socks_server, char *confname) 
{
	if (socks_server == NULL)
		return strdup(DEFAULT_CONF_URL);

	char *socks_server_bk = strdup(socks_server);

	char *strport = strchr(socks_server_bk, ':');
	if (strport == NULL) 
	{
		free(socks_server_bk);
		return strdup(DEFAULT_CONF_URL);
	}

	*strport = '\0';
	int port_num = atoi(++strport);

	show_msg(MSGDEBUG, "extract port num:: %s - %s(%d)\n", socks_server_bk, strport, port_num);

	char buff[128];
	sprintf(buff, "http://%s:%d/%s.xconf", socks_server_bk, ++port_num, confname);
	return strdup(buff);
}

int find_index_inarray(int argc, char **argv, char *tofind)
{
	if (tofind == NULL)
		return (-2);
	if (argc){
		int i;
		char *to_compare;
		for (i=argc-1; i<argc ; i++){
			to_compare = argv[i];
			if (0 == strcmp(tofind, to_compare)) {
				return (i);
			}
		}
	}
	return (-1);
}

void free_char_array(int argc, char **argv)
{
	if (argc)
	{
		int i;
		char *tofree;
		for (i=argc-1; i<argc ; i++)
		{
			tofree = argv[i];
			if (tofree)
			{
				free(tofree);
			}
		}
		free(argv);
	}
}


FILETIME get_modify_time(char *socksconf) 
{
	HANDLE hFile;
	OFSTRUCT ofStruct;
	FILETIME ftCreate,ftAccess,ftLastWrite;
	ftLastWrite.dwLowDateTime = 0;
	ftLastWrite.dwHighDateTime = 0;

	hFile = (HANDLE)OpenFile(socksconf, &ofStruct, OF_READ);	
	if (hFile == INVALID_HANDLE_VALUE)
		return ftLastWrite;

	GetFileTime(hFile, &ftCreate, &ftAccess, &ftLastWrite);

	CloseHandle(hFile);
	return ftLastWrite;
}

typedef struct 
{
	wchar_t* caption;
	wchar_t* cancel;
	wchar_t* from;
	wchar_t* tofile;
} download_param;

DWORD __stdcall download_thread_routine (void* p)
{
	download_param* param = (download_param*)p;
	show_msg(MSGDEBUG, "start call download_file_withui");
	return (DWORD)download_file_withui(param->caption, param->cancel, param->from, param->tofile);
}

DWORD download_file_withui_async(wchar_t* caption, wchar_t* cancel, wchar_t* from, wchar_t* tofile)
{
	DWORD tid;
	DWORD exit_code;
	download_param param;
	param.caption = caption;
	param.cancel = cancel;
	param.from = from;
	param.tofile = tofile;

	show_msg(MSGDEBUG, "start create thread for download");
	HANDLE download_thread = CreateThread(NULL, 0, download_thread_routine, &param, 0, &tid);
	
	if (download_thread == NULL)
	{
		show_msg(MSGDEBUG, "CreateThread error: %d", GetLastError());
		return (0);
	}

	if (WaitForSingleObject(download_thread, INFINITE) == WAIT_OBJECT_0)
	{
		if (GetExitCodeThread(download_thread, &exit_code))
		{
			return (exit_code);
		}
	}

	show_msg(MSGDEBUG, "thread run error: %d", GetLastError());
	return (0);
}

int get_socks_selected_result()
{
	//获取本地配置文件的名字
	//如果存在，则读出来
	char *socksconf = get_conf_file_name();
	assert(socksconf);

	char **filelist = NULL;
	int argc = fill_servers_from_conf(socksconf, &filelist);

	show_msg(MSGDEBUG, "first read conf finish.argc=%d(%s)\n", argc, socksconf);

	//随机选出配置文件中的服务器，得出更新配置文件的url
	//不过本地没有配置文件，则采用默认值
	char *conf_url = NULL;
	if (argc) 
	{
		char *random_server = get_random_socks(argc, filelist);
		show_msg(MSGDEBUG, "random socks server : %s\n", random_server);

		conf_url = socks_server_to_confurl(random_server, "sockshook");
		show_msg(MSGDEBUG, "random select %s\n", conf_url);

		if (conf_url == NULL)
		{
			conf_url = strdup(DEFAULT_CONF_URL);
			show_msg(MSGDEBUG, "has to uses default.(%s)\n", conf_url);
		}
	}
	else 
	{
		conf_url = strdup(DEFAULT_CONF_URL);
		show_msg(MSGDEBUG, "argc=0, has to uses default.(%s)\n", conf_url);
	}

	assert(conf_url);
	assert(download_file_withui);
	assert(select_socks_server);

	//下载新的配置文件
	wchar_t *localfile = m2w(socksconf);
	wchar_t *remoteconf = m2w(conf_url);
	FILETIME oldtime = get_modify_time(socksconf);
	//调用外部ui
	download_file_withui(L"下载配置文件", L"中止", remoteconf, localfile);
	//检查修改时间
	FILETIME newtime = get_modify_time(socksconf);
	if (CompareFileTime(&newtime, &oldtime) == 1)
		show_msg(MSGDEBUG, "update succeed %s\n", conf_url);


	//从新获取一次服务器列表
	show_msg(MSGDEBUG, "re read conf file.\n");
	char **filelist2 = NULL;
	char *selected_srv = NULL;
	int argc2 = fill_servers_from_conf(socksconf, &filelist2);


	//修正用户选择后的返回值
	if (argc2) 
	{
		selected_index = select_socks_server(argc2, filelist2);
		//这时候，select_index的取值有3类：
		//（1）：>=0，用户选择了列表中的服务器
		//（2）：-1，用户没有选择任何的服务器
		//（3）：-2，用户想忽略所有socks服务器
		//（4）：-3，用户想关闭进程
		switch (selected_index) 
		{
			case -1:
				selected_index = get_random_num(argc2);
				selected_srv = filelist2[selected_index];
				show_msg(MSGDEBUG, "help user select: %s(%d)\n", selected_srv, selected_index);
				break;
			case -2:
				selected_srv = NULL;
				show_msg(MSGDEBUG, "user didn't select, or xconf file error: %s(%d)\n", selected_srv, selected_index);
				break;
			case -3:
				ExitProcess(0);
			default:
				if (selected_index >= 0)
				{
					selected_srv = filelist2[selected_index];
					show_msg(MSGDEBUG, "user selected: %s(%d)\n", selected_srv, selected_index);
				} else {
					selected_index = get_random_num(argc2);
					selected_srv = filelist2[selected_index];
					show_msg(MSGDEBUG, "exception select: %s(%d)\n", selected_srv, selected_index);
				}
		}
	}
	else
	{
		selected_srv = NULL;
		show_msg(MSGDEBUG, "exception with no server for selected: %s(%d -> -2)\n", selected_srv, selected_index);
		selected_index = -2;
	}


	//清理资源
	free_char_array(argc2, filelist2);
	free_char_array(argc, filelist);
	free(socksconf);
	free(conf_url);

	return (selected_index);
}

BOOL WINAPI DllMain (HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
	switch(fdwReason) 
	{ 
		case DLL_PROCESS_ATTACH: 
			OutputDebugStringA("sockshook.dll started");

			load_codetrick_dll();
			load_socksui_dll();

			const char* share_type = "sockshook.dll";
			const char* share_key = "last_choice_tick";
			const char* share_key_choice = "last_choice_value";
			const char* pop_interval = "pop_window_interval";

			DWORD interval_tick = (DWORD)get_param_valint(pop_interval, 180000);
			DWORD last_tick = (DWORD)get_share_valint(share_type, share_key, 0);
			DWORD now_tick = GetTickCount();

			if ((now_tick - last_tick) > interval_tick)
			{
				get_socks_selected_result();
				set_share_valint(share_type, share_key, (long)now_tick);
				set_share_valint(share_type, share_key_choice, (long)selected_index);
			}
			else
			{
				selected_index = get_share_valint(share_type, share_key_choice, -2);
			}

			/*
			不用安装hook:
			1)如果用户想忽略socks服务器，
			2)本地目录没有访问权限，无法写入配置文件
			3)被注射进64bit程序中
			*/
			if (selected_index == -2)
			{
				show_msg(MSGDEBUG, "disable all hooks\n");
				OutputDebugStringA("user ignor socks");
			}
			else
			{
				getset_conf_option();
				installhook();
			}

			break;

		case DLL_PROCESS_DETACH: 
			removehook();
			break;
	}
	SetLastError(0);
	return (TRUE);
}
