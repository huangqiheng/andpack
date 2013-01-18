#ifndef __LOG_CLIENT_H_ONCE
#define __LOG_CLIENT_H_ONCE

#define MSGNONE   -1
#define MSGERR    0
#define MSGWARN   1
#define MSGNOTICE 2
#define MSGDEBUG  3

void logmsg(int level, const char *fmt, ...);
void log_hex(int level, char* title, void *p, int len);
void log_hex_block(int level, char* title, char* membase, long memsize);


#endif
