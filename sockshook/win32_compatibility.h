/******************************************************************************
 * $Id: win32_compatibility.h,v 1.4 2008/06/04 22:58:37 gareuselesinge Exp $
 * This file is part of liberopops (http://liberopops.sf.net)                 *
 * This file is distributed under the terms of GNU GPL license.               *
 ******************************************************************************/


/******************************************************************************/
 /*!
  * \file   win32_compatibility.h
  * \brief  simple implementation of some functions not implemented in win32
  * origilly taken from www.mattdm.org/icebreaker/
  * \author Enrico Tassi <gareuselesinge@users.sourceforge.net>
  * \author Matthew Miller
  */
/******************************************************************************/


#ifndef WIN32_COMPATIBILITY_H
#define WIN32_COMPATIBILITY_H

#if defined(WIN32) && !defined(CYGWIN)

#include <stdio.h>
#include <windows.h>

/** @name Mingw32 missing types */
//@{
#define uid_t int
#define gid_t int

//! the structure that contains user infos
struct passwd{
              char    *pw_name;       /* user name */
              char    *pw_passwd;     /* user password */
              uid_t   pw_uid;         /* user id */
              gid_t   pw_gid;         /* group id */
              char    *pw_gecos;      /* real name */
              char    *pw_dir;        /* home directory */
              char    *pw_shell;      /* shell program */
      };
//@}

/** @name Mingw32 missing functions */
//@{
#define getuid() 1000
#define geteuid() 1000
extern struct passwd *getpwuid(int id);

#ifndef bzero
extern void bzero(void* s, size_t n);
#endif

#ifndef index
char* index(const char * s, int i);
#endif

#define usleep(s) Sleep(s)
//@}



int win_snprintf(const char* c,...);
int win_vsnprintf(const char *format, va_list ap);
#define snprintf(a,b,c...) (__extension__             \
                  ({                            \
                  int __result;                       \
                  if ( a == NULL && b == 0)           \
                        __result = c99_snprintf(c);   \
                  else                          \
                        __result = snprintf(a,b,c);   \
                  __result; }))

#define vsnprintf(a,b,c,d) (__extension__             \
                  ({                            \
                  int __result;                       \
                  if ( a == NULL && b == 0)           \
                        __result = c99_vsnprintf(c,d);\
                  else                          \
                        __result = vsnprintf(a,b,c,d);      \
                  __result; }))

#define inet_aton(a,b) inet_aton_w32(a,b)
int inet_aton_w32(const char *cp, struct in_addr *inp);

#endif

#endif
