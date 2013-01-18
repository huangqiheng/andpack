/******************************************************************************
 * $Id: win32_compatibility.c,v 1.4 2008/06/04 22:58:37 gareuselesinge Exp $
 * This file is part of liberopops (http://liberopops.sf.net)                 *
 * This file is distributed under the terms of GNU GPL license.               *
 ******************************************************************************/

/******************************************************************************
 * File description:
 *    simple implementation of some functions not implemented in the win32
 *    environment
 * Notes:
 *    origilly taken from www.mattdm.org/icebreaker/
 * Authors:
 *    Enrico Tassi <gareuselesinge@users.sourceforge.net> 
 ******************************************************************************/

#if defined(WIN32) && !defined(CYGWIN)

#include <stdio.h>
#include <stdarg.h> 
#include <windows.h>
#include <lmcons.h>

#include "win32_compatibility.h"

/* This is the structure that getpwuid returns. fix -- how to get username
   in winNT, etc? */
struct passwd pwdwin32_standard={NULL,"*",1,1,"Win32 User",".","command.com"};

struct passwd *getpwuid(int id)
{
      static CHAR name[UNLEN + 1]="Nobody";
      DWORD width=UNLEN + 1;
      int i;

      GetUserName(name,&width);
      for (i=0;i<50 && name[i]!='\0';i++)
      {
            if (name[i]==' ')
            {
                  name[i]='\0';
                  break;
            }
      }
      
      pwdwin32_standard.pw_name = name;

      return &pwdwin32_standard;
}

#ifndef bzero
void bzero(void* s, size_t n)
{
char* _s = (char*)s;
int i;
for(i=0;i<n;i++) _s[i]='\0';
}
#endif

#ifndef index
char* index(const char * s, int i)
{
char* r=(char *)s;
while(*r != '\0')
      {
      if( *r == i)
            return r;

      r++;
      }
return NULL;
}
#endif

int inet_aton_w32(const char *cp, struct in_addr *inp){
inp->s_addr = inet_addr(cp);
return inp->s_addr != -1;
}


#endif
