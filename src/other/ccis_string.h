#ifndef __CCIS_STRING_H__
#define __CCIS_STRING_H__

#include <string.h>

extern int Analyze_Info(char* source_str , char** result , int item_num , char* delim);

/********
Note : 
strsplit_xxx functions modifies its first argument , so it cannot be used on constant strings.
BE CAUTIOUS when using these functions !
********/
extern char*	strsplit_before(char **stringp , const char* delim);
extern char*	strsplit_after(char **stringp , const char* delim);

extern int	String_Replace(char* string , char ch_sou , char ch_des , int pos_start , int pos_end);

extern int	String_Delete_Char(char* string , char ch , int pos_start , int pos_end);

#endif
