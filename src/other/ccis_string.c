#include "ccis_string.h"
#include "../log/ccis_log.h"
#include "stdio.h"
#include "unistd.h"
#include "stdlib.h"

char*	strsplit_before(char **stringp , const char* delim);
char*	strsplit_after(char** stringp , const char* delim);
int	Analyze_Info(char* source , char** result , int item_num , char* delim);
int	String_Replace(char* string , char ch_sou , char ch_des , int pos_start , int pos_end);
int	String_Delete_Char(char* string , char ch , int pos_start , int pos_end);


char* strsplit_before(char **stringp , const char* delim)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	char *s;
	const char* spanp;
	int c , sc;
	char *tok;
	if ((s = *stringp) == NULL)
		return NULL;
	for (tok = s ; ; )
	{
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp ++ ) == c)
			{
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return tok;
			}
		}while(sc != 0);
	}
}

char* strsplit_after(char** stringp , const char* delim)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (delim == NULL)
		delim	= "=";
	if (!stringp || !*stringp)
		return NULL;

	char* tok = strsep(stringp , delim);
	if (tok)
		tok	= strsep(stringp , delim);
	return tok;
}

int Analyze_Info(char* source , char** result , int item_num , char* delim)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!source || !result)
		return -1;

	if (!delim)
		delim	= "+";

	int count	= 0;
	char* tmp_str	= NULL;
	for (tmp_str = strsplit_before(&source , delim) ; count < item_num/* && result[count] != NULL */; count ++ , tmp_str = strsplit_before(&source , delim))
	{
		if (!tmp_str)
			break;
		tmp_str		= strsplit_after(&tmp_str , "=");
		if (!tmp_str)
			break;
		result[count]	= calloc(strlen(tmp_str) + 1 , sizeof(char));
		if (!result[count])
			break;
		strcpy(result[count] , tmp_str);
	}
	if (count != item_num)
		return 1;
	/*for (int i = 0 ; i < item_num ; i ++)
	{
		result[i]	= strsplit_after(&result[i] , "=");
		if (result[i] == NULL)
			return 1;
	}*/
	return 0;
}

/*
int Analyze_Info(char* source , char** result , int item_num , char* delim)
{
	if (!source || !result)
		return -1;

	if (!delim)
		delim	= "+";

	int count	= 0;
	for (result[count] = strsplit_before(&source , delim) ; count < item_num && result[count] != NULL ; count ++ , result[count] = strsplit_before(&source , delim));
	if (count != item_num)
		return 1;
	for (int i = 0 ; i < item_num ; i ++)
	{
		result[i]	= strsplit_after(&result[i] , "=");
		if (result[i] == NULL)
			return 1;
	}
	return 0;
}
*/
int String_Replace(char* string , char ch_sou , char ch_des , int pos_start , int pos_end)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	char* pStr	= string;
	int length	= strlen(string);
	if (!pStr)
	{
		return 1;
	}
	if (pos_start == 0 && pos_end == 0)
	{
		pos_end	= length;
	}
	else if (pos_start < 0 || pos_end < 0 || pos_start >= length)
	{
		return 1;
	}
	
	if (pos_end >= length)
		pos_end	= length;

	if (pos_end < pos_start)
	{
		int tmp	= pos_end;
		pos_end	= pos_start;
		pos_start = tmp;
	}

	pStr	+= pos_start;
	int	pos_cur	= pos_start;
	while(*pStr != '\0' && pos_cur ++ <= pos_end)
	{
		if (*pStr == ch_sou)
			*pStr	= ch_des;
		pStr ++;
	}
	return 0;
}

int String_Delete_Char(char* string , char ch , int pos_start , int pos_end)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!string)
	{
		return 1;
	}

	int length	= strlen(string);
	if (pos_start == length)
		pos_start --;
	if (pos_end == length)
		pos_end -- ;
	if (pos_start > pos_end || pos_end < 0 || pos_start > length)
		return 1;
	else if (pos_start == 0 && pos_end == 0)
		pos_end	= length - 1;
	else if (pos_end > length)
		pos_end	= length - 1;

	char* cur_pos	= string + pos_start;

	for (int i = pos_start ; i <= pos_end && cur_pos != '\0' ; i ++)
	{
		if (*cur_pos == ch)
		{
			char* k	= cur_pos;
			int k_pos	= i;
			while (*k != '\0' && k_pos <= length)
			{
				*k	= *(k + 1);
				k ++;
				k_pos ++;
			}
		}
		cur_pos ++;
	}
	return 0;
}
