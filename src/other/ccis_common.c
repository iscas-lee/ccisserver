#include "ccis_common.h"
#include "ccis_time.h"
#include "ccis_string.h"
#include "../ccis.h"
#include "../type.h"
#include "../log/ccis_log.h"
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <pwd.h>

int	Write_File(const char* filepath , char* buffer , int bufLen , int status);
int	Get_Filepath(int type , char* filepath , const char* idnum , const char* querysn);	//type:0身份证，1公安部，2现场，3红外，4报告，5目录
int	Get_Homepath(char* result);


int Get_Filepath(int type , char* filepath , const char* idnum , const char* querysn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!filepath)
	{
		ccis_log_err("获取文件路径失败：无效的路径指针！");
		return -1;
	}

	int retv			= 0;
	const char bmp_flag[]           = {".bmp"};
	const char jpg_flag[]		= {".jpg"};
	const char vis_flag[]           = {"_3_catch"};
	const char report_flag[]	= {".html"};
	const char dir_idphoto[]	= {"/id_photo/"};
	const char dir_policephoto[]	= {"/police_photo/"};
	const char dir_visphoto[]	= {"/vis_photo/"};
	const char dir_infphoto[]	= {"/inf_photo/"};
	const char dir_report[]		= {"/report/"};
	char dir_name[CCIS_MIDSIZE]	= {0};
	DIR* dir 			= NULL;
	FILE* fp			= NULL;
	char* cur_date			= NULL;

	strcpy(dir_name , data_path);
	strcat(dir_name , "/");
	cur_date	= Get_Localdate();
	if (!cur_date)
	{
		retv	= -1;
		ccis_log_alert("[%s:%d]无法获取当前日期！" , __FUNCTION__ , __LINE__);
		goto clean_up;
	}
	if (String_Replace(cur_date , '/' , '-' , 0 , 0) != 0)
	{
		retv	= -1;
		ccis_log_alert("[%s:%d]转换日期格式出错！" , __FUNCTION__ , __LINE__);
		goto clean_up;
	}
	strcat(dir_name , cur_date);
	dir	= opendir(dir_name);
	if (!dir)
	{
		if (errno == ENOENT)
		{
			if (mkdir(dir_name , 0755))
			{
				retv	= errno;
				ccis_log_alert("[%s:%d]无法创建目录%s，失败原因：%s" , __FUNCTION__ , __LINE__ , dir_name , strerror(errno));
				goto clean_up;
			}
		}
		else
		{
			retv	= errno;
			ccis_log_err("[%s:%d]无法打开目录%s，失败原因：%s" , __FUNCTION__ , __LINE__ , dir_name , strerror(errno));
			goto clean_up;
		}
	}
	else
	{
		closedir(dir);
		dir	= NULL;
	}

	switch(type)
	{
		case 0:{
			strcat(dir_name , dir_idphoto);
		}break;
		case 1:{
			strcat(dir_name , dir_policephoto);
		}break;
		case 2:{
			strcat(dir_name , dir_visphoto);
		}break;
		case 3:{
			strcat(dir_name , dir_infphoto);
		}break;
		case 4:{
			strcat(dir_name , dir_report);
		}break;
		default:{
			strcpy(filepath , dir_name);
			goto clean_up;
		};
	}

	dir	= opendir(dir_name);
	if (!dir)
	{
		if (errno == ENOENT)
		{
			if (mkdir(dir_name , 0755))
			{
				retv	= errno;
				ccis_log_alert("[%s:%d]无法创建目录%s，失败原因：%s" , __FUNCTION__ , __LINE__ , dir_name , strerror(errno));
				goto clean_up;
			}
		}
		else
		{
			retv	= errno;
			ccis_log_err("[%s:%d]无法打开目录%s，失败原因：%s" , __FUNCTION__ , __LINE__ , dir_name , strerror(errno));
			goto clean_up;
		}
	}
	else
	{
		closedir(dir);
		dir	= NULL;
	}

	strcat(dir_name , idnum);
	if (querysn)
	{
		strcat(dir_name , "_");
		while(*querysn ++ == '0');
		querysn	--;
		strcat(dir_name , querysn);
	}
//ada-add
	if (type == 0)
	{
		strcat(dir_name , bmp_flag);
		fp	= fopen(dir_name , "wb+");
		if (!fp)
		{
			retv	= errno;
			ccis_log_err("文件[%s]打开失败，失败原因：%s" , dir_name , strerror(errno));
			goto clean_up;

		}
	}
	else if (type == 1)
	{
		strcat(dir_name , jpg_flag);
		fp      = fopen(dir_name , "wb+");
                if (!fp)
                {
                        retv    = errno;
                        ccis_log_err("文件[%s]打开失败，失败原因：%s" , dir_name , strerror(errno));
                        goto clean_up;
                }

	}
	else if (type == 2)
	{
		strcat(dir_name , vis_flag);
		strcat(dir_name , jpg_flag);
		 fp      = fopen(dir_name , "wb+");
                if (!fp)
                {
                        retv    = errno;
                        ccis_log_err("文件[%s]打开失败，失败原因：%s" , dir_name , strerror(errno));
                        goto clean_up;
                }

	}
	else
	{
		strcat(dir_name , report_flag);
		fp	= fopen(dir_name , "w+");
		if (!fp)
		{
			retv	= errno;
			ccis_log_err("文件[%s]打开失败，失败原因：%s" , dir_name , strerror(errno));
			goto clean_up;
		}
	}
	
	strcpy(filepath , dir_name);
clean_up:
	if (cur_date)
		free(cur_date);
	cur_date = NULL;
	if (dir)
		closedir(dir);
	dir	= NULL;
	if (fp)
		fclose(fp);
	fp	= NULL;
	return retv;
}


int Write_File(const char* filepath , char* buffer , int bufLen , int status)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	FILE* fp = NULL;
	size_t	iWrite	= 0;
	if (filepath == NULL || buffer == NULL)
	{
		ccis_log_err("文件写入失败，文件路径/待写入内容不可为空！");
		return -1;
	}

	if (status == CCIS_PACKAGE_FIRST)
	{
		fp	= fopen(filepath , "w");
		if (!fp)
		{
			retv	= errno;
			ccis_log_err("[%s:%d]文件[%s]打开失败！失败原因：%s" , __FUNCTION__ , __LINE__ , filepath , strerror(errno));
			goto clean_up;
		}
	}
	else if (status == CCIS_PACKAGE_UNFINISHED)
	{
		fp	= fopen(filepath , "a");
		if (!fp)
		{
			retv	= errno;
			ccis_log_err("[%s:%d]文件[%s]打开失败！失败原因：%s" , __FUNCTION__ , __LINE__ , filepath , strerror(errno));
			goto clean_up;
		}
	}
	else
		goto clean_up;

	iWrite	= fwrite(buffer , sizeof(char) , bufLen , fp);
	if (iWrite != bufLen)
	{
		retv	= -1;
		ccis_log_err("文件[%s]写入失败！失败原因：%s" , filepath , strerror(errno));
		goto clean_up;
	}

clean_up:
	if (fp)
		fclose(fp);
	fp	= NULL;
	return retv;
}

int Get_Homepath(char* result)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!result)
	{
		ccis_log_alert("获取用户主目录失败！失败原因：无效的存放指针！");
		return 1;
	}
	struct passwd *pwd;
	uid_t uid = getuid();
	pwd = getpwuid(uid);
	if (!pwd) {
		ccis_log_alert("获取用户主目录失败！失败原因：%s" , strerror(errno));
	        return 1;
	}
	else
	{
		strcpy(result , pwd->pw_dir);
        	return 0;
	}
}
