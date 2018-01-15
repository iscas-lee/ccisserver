#include "monitor.h"
#include "../ccis.h"
#include "../log/ccis_log.h"
#include "../database/dbquery.h"
#include <stdio.h>
#include <errno.h>

int	Client_Login_Status(int level , const char* devsn , int value , const char* comment);
int	Client_Logout_Status(int level , const char* devsn , int value , const char* comment);

int Client_Login_Status(int level , const char* devsn , int value , const char* comment)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn)
		return -1;
	int retv	= 0;
	Do_Connect();
	char sql_command[CCIS_MIDSIZE];

	if (!comment)
	{
		sprintf(sql_command , "'%s','%d','%d','%d'" , devsn , level , CCIS_MONITOR_LOGIN , value);
		retv	= DB_Insert_Data("dev12" , "devsn,level,type,value" , sql_command);
	}
	else
	{
		sprintf(sql_command , "'%s','%d','%d','%d','%s'" , devsn , level , CCIS_MONITOR_LOGIN , value , comment);
		retv	= DB_Insert_Data("dev12" , "devsn,level,type,value,comment" , sql_command);
	}

	if (retv)
	{
		ccis_log_err("[%s:%d]数据库插入失败！SQL返回值：%d" , __FUNCTION__ , __LINE__ , retv);
	}
	
clean_up:
	Do_Close();
	return retv;
}

int Client_Logout_Status(int level , const char* devsn , int value , const char* comment)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn)
		return -1;
	int retv	= 0;
	Do_Connect();
	char sql_command[CCIS_MIDSIZE];

	if (!comment)
	{
		sprintf(sql_command , "'%s','%d','%d','%d'" , devsn , level , CCIS_MONITOR_LOGOUT , value);
		retv	= DB_Insert_Data("dev12" , "devsn,level,type,value" , sql_command);
	}
	else
	{
		sprintf(sql_command , "'%s','%d','%d','%d','%s'" , devsn , level , CCIS_MONITOR_LOGIN , value , comment);
		retv	= DB_Insert_Data("dev12" , "devsn,level,type,value,comment" , sql_command);
	}

	if (retv)
	{
		ccis_log_err("[%s:%d]数据库插入失败！SQL返回值：%d" , __FUNCTION__ , __LINE__ , retv);
	}
clean_up:
	Do_Close();
	return retv;
}
