#include "client_login.h"
#include "../type.h"
#include "../ccis.h"
#include "../database/dbquery.h"
#include "../other/ccis_common.h"
#include "../log/ccis_log.h"
#include "../security/security.h"
#define NON_MAIN
#include "../security/ca/apps.h"
#undef NON_MAIN
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

int	Compare_Client_Hash(char* devsn , pHashInfo pstHash);			//对比软硬件hash值，匹配返回0
int	Insert_HardSN(char* devsn , pHardSN pstHard);				//插入硬件SN号
int	Modify_HardSN(char* devsn , pHardSN pstHard);				//更改硬件SN号
int	Get_UkeyPIN(char* devsn , char* tpmsn , char* ukeysn , char* result , int chkbind);	//获取Ukey PIN码
int	Try_NewPIN(char* ukeysn , char* newpin);				//检查是否有新PIN码，没有返回0，有返回1
int	Bind_Ukey_TPM(char* devsn , char* tpmsn , char* ukeysn);		//绑定Ukey与TPM
int	Unbind_Ukey_TPM(char* devsn , char* tpmsn , char* ukeysn);		//解除Ukey绑定关系
int	Check_Ukey_TPM(char* devsn , char* tpmsn , char* ukeysn);		//检测Ukey与TPM绑定关系
int	Check_Ukey_Bind_Status(char* ukeysn);					//检测Ukey绑定状态
int	Insert_SystemInfo(char* devsn , pSystemInfo pstSystem);			//插入系统信息
int	Modify_SystemInfo(char* devsn , pSystemInfo pstSystem);			//更新系统信息
int	Receive_Ukey_Cert(char* filepath , char* buffer , int bufLen , int status);	//接收Ukey证书
int	Rollback_SystemInfo(char* devsn);						//回滚插入的硬件信息
int	Rollback_HardSN(char* devsn);						//回滚插入的硬件信息
int	Check_Cert_In_CA(char* certfile);
int	Check_Orgid(const char* devsn , const char* orgid);			//验证Orgid有效性
int	Check_Pwd_Status(const char* pbcuser , char* newinfo , int* pwdlen , RSA* pubkey);	//检验是否有密码需要更新，返回0表示无需修改，返回1表示需要修改，-1表示异常
int	Check_Account_Status(const char* devsn , const char* ukeysn , char* newinfo , int* pwdlen , RSA* pubkey);	//检验是否有帐密需要更新
int	Update_Account_Status(const char* devsn , const char* ukeysn , const char* pbcuser  , int status);	//更新帐号状态
int	Query_PBC_Account(const char* devsn , const char* ukeysn , const char* orgid , char* result);		//申请征信帐号密码
int	Check_PBCInfo_Change(const char* devsn , const char* ukeysn , PBCInfo* pstPBC);		//检测帐号更新状态
int	Record_PBCInfo_Change(const char* devsn , const char* ukeysn , PBCInfo* pstPBC , int status , int reason , const char* opera); //记录密码更新日志
int	Check_Register_Status(const char* devsn , const char* ukeysn , bool* tpmsign , bool* ukeysign);	//检测TPM与Ukey的注册状态
int	Version_Check(const char* client_ver , const char* lowlimit_ver , const char* uplimit_ver);		//检测客户端版本号，通过返回0,过低返回负值，过高返回正值
int	Compare_Version(const char* client_ver , const char* limit_ver , int sign);		//比较版本号
int	Check_LoginStatus(const char* devsn);	//返回0表示允许登陆，返回1禁止登陆

void	Free_Hash(pHashInfo pstHash);
void	Free_HardSN(pHardSN pstHard);
void	Free_UkeyBind(pUkeyBind pstUkeyBind);
void	Free_PBCInfo(pPBCInfo pstPBC);
void	Free_SystemInfo(pSystemInfo pstSystem);

int Compare_Client_Hash(char* devsn , pHashInfo pstHash)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !pstHash)
		return 1;

	int retv	= 0;
	char* sql_command	= NULL;
	Query_Info* q_ret	= NULL;
	
	Do_Connect();
	sql_command	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_command)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));

	sprintf(sql_command , "devsn='%s'" , devsn);
	retv	= DB_Select_Data("dev02" , "modhash" , sql_command , q_ret);
	if (retv == -1)
	{
		ccis_log_err("[devsn:%s]该设备尚未登记！" , devsn);
		ccis_log_debug("[devsn:%s]尝试硬件型号hash：%s尝试软件版本hash：%s" , devsn , pstHash->hardmodelhash , pstHash->softhash);
		goto clean_up;
	}
	else if (retv)
	{
		printf("[devsn:%s]数据库查询失败！SQL errcode %d\n" , devsn , retv);
		retv	= 1;
		goto clean_up;
	}

	if (likely(q_ret->res_data[0][0]))
	{
		if (strcmp(pstHash->hardmodelhash , q_ret->res_data[0][0]))
		{
			ccis_log_err("[devsn:%s]硬件hash不匹配！" , devsn);
			ccis_log_err("[devsn:%s]尝试硬件型号hash：%s" , devsn , pstHash->hardmodelhash);
			retv	= 2;
			goto clean_up;
		}
	}
	else
	{
		ccis_log_err("[devsn:%s]硬件hash未登记！" , devsn);
		retv	= 2;
		goto clean_up;
	}
/*
	memset(q_ret , 0 , sizeof(Query_Info));

	retv	= DB_Select_Data("dev04" , "hash" , sql_command , q_ret);
	if (retv == -1)
	{
		ccis_log_err("[devsn:%s]该设备尚未登记！" , devsn);
		ccis_log_debug("[devsn:%s]尝试硬件型号hash：%s尝试软件版本hash：%s" , devsn , pstHash->hardmodelhash , pstHash->softhash);
		goto clean_up;
	}
	else if (retv)
	{
		ccis_log_err("[devsn:%s]数据库查询失败！SQL errcode %d" , devsn , retv);
		retv	= 1;
		goto clean_up;
	}

	if (strcmp(pstHash->softhash , q_ret->res_data[0][0]))
	{
		ccis_log_err("[devsn:%s]软件hash不匹配！" , devsn);
		ccis_log_err("[devsn:%s]尝试软件版本hash：%s" , devsn , pstHash->softhash);
		retv	= 3;
		goto clean_up;
	}
*/
clean_up:
	if (sql_command)
		free(sql_command);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	Do_Close();
	return retv;
}

int Insert_HardSN(char* devsn , pHardSN pstHard)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !pstHard)
	{
		return 1;
	}

	int retv	= 0;
	char* sql_command_values	= NULL;
	
	Do_Connect();
	sql_command_values	= (char*)malloc(CCIS_MAXSIZE);
	if (!sql_command_values)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	sprintf(sql_command_values , "'%s','%s','%s','%s','%s','%s','%s','%s'" , devsn , pstHard->prtsn , pstHard->idrsn , pstHard->tssn , pstHard->chgsn , pstHard->camsn01 , pstHard->camsn02 , pstHard->vedsn);
	retv	= DB_Insert_Data("dev03" , "devsn,prtsn,idrsn,tssn,chgsn,camsn01,camsn02,vedsn" , sql_command_values);
	if (retv)
	{
		ccis_log_err("[%s:%d]Insert DB Failed , errno %d" , __FUNCTION__ , __LINE__ , retv);
		retv	= 1;
		goto clean_up;
	}

clean_up:
	if (sql_command_values)
		free(sql_command_values);
	Do_Close();

	return retv;
}

int Modify_HardSN(char* devsn , pHardSN pstHard)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !pstHard)
		return 1;

	int retv	= 0;
	char* sql_command	= NULL;
	char* sql_condition	= NULL;

	Do_Connect();
	sql_command	= (char*)malloc(CCIS_MAXSIZE);
	if (!sql_command)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	sql_condition	= (char*)malloc(CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}

	sprintf(sql_command , "tpmsn='%s',ukeysn='%s',prtsn='%s',idrsn='%s',tssn='%s',chgsn='%s',camsn01='%s',camsn02='%s',vedsn='%s'" , pstHard->tpmsn , pstHard->ukeysn , pstHard->prtsn , pstHard->idrsn , pstHard->tssn , pstHard->chgsn , pstHard->camsn01 , pstHard->camsn02 , pstHard->vedsn);
	sprintf(sql_condition , "devsn='%s'" , devsn);

	retv	= DB_Update_Data("dev03" , sql_command , sql_condition);

clean_up:
	Do_Close();
	if (sql_command)
	{
		free(sql_command);
		sql_command	= NULL;
	}
	if (sql_condition)
	{
		free(sql_condition);
		sql_condition	= NULL;
	}
	return retv;
}

int Get_UkeyPIN(char* devsn , char* tpmsn , char* ukeysn , char* result , int chkbind)	//-1未知错误，0成功，1Ukey未登记，2Ukey与TPM不匹配，3数据库查询错误
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !tpmsn || !ukeysn || !result)
		return -1;
#ifdef DEBUG
	ccis_log_debug("设备号：%sUKeySN：%s" , devsn , ukeysn);
#endif

	if (chkbind)
	{
		if (Check_Ukey_TPM(devsn , tpmsn , ukeysn))
		{
			ccis_log_err("[devsn:%s]Ukey与TPM绑定关系不匹配！" , devsn);
			return 2;
		}
	}

	int retv	= 0;
	char* sql_command	= NULL;
	Query_Info* q_ret	= NULL;

	Do_Connect();
	sql_command	= (char*)malloc(CCIS_MIDSIZE);
	if (!sql_command)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));

	sprintf(sql_command , "ukeysn='%s'" , ukeysn);	
	retv	= DB_Select_Data("type21" , "pin" , sql_command , q_ret);
	if (retv == 0 && q_ret->res_data[0][0])
	{
		strcpy(result , q_ret->res_data[0][0]);
	}
	else if (retv == -1)
	{
		ccis_log_err("[devsn:%s]设备使用的Ukey未被登记在数据库中！" , devsn);
		retv	= 1;
	}
	else
	{
		retv	= 3;
		printf("[%s:%d] SQL Select Failed , returned %d\n" , __FUNCTION__ , __LINE__ , retv);
	}
	
clean_up:
	Do_Close();
	if(sql_command)	
	{
		free(sql_command);
		sql_command	= NULL;
	}
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Try_NewPIN(char* ukeysn , char* newpin)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ukeysn || !newpin)
		return 0;

	int retv	= 0;
	Do_Connect();
	char sql_condition[CCIS_MIDSIZE];
	Query_Info* q_ret	= (Query_Info*)calloc(1 , sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 0;
		goto clean_up;
	}

	sprintf(sql_condition , "ukeysn='%s'" , ukeysn);
	retv	= DB_Select_Data("type21" , "newpin" , sql_condition , q_ret);
	if (retv)
	{
		ccis_log_debug("[%s:%d]SQL查询错误！返回码：%d" , __FUNCTION__ , __LINE__ , retv);
		retv	= 0;
		goto clean_up;
	}
	else
	{
		if (!q_ret->res_data[0][0] || !strcmp(q_ret->res_data[0][0] , ""))
		{
			ccis_log_debug("Ukey[%s]不存在未同步的pin码" , ukeysn);
			retv	= 0;
			goto clean_up;
		}
		strcpy(ukeysn , q_ret->res_data[0][0]);
		ccis_log_debug("查找到Ukey[%s]未同步的pin码！" , ukeysn);
		retv	= 1;
		goto clean_up;
	}

clean_up:
	Do_Close();
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Insert_SystemInfo(char* devsn , pSystemInfo pstSystem)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !pstSystem)
		return 1;
	int retv	= 0;
	char* sql_command	= NULL;
	Do_Connect();
	
	sql_command	= (char*)malloc(CCIS_MIDSIZE * sizeof(char));
	if (!sql_command)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}

	sprintf(sql_command , "'%s','%s','%s','%s','%s'" , devsn , pstSystem->ip , pstSystem->netmask , pstSystem->gateway , pstSystem->dns);
	retv	= DB_Insert_Data("dev05" , "devsn,ip,netmask,gateway,dns" , sql_command);

clean_up:
	Do_Close();
	if (sql_command)
		free(sql_command);
	return retv;
}

int Modify_SystemInfo(char* devsn , pSystemInfo pstSystem)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !pstSystem)
		return 1;

	int retv	= 0;
	char* sql_command	= NULL;
	char* sql_condition	= NULL;
	Do_Connect();

	sql_command	= (char*)malloc(CCIS_MIDSIZE * sizeof(char));
	if (!sql_command)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	sql_condition	= (char*)malloc(CCIS_SMALLSIZE * sizeof(char));
	if (!sql_condition)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}

	sprintf(sql_condition , "devsn='%s'" , devsn);
	sprintf(sql_command , "ip='%s',netmask='%s',gateway='%s',dns='%s'" , pstSystem->ip , pstSystem->netmask , pstSystem->gateway , pstSystem->dns);

	retv	= DB_Update_Data("dev05" , sql_command , sql_condition);
clean_up:
	Do_Close();
	if (sql_command)
		free(sql_command);
	if (sql_condition)
		free(sql_condition);
	return retv;
}

int Bind_Ukey_TPM(char* devsn , char* tpmsn , char* ukeysn)	//-1未知错误，0绑定成功，1ukey已被绑定
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !tpmsn || !ukeysn)
		return -1;

	if (Check_Ukey_Bind_Status(ukeysn))
		return 1;
	char* sql_command	= NULL;
	int retv	= 0;
	Do_Connect();
	sql_command	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_command)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	sprintf(sql_command , "'%s','%s','%s'" , devsn,tpmsn,ukeysn);
	retv	= DB_Insert_Data("dev11" , "devsn,tpmsn,ukeysn" , sql_command);
	if (unlikely(retv))
	{
		ccis_log_err("[devsn:%s]TPM与UKey绑定失败！失败原因：%d" , devsn , retv);
		retv	= -1;
	}
	else
	{
		ccis_log_info("[devsn:%s]TPM与UKey已绑定！" , devsn);
	}

clean_up:
	Do_Close();
	if (sql_command)
		free(sql_command);
	return retv;
}

int Unbind_Ukey_TPM(char* devsn , char* tpmsn , char* ukeysn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !tpmsn || !ukeysn)
		return -1;
	int retv	= 0;
	Do_Connect();
	char* sql_condition	= NULL;
	sql_condition	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_condition)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	sprintf(sql_condition , "devsn='%s' and tpmsn='%s' and ukeysn='%s'" , devsn , tpmsn , ukeysn);

	retv	= DB_Delete_Data("dev11" , sql_condition);
	
clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	return retv;
}

int Check_Ukey_TPM(char* devsn , char* tpmsn , char* ukeysn)		//-1未知错误，0Ukey与TPM匹配，1Ukey与TPM不匹配
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !tpmsn || !ukeysn)
		return -1;
	int retv	= 0;
	Do_Connect();
	char* sql_condition	= NULL;
	Query_Info* q_ret	= NULL;
	sql_condition	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_condition)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));

	sprintf(sql_condition , "devsn='%s' and tpmsn='%s' and ukeysn='%s'" , devsn , tpmsn , ukeysn);
	retv	= DB_Select_Data("dev11" , "devsn" , sql_condition , q_ret);
	if (retv == -1)
		retv	= 1;
	else if (retv)
	{
		ccis_log_err("[%s:%d]数据库查询错误！错误码：%d" , __FUNCTION__ , __LINE__ , retv);
	}

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Check_Ukey_Bind_Status(char* ukeysn)			//-1未知错误，0Ukey尚未被绑定，1Ukey已被使用
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ukeysn)
		return -1;
	int retv	= 0;
	Do_Connect();
	char* sql_condition	= NULL;
	Query_Info* q_ret	= NULL;

	sql_condition	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));
	sprintf(sql_condition , "ukeysn='%s'" , ukeysn);
	retv	= DB_Select_Data("dev11" , "devsn" , sql_condition , q_ret);
	if (unlikely(retv == 0))
	{
		retv	= 1;
		if (q_ret->res_data[0][0])
			ccis_log_info("Ukey[%s]已经与设备[%s]绑定！" , ukeysn , q_ret->res_data[0][0]);
		else
			ccis_log_info("Ukey[%s]已经与某台设备绑定，设备号无法获取，请检查数据库！" , ukeysn);
	}
	else if (retv == -1)
	{
		retv	= 0;
		ccis_log_info("Ukey[%s]尚未被绑定！" , ukeysn);
	}
	else
	{
		ccis_log_err("[%s:%d]数据库查询错误！错误码：%d" , __FUNCTION__ , __LINE__ , retv);
	}

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Receive_Ukey_Cert(char* filepath , char* buffer , int bufLen , int status)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	FILE* fp	= NULL;
	if (status == CCIS_PACKAGE_FINISHED)
	{
		fp	= fopen(filepath , "r");
		if (!fp)
		{
			ccis_log_err("无法打开证书文件%s ，失败原因：%s" , filepath , strerror(errno));
			retv	= 1;
			goto clean_up;
		}
	}
	else
	{
		retv	= Write_File(filepath , buffer , bufLen , status);
	}

clean_up:
	if (fp)
		fclose(fp);
	return retv;
}

void Free_Hash(pHashInfo pstHash)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pstHash)
		return;
	
	if (pstHash->hardmodelhash)
		free(pstHash->hardmodelhash);
	if (pstHash->softhash)
		free(pstHash->softhash);
	free(pstHash);
}

void Free_HardSN(pHardSN pstHard)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pstHard)
		return;
	
	if (pstHard->ukeysn)
		free(pstHard->ukeysn);
	if (pstHard->tpmsn)
		free(pstHard->tpmsn);
	if (pstHard->prtsn)
		free(pstHard->prtsn);
	if (pstHard->idrsn)
		free(pstHard->idrsn);
	if (pstHard->tssn)
		free(pstHard->tssn);
	if (pstHard->chgsn)
		free(pstHard->chgsn);
	if (pstHard->camsn01)
		free(pstHard->camsn01);
	if (pstHard->camsn02)
		free(pstHard->camsn02);
	if (pstHard->vedsn)
		free(pstHard->vedsn);
	free(pstHard);
}

void Free_UkeyBind(pUkeyBind pstUkeyBind)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pstUkeyBind)
		return ;

	if (pstUkeyBind->tpmsn)
		free(pstUkeyBind->tpmsn);
	if (pstUkeyBind->ukeysn);
		free(pstUkeyBind->ukeysn);
	free(pstUkeyBind);
}

void Free_PBCInfo(pPBCInfo pstPBC)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pstPBC)
		return;

	if (pstPBC->pbcid)
		free(pstPBC->pbcid);
	if (pstPBC->username)
		free(pstPBC->username);
	if (pstPBC->password)
		free(pstPBC->password);
	if (pstPBC->agt)
		free(pstPBC->agt);
	free(pstPBC);
}

void Free_SystemInfo(pSystemInfo pstSystem)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pstSystem)
		return;

	if (pstSystem->ip)
		free(pstSystem->ip);
	if (pstSystem->netmask)
		free(pstSystem->netmask);
	if (pstSystem->gateway)
		free(pstSystem->gateway);
	if (pstSystem->dns)
		free(pstSystem->dns);
	free(pstSystem);
}

int Rollback_SystemInfo(char* devsn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn)
		return 1;

	int retv	= 0;
	Do_Connect();
	char* sql_condition	= NULL;
	sql_condition	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	sprintf(sql_condition , "devsn='%s'" , devsn);

	retv	= DB_Delete_Data("dev05" , sql_condition);

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	return retv;
}

int Rollback_HardSN(char* devsn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn)
		return 1;
	int retv	= 0;
	Do_Connect();
	char* sql_condition	= NULL;
	sql_condition	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	sprintf(sql_condition , "devsn='%s'" , devsn);

	retv	= DB_Delete_Data("dev03" , sql_condition);

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	return retv;
}

int Check_Cert_In_CA(char* certfile)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!certfile)
        	return 1;
	char *CertStatusReq[16] = {"-issuer" , cacert , "-CAfile" , cacert , "-certfile" , certfile , "-url" , cahost};
	if (SSL_CheckCertStatus(CertStatusReq) == V_OCSP_GERTSTATUS_GOOD)
	{
        	return 0;
	}
	else
        	return 1;
}

int Check_Orgid(const char* devsn , const char* orgid)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!orgid)
		return -1;
	int retv	= 0;
	char* sql_condition	= NULL;
	Query_Info* q_ret	= NULL;
	Do_Connect();

	sql_condition	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	sprintf(sql_condition , "pbcid='%s'" , orgid);
	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));

	retv	= DB_Select_Data("org02" , "*" , sql_condition , q_ret);
	if (retv == -1)
	{
		ccis_log_err("[devsn:%s]SQL 查询失败：未登记的Orgid！" , devsn);
		retv	= 1;
	}
	else if (retv != 0)
	{
		ccis_log_err("[devsn:%s]SQL 查询失败，SQL错误码：%d" , devsn , retv);
		retv	= 1;
	}

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Check_Pwd_Status(const char* pbcuser , char* newinfo , int* pwdlen , RSA* pubkey)		//检验是否有密码需要更新，返回0表示无需修改，返回1表示需要修改，-1表示异常
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pbcuser || !newinfo || !pwdlen || !pubkey)
		return -1;

	int retv	= 0;
	char* sql_condition	= NULL;
	Query_Info* q_ret	= NULL;
	Do_Connect();

	sql_condition	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	q_ret	= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}

	sprintf(sql_condition , "usrid='%s' order by crtdate desc" , pbcuser);
	retv	= DB_Select_Data("org03" , "usrpwd,status" , sql_condition , q_ret);
	if (retv == -1)
	{
		ccis_log_debug("账号[%s]无密码更新记录" , pbcuser);
		retv	= 0;
		goto clean_up;
	}
	else if (retv == 0)
	{
		int status	= 0;
		if (q_ret->res_data[0][1])
			status	= atoi(q_ret->res_data[0][1]);
		ccis_log_debug("账号[%s]最近的密码更新记录状态为：%d" , pbcuser , status);
		if (status == 1)
		{
			if (q_ret->res_data[0][0])
			{
				//Base64先解密，然后再用对端Ukey公钥加密，密文是newpwd，然后还要有密文长度
				char tmppwd[CCIS_SMALLSIZE]	= {0};
				if (Base64_Decode(q_ret->res_data[0][0] , strlen(q_ret->res_data[0][0]) , tmppwd , CCIS_SMALLSIZE))
				{
					ccis_log_err("账号[%s]需要更新密码，但数据库密文密码解密失败！请联系管理员解决" , pbcuser);
					retv	= -1;
					goto clean_up;
				}
				*pwdlen	= server_encrypt_long_data(tmppwd , newinfo , pubkey);
				if (*pwdlen <= 0)
				{
					ccis_log_err("账号[%s]需要更新密码，但密码加密失败！请联系管理员解决" , pbcuser);
				}
				retv	= 1;
				ccis_log_debug("账号[%s]待更新的新密码已准备就绪，即将推送" , pbcuser);
			}
			else
				ccis_log_err("账号[%s]需要更新密码，但数据库中密码为空！请联系管理员解决" , pbcuser);
		}
	}
	else
	{
		ccis_log_err("[%s:%d]SQL查询错误！SQL返回码：%d" , __FUNCTION__ , __LINE__ , retv);
		retv	= -1;
	}

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Check_Account_Status(const char* devsn , const char* ukeysn , char* newinfo , int* pwdlen , RSA* pubkey)	//检验是否有帐密需要更新
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !ukeysn || !newinfo || !pwdlen || !pubkey)
		return -1;

	int retv	= 0;
	char* sql_condition	= NULL;
	Query_Info* q_ret	= NULL;
	Do_Connect();

	sql_condition	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_condition)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	q_ret	= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}

	sprintf(sql_condition , "devsn='%s' and ukeysn='%s' order by changeid desc" , devsn , ukeysn);
	retv	= DB_Select_Data("org03" , "usrid,usrpwd,status" , sql_condition , q_ret);
	if (retv == -1)
	{
		ccis_log_debug("[devn:%s]设备无帐密更新记录" , ukeysn);
		retv	= 0;
		goto clean_up;
	}
	else if (retv == 0)
	{
		int status	= 0;
		if (q_ret->res_data[0][2])
			status	= atoi(q_ret->res_data[0][2]);
		ccis_log_debug("[devsn:%s]设备最近的帐密更新记录状态为：%d" , devsn , status);
		if (status == 1)
		{
			if (q_ret->res_data[0][0] && q_ret->res_data[0][1])
			{
				//Base64先解密，然后再用对端Ukey公钥加密，密文是newpwd，然后还要有密文长度
				char tmppwd[CCIS_SMALLSIZE]	= {0};
				char tmpinfo[CCIS_MIDSIZE]	= {0};
				if (Base64_Decode(q_ret->res_data[0][1] , strlen(q_ret->res_data[0][1]) , tmppwd , CCIS_SMALLSIZE))
				{
					ccis_log_err("[devsn:%s]设备需要更新帐密，但数据库密文密码解密失败！请联系管理员解决" , devsn);
					retv	= -1;
					goto clean_up;
				}
				sprintf(tmpinfo , "username=%s+password=%s" , q_ret->res_data[0][0] , tmppwd);
				*pwdlen	= server_encrypt_long_data(tmpinfo , newinfo , pubkey);
				if (*pwdlen <= 0)
				{
					ccis_log_err("[desn:%s]设备需要更新帐密，但密码加密失败！请联系管理员解决" , devsn);
				}
				retv	= 1;
				ccis_log_debug("[devsn:%s]设备待更新的新帐密已准备就绪，即将推送" , devsn);
			}
			else
				ccis_log_err("[devsn:%s]设备需要更新帐密，但数据库中信息为空！请联系管理员解决" , devsn);
		}
	}
	else
	{
		ccis_log_err("[%s:%d]SQL查询错误！SQL返回码：%d" , __FUNCTION__ , __LINE__ , retv);
		retv	= -1;
	}

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}
int Update_Account_Status(const char* devsn , const char* ukeysn , const char* pbcuser , int status)			//更新密码状态
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pbcuser)
		return -1;
	int retv	= 0;
	char sql_condition[CCIS_MAXSIZE];
	char sql_command[CCIS_MIDSIZE];
	Query_Info* q_ret;
	char passwordhash[CCIS_SMALLSIZE];
	Do_Connect();

	q_ret	= (Query_Info*)calloc(1 , sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}

	if (!strcmp(pbcuser , ""))
		sprintf(sql_condition , "devsn='%s' and status <> '2' and status <> '3' order by changeid desc" , devsn);
	else
		sprintf(sql_condition , "devsn='%s' and usrid='%s' and status <> '2' and status <> '3' order by changeid desc" , devsn , pbcuser);

	retv	= DB_Select_Data("org03" , "changeid,usrid,usrpwd" , sql_condition , q_ret);
	if (retv == -1)
	{
		ccis_log_err("[devsn:%s]帐号(%s)状态更新失败，无法找到该帐号的更新记录！" , devsn , pbcuser);
		goto clean_up;
	}
	else if (retv)
	{
		ccis_log_err("[devsn:%s]帐号(%s)状态更新失败，数据库错误！" , devsn , pbcuser);
		ccis_log_err("[%s:%d]SQL Select Failed ! SQL returned %d" , __FUNCTION__ , __LINE__ , retv);
		retv	= -1;
		goto clean_up;
	}
	else
	{
		if (q_ret->res_data[0][1] && q_ret->res_data[0][2])
		{
			char s_pwd[CCIS_SMALLSIZE];
			if (Base64_Decode(q_ret->res_data[0][2] , strlen(q_ret->res_data[0][2]) , s_pwd , CCIS_SMALLSIZE))
			{
				ccis_log_err("[devsn:%s]帐号(%s)状态更新失败：无法解密密码！" , devsn , q_ret->res_data[0][1]);
				retv	= -1;
				goto clean_up;
			}
			if (Compute_String_MD5(s_pwd , passwordhash))
			{
				ccis_log_err("[devsn:%s]帐号(%s)状态更新失败，无法计算原密码hash值！" , devsn , q_ret->res_data[0][1]);
				retv	= -1;
				goto clean_up;
			}
		}
		else
		{
			ccis_log_err("[devsn:%s]帐号(%s)状态更新失败，原密码不存在！" , devsn , pbcuser);
			retv	= -1;
			goto clean_up;
		}
	}

	sprintf(sql_condition , "changeid='%s'" , q_ret->res_data[0][0]);

/*
	if (status > 2)
		sprintf(sql_command , "ukeysn='%s',usrpwd='%s',status='%d'" , ukeysn , passwordhash , status);
	else
		sprintf(sql_command , "ukeysn='%s',status='%d'" , ukeysn , status);
*/
	sprintf(sql_command , "ukeysn='%s',usrpwd='%s',status='%d'" , ukeysn , passwordhash , status);
	retv	= DB_Update_Data("org03" , sql_command , sql_condition);

clean_up:
	Do_Close();
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Query_PBC_Account(const char* devsn , const char* ukeysn , const char* orgid , char* result)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !ukeysn || !orgid || !result)
		return -1;

	int retv	= 0;
	Do_Connect();
	Query_Info* q_ret;
	char sql_condition[CCIS_MIDSIZE];
	char sql_command[CCIS_MAXSIZE];

	q_ret	= (Query_Info*)calloc(1 , sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}

	sprintf(sql_condition , "devsn='%s' order by changeid desc" , devsn);

	retv	= DB_Select_Data("org03" , "status,usrid,usrpwd,ukeysn" , sql_condition , q_ret);
	if (retv == -1)
	{
		retv	= 0;
		ccis_log_info("[devsn:%s]设备未申请过帐号，允许申请新帐号！" , devsn);
		sprintf(sql_command , "'%s','%s','%s','%s','%s','%s','%s'" , orgid , devsn , ukeysn , "N/A" , "0" , "2" , "N/A"); //reason==2表示客户端首次开机申请帐号
		retv	= DB_Insert_Data("org03" , "orgid,devsn,ukeysn,usrid,status,reason,operator" , sql_command);
		if (retv)
		{
			ccis_log_err("[devsn:%s]设备征信帐号申请失败，数据库插入错误！" , devsn);
			ccis_log_err("[%s:%d]SQL Insert Failed ! SQL returned %d" , __FUNCTION__ , __LINE__ , retv);
			retv	= -2;
			goto clean_up;
		}
		ccis_log_info("[devsn:%s]设备征信帐号申请已提交！" , devsn);
		goto clean_up;
	}
	else if (retv == 0)
	{
		if (q_ret->res_data[0][0])
		{
			if (!strcmp(q_ret->res_data[0][0] , "0"))
			{
				ccis_log_info("[devsn:%s]设备的帐号申请正在等待中，不允许重新申请！" , devsn);
				retv	= 2;
				goto clean_up;
			}
			else if (!strcmp(q_ret->res_data[0][0] , "1"))
			{
				if (q_ret->res_data[0][1] && q_ret->res_data[0][2])
				{
					ccis_log_info("[devn:%s]设备申请的新帐号已获得授权，将发送新帐号！" , devsn);
					char s_pwd[CCIS_SMALLSIZE];
					if (Base64_Decode(q_ret->res_data[0][2] , strlen(q_ret->res_data[0][2]) , s_pwd , 128))
					{
						ccis_log_err("[devsn:%s]设备的帐号已颁发，但密码解密失败，请联系管理员解决！" , devsn);
						retv	= -3;
						goto clean_up;
					}
					sprintf(result , "username=%s+password=%s" , q_ret->res_data[0][1] , s_pwd);
					retv	= 1;
				}
				else
				{
					ccis_log_err("[devsn:%s]设备申请的帐号有异常，请联系管理员检查！" , devsn);
					retv	= 4;
				}
				goto clean_up;
			}
			else if (!strcmp(q_ret->res_data[0][0] , "2"))
			{
				if (q_ret->res_data[0][3] && !strcmp(q_ret->res_data[0][3] , ukeysn))
				{
					ccis_log_info("[devsn:%s]设备已经拥有过征信帐号，不允许重新申请！" , devsn);
					retv	= 3;
					goto clean_up;
				}
				else
				{
					ccis_log_info("[devsn:%s]设备曾经拥有过帐号，但是所使用Ukey(%s)与当前(%s)不同，允许重新申请！" , devsn ,q_ret->res_data[0][3] , ukeysn);
					retv	= 0;
					goto clean_up;
				}
			}
			else
			{
				ccis_log_info("[devsn:%s]设备原始帐号密码可能存在某些错误，允许重新申请！" , devsn);
				retv	= 0;
				goto clean_up;
			}
		}
		else
		{
			retv	= 0;
			ccis_log_info("[devsn:%s]设备密码记录查询异常，但允许重新申请新帐号！" , devsn);
			sprintf(sql_command , "'%s','%s','%s','%s','%s','%s','%s'" , orgid , devsn , ukeysn , "N/A" , "0" , "2" , "N/A");
			retv	= DB_Insert_Data("org03" , "orgid,devsn,ukeysn,usrid,status,reason,operator" , sql_command);
			if (retv)
			{
				ccis_log_err("[devsn:%s]设备征信帐号申请失败，数据库插入错误！" , devsn);
				ccis_log_err("[%s:%d]SQL Insert Failed ! SQL returned %d" , __FUNCTION__ , __LINE__ , retv);
				retv	= -2;
				goto clean_up;
			}
			ccis_log_info("[devsn:%s]设备征信帐号申请已提交！" , devsn);
			goto clean_up;
		}
	}
	else
	{
		ccis_log_err("[devsn:%s]设备密码记录查询异常，无法申请新帐号！" , devsn);
		ccis_log_err("[%s:%d]SQL Select Failed ! SQL returned %d" , __FUNCTION__ , __LINE__ , retv);
	}


clean_up:
	Do_Close();
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}

	return retv;
}

int Check_PBCInfo_Change(const char* devsn , const char* ukeysn , PBCInfo* pstPBC)		//检测帐号更新状态，0表示无更新，1表示密码或帐号有变动
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !ukeysn || !pstPBC)
		return -1;

	int retv	= 0;
	Do_Connect();
	char sql_condition[CCIS_MIDSIZE];
	char cur_pwdhash[CCIS_MIDSIZE];
	Query_Info* q_ret;

	q_ret	= (Query_Info*)calloc(1 , sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}

	sprintf(sql_condition , "devsn='%s' and ukeysn='%s' order by changeid desc" , devsn , ukeysn);

	retv	= DB_Select_Data("org03" , "usrid,usrpwd" , sql_condition , q_ret);
	if (retv == -1)
	{
		ccis_log_info("[devsn:%s]设备无帐号记录信息，将记录该次登录信息作为初始参考信息！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	else if (retv == 0)
	{
		if (!q_ret->res_data[0][0] || !q_ret->res_data[0][1])
		{
			ccis_log_err("[devsn:%s]设备帐号信息存在缺失，将记录该次登录信息作为替换参考信息！" , devsn);
			retv	= 1;
			goto clean_up;
		}

		if (Compute_String_MD5(pstPBC->password , cur_pwdhash))
		{
			ccis_log_err("[devsn:%s]设备帐号信息校验失败，密码MD5计算失败，将记录该次登录信息作为替换参考信息！" , devsn);
			retv	= 1;
			goto clean_up;
		}

		if (strcmp(q_ret->res_data[0][0] , pstPBC->username) || strcmp(q_ret->res_data[0][1] , cur_pwdhash))
		{
			ccis_log_info("[devsn:%s]设备帐号信息存在变动，将记录该次登录信息作为替换参考信息！" , devsn);
			retv	= 1;
			goto clean_up;
		}
		else
		{
			ccis_log_debug("[devsn:%s]设备帐号信息无变更！" , devsn);
			retv	= 0;
			goto clean_up;
		}
	}
	else
	{
		ccis_log_err("[devsn:%s]设备历史帐号信息查询出错，将记录该次登录信息作为替换参考信息！" , devsn);
		ccis_log_err("[%s:%d]SQL Select Failed ! SQL returned %d" , __FUNCTION__ , __LINE__ , retv);
		retv	= 1;
	}

clean_up:
	Do_Close();
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Record_PBCInfo_Change(const char* devsn , const char* ukeysn , PBCInfo* pstPBC , int status , int reason , const char* opera) //记录密码更新日志
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn || !ukeysn || !pstPBC)
		return -1;

	int retv	= 0;
	Do_Connect();
	char sql_command[CCIS_MAXSIZE];
	char sql_condition[CCIS_MIDSIZE];
	char passwordhash[CCIS_MIDSIZE];

	if (Compute_String_MD5(pstPBC->password , passwordhash))
	{
		ccis_log_err("[devsn:%s]帐号(%s)密码变更记录失败，密码md5计算失败！" , devsn , pstPBC->username);
		retv	= -1;
		goto clean_up;
	}

	sprintf(sql_command , "'%s','%s','%s','%s','%s','%d','%d','%s'" , pstPBC->pbcid , devsn , ukeysn , pstPBC->username , passwordhash , status , reason , opera);

	retv	= DB_Insert_Data("org03" , "orgid,devsn,ukeysn,usrid,usrpwd,status,reason,operator" , sql_command);
	if (retv)
	{
		ccis_log_err("[devsn:%s]帐号(%s)密码变更记录失败，数据库插入失败！" , devsn , pstPBC->username);
		ccis_log_err("[%s:%d]SQL Insert Error ! SQL returned %d" , __FUNCTION__ , __LINE__ , retv);
		retv	= -1;
		goto clean_up;
	}
	ccis_log_info("[devsn:%s]帐号(%s)密码变更记录成功！" , devsn , pstPBC->username);

	sprintf(sql_condition , "devsn='%s' and status <> '2'" , devsn);
	sprintf(sql_command , "usrpwd='ABANDON',status='3'");
	retv	= DB_Update_Data("org03" , sql_command , sql_condition);
	if (retv)
	{
		ccis_log_err("[devsn:%s]设备历史帐号信息调整失败，请检查数据库！" , devsn);
		ccis_log_err("[%s:%d]SQL Update Error ! SQL returned %d" , __FUNCTION__ , __LINE__ , retv);
	}

clean_up:
	Do_Close();
	return retv;
}

int Check_Register_Status(const char* devsn , const char* ukeysn , bool* tpmsign , bool* ukeysign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	Query_Info* q_ret;
	char sql_condition[CCIS_SMALLSIZE];

	Do_Connect();
	q_ret	= (Query_Info*)calloc(1 , sizeof(Query_Info));
	if (!q_ret)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}

	//检测Ukey注册状态
	sprintf(sql_condition , "ukeysn='%s'" , ukeysn);
	retv	= DB_Select_Data("type21" , "regsign" , sql_condition , q_ret);
	if (retv == -1)
	{
		*ukeysign = false;
		ccis_log_info("[devsn:%s]所使用Ukey(%s)尚未登记！" , devsn , ukeysn);
	}
	else if (retv == 0)
	{
		if (q_ret->res_data[0][0])
		{
			if (strcmp(q_ret->res_data[0][0] , "2") == 0)
			{
				*ukeysign = true;
				ccis_log_debug("[devsn:%s]所使用Ukey(%s)已经注册！" , devsn , ukeysn);
			}
			else
			{
				*ukeysign = false;
				ccis_log_info("[devsn:%s]所使用Ukey(%s)尚未被注册！" , devsn , ukeysn);
			}
		}
		else
		{
			*ukeysign = false;
			ccis_log_info("[devsn:%s]所使用Ukey(%s)尚未被注册！" , devsn , ukeysn);
		}
	}
	else
	{
		*ukeysign = false;
		ccis_log_err("[%s:%d]SQL查询错误！SQL返回码%d" , __FUNCTION__ , __LINE__ , retv);
	}

	if (q_ret->ptr)
		mysql_free_result(q_ret->ptr);
	q_ret->ptr	= NULL;

	//检测TPM注册状态
	sprintf(sql_condition , "devsn='%s'" , devsn);
	retv	= DB_Select_Data("update02" , "modename" , sql_condition , q_ret);
	if (retv == -1)
	{
		*tpmsign	= false;
		ccis_log_info("[devsn:%s]TPM证书尚未注册！" , devsn);
	}
	else if (retv == 0)
	{
		*tpmsign	= true;
		ccis_log_debug("[devsn:%s]TPM证书已经注册！" , devsn);
	}
	else
	{
		*tpmsign	= false;
		ccis_log_err("[%s:%d]SQL查询错误！SQL返回码%d" , __FUNCTION__ , __LINE__ , retv);
	}

clean_up:
	Do_Close();
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Compare_Version(const char* client_ver , const char* limit_ver , int sign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!client_ver)
		return -1;

	int retv	= 0;
	int cur_ver	= 0;
	int lim_ver	= 0;
	char* cur_pos	= client_ver;
	char* lim_pos	= limit_ver;

	while (!isdigit(*lim_pos) && *lim_pos != '\0')
		lim_pos ++;
	if (*lim_pos == '\0')
	{
		if (sign > 0)
			retv	= -1;
		else
			retv	= 1;
		goto clean_up;
	}

	while (!isdigit(*cur_pos) && *cur_pos != '\0')
		cur_pos ++;
	if (*cur_pos == '\0')
	{
		retv	= -1;
		goto clean_up;
	}

	while(*cur_pos != '\0' && *lim_pos != '\0')
	{
		cur_ver	= atoi(cur_pos);
		if (*lim_pos != '\0')
		{
			lim_ver	= atoi(lim_pos);
			while (*lim_pos != '\0' && *lim_pos != '.')
				lim_pos ++;
			if (*lim_pos == '.')
				lim_pos ++;
		}
		else
			lim_ver	= 0;

		if (*cur_pos != '\0')
		{
			cur_ver	= atoi(cur_pos);
			while (*cur_pos != '\0' && *cur_pos != '.')
				cur_pos ++;
			if (*cur_pos == '.')
				cur_pos ++;
		}
		else
			cur_ver	= 0;

		if (cur_ver < lim_ver)
		{
			retv	= -1;
			goto clean_up;
		}
		else if (cur_ver > lim_ver)
		{
			retv	= 1;
			goto clean_up;
		}
	}

clean_up:
	return retv;
}

int Version_Check(const char* client_ver , const char* lowlimit_ver , const char* uplimit_ver)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!client_ver || !lowlimit_ver || !uplimit_ver)
		return -1;

	if (Compare_Version(client_ver , lowlimit_ver , 0) < 0)	
		return -1;
	else if (Compare_Version(client_ver , uplimit_ver , 1) > 0)
		return 1;
	else
		return 0;
}

int Check_LoginStatus(const char* devsn)	//返回0表示允许登陆，返回1禁止登陆
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!devsn)
		return 0;

	int retv	= 0;
	pRing tmpring	= Find_Ring_Node(devsn);
	if (tmpring)
	{
		if (duplicate_login_action == 1)
		{
			ccis_log_notice("[devsn:%s]设备强制登陆，原登陆IP将被踢除！" , devsn);
			Free_Ring_Node(devsn);
			retv	= 0;
		}
		else if (duplicate_login_action == 0)
		{
			ccis_log_err("[devsn:%s]该设备序列号已在别处登陆！" , devsn);
			retv	= 1;
		}
	}

clean_up:
	return retv;
}
