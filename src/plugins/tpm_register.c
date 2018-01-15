#include "register.h"
#include "../other/ccis_thread.h"
#include "../log/ccis_log.h"
#include "../other/ccis_common.h"
#include "../server/server.h"
#include "../security/security.h"
#include "../configure/configure.h"
#include "../database/dbquery.h"
#include <curl/curl.h>
#include <htmlstreamparser.h>

void	TPM_Register(BSNMsg msg , Channel* ch , char* tpmsn);
int	Update_TPM_Sign(const char* devsn , int sign);
void	Auto_Register_TPM(TPMRegArgs* args);
extern int	Get_XSRFCode(char* xsrfcode);
extern size_t	write_callback(void* buffer , size_t size , size_t nmemb , void* hsp);
extern int	Post_Query_To_CA(const char* csrpath , const char* xsrfcode , char** pserialnum);
extern size_t	getSerial(char* str , size_t size , size_t nmemb , void* pserialnum);
int	Wait_For_TPMCert(Channel* ch , const char* devsn , const char* serialnum , char* tpmsn);
extern int	Get_CADB_Configure();
extern void	Free_CADB_Configure();
extern int	Remove_CRT_Head(const char* sourcefile , const char* desfile);

extern int conf_flag;

void TPM_Register(BSNMsg msg , Channel* ch , char* tpmsn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	BSNMsg response;
	char sql_condition[CCIS_SMALLSIZE];
	Query_Info* q_ret;
	memset (&response , 0 , sizeof(BSNMsg));
	response.head.type	= CCIS_TPM_REGISTER;
	int rep_sign	= 1;
	int rep_len	= sizeof(CTLMsg);
	char filepath[CCIS_PATHLEN];

	Do_Connect();
	sprintf(filepath , "/tmp/%s.csr" , msg.body.devsn);
	if (conf_flag == 0)
	{
		if (Get_CADB_Configure())
		{
			Free_CADB_Configure();
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_err("[devsn:%s]TPM自动注册失败：配置文件错误！" , msg.body.devsn);
			goto clean_up;
		}
	}

	//检测TPM注册状态
	q_ret	= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		response.head.errcode	= CCIS_UNKNOW_ERROR;
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	q_ret->ptr	= NULL;
	sprintf(sql_condition , "devsn='%s'" , msg.body.devsn);
	if (DB_Select_Data("update02" , "modename" , sql_condition , q_ret) != -1)
	{
		ccis_log_err("[devsn:%s]TPM自动注册失败：所使用设备TPM已经注册过！" , msg.body.devsn);
		response.head.errcode	= CCIS_TPM_ALREADY_REGISTED;
		goto clean_up;
	}

	if (msg.head.status == CCIS_PACKAGE_FINISHED)
	{
		TPMRegArgs* args	= (TPMRegArgs*)calloc(1 , sizeof(TPMRegArgs));
		if (!args)
		{
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
			goto clean_up;
		}
		args->ch	= ch;
		strcpy(args->filepath , filepath);
		strcpy(args->devsn , msg.body.devsn);
		args->tpmsn	= tpmsn;
		if (Create_ASync_Thread((void*)Auto_Register_TPM , (void*)args , NULL))
		{
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_err("[devsn:%s]TPM注册失败：线程无法创建，%s" , msg.body.devsn , strerror(errno));
			goto clean_up;
		}
		rep_sign	= 1;
		response.head.errcode	= CCIS_SUCCESS;
	}
	else
	{
		if (Write_File(filepath , msg.buffer , msg.body.bufLen , msg.head.status))
		{
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_err("[devsn:%s]TPM注册失败：csr文件写入失败！" , msg.body.devsn);
			goto clean_up;
		}
		rep_sign	= 0;
	}

clean_up:
	Do_Close();
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	if (rep_sign)
	{
		Write_Msg(ch->ssl , (void*)&response , rep_len);
	}
	return;
}

int Update_TPM_Sign(const char* devsn , int sign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	Do_Connect();
	char sql_condition[CCIS_SMALLSIZE];

	if (sign == CCIS_TPM_REGISTER_FAILED)
	{
		sprintf(sql_condition , "devsn='%s'" , devsn);
		retv	= DB_Delete_Data("update02" , sql_condition);
		if (retv)
		{
			ccis_log_err("[%s:%d]SQL删除失败：SQL错误码%d" , __FUNCTION__ , __LINE__ , retv);
			retv	= 1;
			goto clean_up;
		}
	}

clean_up:
	Do_Close();
	return retv;
}

void Auto_Register_TPM(TPMRegArgs* args)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int rep_sign	= 1;
	int rep_len	= sizeof(BSNMsg);
	BSNMsg response;
	response.head.type	= CCIS_TPM_REGISTER;

	char* xsrfcode	= (char*)calloc(CCIS_SMALLSIZE , sizeof(char*));
	char* serialnum	= NULL;

	if (!xsrfcode)
	{
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		response.head.errcode	= CCIS_UNKNOW_ERROR;
		goto clean_up;
	}

	if (Get_XSRFCode(xsrfcode))
	{
		ccis_log_err("[devsn:%s]TPM自动注册失败：无法获取XSRF码！" , args->devsn);
		response.head.errcode	= CCIS_UNKNOW_ERROR;
		goto clean_up;
	}

	if (Post_Query_To_CA(args->filepath , xsrfcode , &serialnum))
	{
		ccis_log_err("[devsn:%s]TPM自动注册失败：向CA提交注册请求失败！" , args->devsn);
		response.head.errcode	= CCIS_UNKNOW_ERROR;
		goto clean_up;
	}

	if (Wait_For_TPMCert(args->ch , args->devsn , serialnum , args->tpmsn))
	{
		ccis_log_err("[devsn:%s]TPM自动注册失败：获取TPM证书失败！" , args->devsn);
		response.head.errcode	= CCIS_UNKNOW_ERROR;
		goto clean_up;
	}
	rep_sign	= 0;

clean_up:
	if (rep_sign)
		Write_Msg(args->ch->ssl , (void*)&response , rep_len);
	if (xsrfcode)
		free(xsrfcode);
	if (serialnum)
		free(serialnum);

	free(args);
}

int Wait_For_TPMCert(Channel* ch , const char* devsn , const char* serialnum , char* tpmsn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	short connected	= 0;
	MYSQL CasqlConn;
	MYSQL ServsqlConn;
	MYSQL_RES *res_ptr	= NULL;
	MYSQL_ROW row;
	int sql_ret;
	FILE* certfp	= NULL;
	FILE* tmpcertfp	= NULL;
	char tmpcertpath[CCIS_PATHLEN];
	char certpath[CCIS_PATHLEN];
	char sql_command[CCIS_MIDSIZE];
	char tpmsha[CCIS_SMALLSIZE];
	BSNMsg response;

	mysql_init(&CasqlConn);
	if (ssl_connect)
	{
		mysql_ssl_set(&CasqlConn, server_private_key, server_cert, cacert, NULL, NULL);
	}
	if (!mysql_real_connect(&CasqlConn , cadb_ip , cadb_user , cadb_passwd , cadb_tablename , cadb_port , NULL , 0))
	{
		ccis_log_err("[devsn:%s]自动注册TPM证书失败：CA数据库连接失败！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	mysql_init(&ServsqlConn);
	if (ssl_connect)
	{
		mysql_ssl_set(&ServsqlConn, server_private_key, server_cert, cacert, NULL, NULL);
	}
	if (!mysql_real_connect(&ServsqlConn , db_ip , db_username , db_passwd , db_tablename , db_port , NULL , 0))
	{
		ccis_log_err("[devsn:%s]自动注册TPM证书失败：业务数据库连接失败！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	connected	= 1;

	sprintf(sql_command , "SELECT data FROM certificate WHERE data like '%%CSR_SERIAL=%s%%'" , serialnum);
	if (mysql_query(&CasqlConn , sql_command))
	{
		ccis_log_err("[devsn:%s]自动注册TPM证书失败：数据库查询错误！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	res_ptr	= mysql_store_result(&CasqlConn);

	int count	= 1;
	while (0 == (unsigned long) mysql_num_rows(res_ptr) && count < 21)
	{
		if (count == 20)
		{
			ccis_log_err("[devsn:%s]自动注册TPM证书失败：等待超时！" , devsn);
			retv	= 1;
			goto clean_up;
		}
		ccis_log_debug("[devsn:%s]第%d次获取证书失败！" , devsn , count ++);
		sleep(5);
		if (mysql_query(&CasqlConn , sql_command))
		{
			ccis_log_err("[devsn:%s]自动注册TPM证书失败：数据库查询错误！" , devsn);
			retv	= 1;
			goto clean_up;
		}
		res_ptr	= mysql_store_result(&CasqlConn);
	}
	ccis_log_debug("[devsn:%s]从CA获取自动注册TPM证书成功！" , devsn);
	sprintf(certpath , "/tmp/%s.crt" , devsn);
	sprintf(tmpcertpath , "/tmp/%s.tmp" , devsn);
	tmpcertfp	= fopen(tmpcertpath , "w+");
	if (!tmpcertfp)
	{
		ccis_log_err("[devsn:%s]自动注册TPM证书失败：证书文件打开失败！错误原因：%s" , devsn , strerror(errno));
		retv	= 1;
		goto clean_up;
	}

	while((row = mysql_fetch_row(res_ptr)) != NULL)
	{
		fputs(row[0] , tmpcertfp);
	}
	fflush(certfp);
	if (Remove_CRT_Head(tmpcertpath , certpath))
	{
		ccis_log_err("[devsn:%s]自动注册TPM证书失败：证书头移除失败！" , devsn);
		retv	= 1;
		goto clean_up;
	}

	ccis_log_info("[devsn:%s]TPM自动注册证书获取完成，证书地址：%s" , devsn , certpath);
	//获取证书SHA1码与SN号
	if (get_cert_serial(certpath , tpmsn))
	{
		ccis_log_err("[devsn:%s]TPM自动注册失败：无法获取证书序列号！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	if (GetSha1FromCert(certpath , tpmsha , CCIS_SMALLSIZE))
	{
		ccis_log_err("[devsn:%s]TPM自动注册失败：获取证书SHA1失败！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	sprintf(sql_command , "insert into update02 (tpmca,devsn,type,modename,certsn)values('%s','%s','1',(select modsn from (select * from dev02 where devsn='%s') as x),'%s')" , tpmsha , devsn , devsn , serialnum);
	if (mysql_query(&ServsqlConn , sql_command))
	{
		ccis_log_err("[devsn:%s]TPM自动注册失败：无法录入SHA1码！SQL错误码%d" , devsn , mysql_errno(&ServsqlConn));
		retv	= 1;
		goto clean_up;
	}


/*
	开始发送TPM证书给客户端
*/
	response.head.type	= CCIS_TPM_REGISTER;
	response.head.errcode	= CCIS_TPM_SEND_CERT;
	response.head .status	= CCIS_PACKAGE_FIRST;
	response.body.bufLen	= 0;
	Write_Msg(ch->ssl , (void*)&response , sizeof(CTLMsg));

	if (Send_File(ch->ssl , certpath , CCIS_TPM_REGISTER , CCIS_TPM_SEND_CERT , NULL))
	{
		ccis_log_err("[devsn:%s]TPM自动注册证书(%s)发送失败！" , devsn , certpath);
		retv	= 1;
		goto clean_up;
	}

/*
	TPM证书已经发送完毕，最后FINISH报文的buffer中应当附带MD5校验码
*/
	memset (&response , 0 , sizeof(BSNMsg));
	response.head.type	= CCIS_TPM_REGISTER;
	response.head.errcode	= CCIS_TPM_SEND_CERT;
	response.head.status	= CCIS_PACKAGE_FINISHED;
	Compute_File_MD5(certpath , response.buffer);
	response.body.bufLen	= strlen(response.buffer);
	
	Write_Msg(ch->ssl , (void*)&response , sizeof(BSNMsg));
	ccis_log_info("[devsn:%s]TPM自动注册证书已颁发完成！" , devsn);

clean_up:
	if (certfp)
		fclose(certfp);
	if (tmpcertfp)
		fclose(tmpcertfp);
	if (res_ptr)
		mysql_free_result(res_ptr);
	if (connected)
	{
		mysql_close(&CasqlConn);
		mysql_close(&ServsqlConn);
	}
	return retv;
}
