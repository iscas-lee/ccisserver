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
#include <stdbool.h>

int conf_flag;

void	Ukey_Register(BSNMsg msg , Channel* ch , EVP_PKEY* tpm_key);
int	Update_UR_Sign(const char* ukeysn , int sign);
void	Auto_Register_UK(UKRegArgs* args);
int	Get_XSRFCode(char* xsrfcode);
size_t	write_callback(void* buffer , size_t size , size_t nmemb , void *hsp);
int	Post_Query_To_CA(const char* csrpath , const char* xsrfcode , char** pserialnum);
size_t	getSerial(char* str , size_t size , size_t nmemb , void* pserialnum);
int	Wait_For_UKCert(Channel* ch , const char* ukeysn , const char* devsn , const char* serialnum , const EVP_PKEY* tpm_key);
int	Get_CADB_Configure();
void	Free_CADB_Configure();
void	Change_Ukey_PIN(char* ukeypin);
int	Remove_CRT_Head(const char* sourcefile , const char* desfile);

void Ukey_Register(BSNMsg msg , Channel* ch , EVP_PKEY* tpm_key)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	BSNMsg response;
	memset (&response , 0 , sizeof(BSNMsg));
	response.head.type	= CCIS_UKEY_REGISTER;
	int rep_sign	= 1;
	int rep_len	= sizeof(CTLMsg);
	char filepath[CCIS_PATHLEN];
	char ukeysn[UKEYSN_LEN];
	sprintf(filepath , "/tmp/%s.csr" , msg.body.devsn);
	if (conf_flag == 0)
	{
		if (Get_CADB_Configure())
		{
			Free_CADB_Configure();
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_err("[devsn:%s]Ukey自动注册失败：配置文件错误！" , msg.body.devsn);
			goto clean_up;
		}
	}

	if (msg.head.status == CCIS_PACKAGE_FIRST)		//验证buffer中的ukeysn是否在数据库中登记
	{
		Do_Connect();
		char sql_condition[CCIS_SMALLSIZE];
		strncpy(ukeysn , msg.body.reseve , UKEYSN_LEN);
		sprintf(sql_condition , "ukeysn='%s'" , ukeysn);
		Query_Info* q_ret	= (Query_Info*)malloc(sizeof(Query_Info));
		if (!q_ret)
		{
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
			Do_Close();
			goto clean_up;
		}
		memset(q_ret , 0 , sizeof(Query_Info));
		if (DB_Select_Data("type21" , "regsign" , sql_condition , q_ret) != 0)
		{
			response.head.errcode	= CCIS_UR_NO_SUCH_UKEY;
			ccis_log_err("[devsn:%s]Ukey注册失败：Ukey(%s)尚未登记！" , msg.body.devsn , msg.buffer);
			Do_Close();
			if (q_ret->ptr)
				mysql_free_result(q_ret->ptr);
			free(q_ret);
			goto clean_up;
		}
		if (q_ret->res_data[0][0] && (strcmp(q_ret->res_data[0][0] , "2") == 0))
		{
			response.head.errcode	= CCIS_UR_ALREADY_REGISTED;
			ccis_log_err("[devsn:%s]Ukey自动注册失败：该设备(%s)已经被注册过！" , msg.body.devsn , msg.buffer);
			Do_Close();
			if (q_ret->ptr)
				mysql_free_result(q_ret->ptr);
			free(q_ret);
			goto clean_up;
		}

		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
		Do_Close();

		if (Write_File(filepath , msg.buffer , msg.body.bufLen , CCIS_PACKAGE_FIRST))
		{
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_err("[devsn:%s]Ukey注册失败：csr文件创建失败！" , msg.body.devsn);
			goto clean_up;
		}
		rep_sign	= 0;
	}
	else if (msg.head.status == CCIS_PACKAGE_UNFINISHED)	//循环接收csr文件，文件名：%devsn%.csr
	{
		if (Write_File(filepath , msg.buffer , msg.body.bufLen , CCIS_PACKAGE_UNFINISHED))
		{
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_err("[devsn:%s]Ukey注册失败：csr文件写入失败！" , msg.body.devsn);
			goto clean_up;
		}
		rep_sign	= 0;
	}
	else if (msg.head.status == CCIS_PACKAGE_FINISHED)	//csr文件接收完毕，创建线程，参数为csr文件地址和对端SSL通道fd，在线程中负责等待CA回复以及回包给客户端
	{
		UKRegArgs* args	= (UKRegArgs*)malloc(sizeof(UKRegArgs));
		if (!args)
		{
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
			goto clean_up;
		}
		memset (args , 0 , sizeof(UKRegArgs));
		args->ch	= ch;
		args->tpm_key	= tpm_key;
		strcpy(args->filepath , filepath);
		strcpy(args->ukeysn , msg.body.reseve);
		strcpy(args->devsn , msg.body.devsn);
		if (Create_ASync_Thread((void*)Auto_Register_UK , (void*)args , NULL))
		{
			response.head.errcode	= CCIS_UNKNOW_ERROR;
			ccis_log_err("[devsn:%s]Ukey注册失败：线程无法创建，%s" , msg.body.devsn , strerror(errno));
			goto clean_up;
		}
		rep_sign	= 1;
		response.head.errcode	= CCIS_SUCCESS;
	}

clean_up:
	if (rep_sign)
	{
		Write_Msg(ch->ssl , (void*)&response , rep_len);
	}
	return;
}

int Update_UR_Sign(const char* ukeysn , int sign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	Do_Connect();
	char sql_command[CCIS_MIDSIZE] = {0};
	char sql_condition[CCIS_SMALLSIZE]	= {0};

	if (sign == CCIS_UR_REGISTER_SUCCESS)
		//sprintf(sql_command , "pin=(select newpin from (select * from type21 where ukeysn='%s') as x) , newpin='' , regsign='2'" , ukeysn);
		sprintf(sql_command , \
			"pin=(case when newpin is not NULL and newpin <> '' then newpin when newpin is NULL or newpin = '' then pin end) , newpin='' , regsign='2'");
	else
		sprintf(sql_command , "newpin='',regsign='0'");
	sprintf(sql_condition , "ukeysn='%s'" , ukeysn);
	retv	= DB_Update_Data("type21" , sql_command , sql_condition);
	if (retv)
		ccis_log_err("[%s:%d]SQL更新表错误！SQL返回码：%d" , __FUNCTION__ , __LINE__ , retv);

clean_up:
	Do_Close();
	return retv;
}

void Auto_Register_UK(UKRegArgs* args)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int rep_sign	= 1;
	int rep_len	= sizeof(BSNMsg);
	BSNMsg response;
	response.head.type	= CCIS_UKEY_REGISTER;

	char* xsrfcode	= malloc(sizeof(char) * CCIS_SMALLSIZE);
	char* serialnum	= NULL;
	
	if (!xsrfcode)
	{
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		response.head.errcode	= CCIS_UNKNOW_ERROR;
		goto clean_up;
	}

	if (Get_XSRFCode(xsrfcode))
	{
		ccis_log_err("[devsn:%s]UKey自动注册失败：无法获取XSRF码！" , args->devsn);
		response.head.errcode	= CCIS_UNKNOW_ERROR;
		goto clean_up;
	}

	if (Post_Query_To_CA(args->filepath , xsrfcode , &serialnum))
	{
		ccis_log_err("[devsn:%s]UKey自动注册失败：向CA提交注册请求失败！" , args->devsn);
		response.head.errcode	= CCIS_UNKNOW_ERROR;
		goto clean_up;
	}


	if (Wait_For_UKCert(args->ch , args->ukeysn , args->devsn , serialnum , args->tpm_key))
	{
		ccis_log_err("[devsn:%s]UKey自动注册失败：获取Ukey证书失败！" , args->devsn);
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

int Get_XSRFCode(char* xsrfcode)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	CURL *curl;
	HTMLSTREAMPARSER *hsp;
	int retv	= 0;
	char tag[1] , attr[4] , val[128];

	curl	= curl_easy_init();
	hsp	= html_parser_init();
	if (!curl || !hsp)
	{
		ccis_log_err("CURL/HSP初始化失败！");
		retv	= 1;
		goto clean_up;
	}

	html_parser_set_tag_to_lower(hsp, 1);
	html_parser_set_attr_to_lower(hsp, 1);
	html_parser_set_tag_buffer(hsp, tag, sizeof(tag));
	html_parser_set_attr_buffer(hsp, attr, sizeof(attr));
	html_parser_set_val_buffer(hsp, val, sizeof(val)-1);

	curl_easy_setopt(curl, CURLOPT_URL, ca_regaddr);
	curl_easy_setopt(curl , CURLOPT_SSL_VERIFYPEER , false);
	curl_easy_setopt(curl , CURLOPT_SSL_VERIFYHOST , true);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION , write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, hsp);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

	curl_easy_perform(curl);

	strncpy(xsrfcode , html_parser_val(hsp) + 61 , CCIS_SMALLSIZE);
	ccis_log_debug("获得CA XSRF码：%s" , xsrfcode);

clean_up:
	if (curl)
		curl_easy_cleanup(curl);
	if (hsp)
		html_parser_cleanup(hsp);
	return retv;
}

size_t write_callback(void* buffer , size_t size , size_t nmemb , void *hsp)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	size_t realsize = size * nmemb, p;
	for(p = 0; p < realsize; p++)
	{
		html_parser_char_parse(hsp, ((char *)buffer)[p]);
		if(html_parser_cmp_tag(hsp, "a", 1))
			if(html_parser_cmp_attr(hsp, "href", 4))
				if(*html_parser_val(hsp) == 112)
					if(html_parser_is_in(hsp, HTML_VALUE_ENDED))
					{
						html_parser_val(hsp)[html_parser_val_length(hsp)] = '\0';
					}
	}
	return realsize;
}

int Post_Query_To_CA(const char* csrpath , const char* xsrfcode , char** pserialnum)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	CURL* curl;
	CURLcode res;
	int retv	= 0;

	struct curl_httppost *formpost	= NULL;
	struct curl_httppost *lastptr	= NULL;
	struct curl_slist *headerlist	= NULL;

	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "request" , CURLFORM_FILECONTENT , csrpath , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "ra" , CURLFORM_COPYCONTENTS , "Trustcenter itself" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "role" , CURLFORM_COPYCONTENTS , "User" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "loa" , CURLFORM_COPYCONTENTS , "Medium" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "passwd1" , CURLFORM_COPYCONTENTS , "123123" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "passwd2" , CURLFORM_COPYCONTENTS , "123123" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "ADDITIONAL_ATTRIBUTE_REQUESTERCN" , CURLFORM_COPYCONTENTS , "kylin" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "ADDITIONAL_ATTRIBUTE_EMAIL" , CURLFORM_COPYCONTENTS , "admin@kylinos.cn" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "ADDITIONAL_ATTRIBUTE_DEPARTMENT" , CURLFORM_COPYCONTENTS , "11" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "ADDITIONAL_ATTRIBUTE_TELEPHONE" , CURLFORM_COPYCONTENTS , "15555555555" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "ADDITIONAL_ATTRIBUTE_SUBJECT_ALT_NAME_DNS.1" , CURLFORM_COPYCONTENTS , "8.8.8.8" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "ADDITIONAL_ATTRIBUTE_SUBJECT_ALT_NAME_DNS.2" , CURLFORM_COPYCONTENTS , "114.114.114.114" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "ADDITIONAL_ATTRIBUTE_SUBJECT_ALT_NAME_IP.1" , CURLFORM_COPYCONTENTS , "127.0.0.1" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "ADDITIONAL_ATTRIBUTE_SUBJECT_ALT_NAME_IP.2" , CURLFORM_COPYCONTENTS , "192.168.0.1" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "cmd" , CURLFORM_COPYCONTENTS , "pkcs10_req" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "autoRegist" , CURLFORM_COPYCONTENTS , "yes" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "operation" , CURLFORM_COPYCONTENTS , "server-confirmed-form" , CURLFORM_END);
	curl_formadd(&formpost , &lastptr , CURLFORM_COPYNAME , "xsrf_protection_token" , CURLFORM_COPYCONTENTS , xsrfcode , CURLFORM_END);
	
	curl	= curl_easy_init();
	if (!curl)
	{
		ccis_log_err("自动注册失败：curl初始化失败！");
		retv	= 1;
		goto clean_up;
	}

	curl_easy_setopt(curl , CURLOPT_URL , ca_regaddr);		//CA_REGADDR为配置项
	curl_easy_setopt(curl , CURLOPT_HTTPPOST , formpost);
	curl_easy_setopt(curl , CURLOPT_WRITEFUNCTION , getSerial);
	curl_easy_setopt(curl , CURLOPT_WRITEDATA , pserialnum);
	curl_easy_setopt(curl , CURLOPT_SSL_VERIFYPEER , false);
	curl_easy_setopt(curl , CURLOPT_SSL_VERIFYHOST , true);

	res	= curl_easy_perform(curl);
	if (res != CURLE_OK)
	{
		ccis_log_err("自动注册失败：curl_perform err，%s" , curl_easy_strerror(res));
		retv	= 1;
		goto clean_up;
	}
	if (*pserialnum)
		ccis_log_debug("获取到证书序列号：%s" , *pserialnum);
	else
	{
		ccis_log_err("获取证书序列号失败！");
		retv	= 1;
	}

clean_up:
	if (curl)
		curl_easy_cleanup(curl);
	if (formpost)
		curl_formfree(formpost);
	if (headerlist)
		curl_slist_free_all(headerlist);
	return retv;
}

size_t getSerial(char* str , size_t size , size_t nmemb , void* pserialnum)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	char* res;
	char* tmp;
	res	= strstr(str , "serial");
	if (res != NULL)
	{
		*(char**)pserialnum	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
		if (!*(char**)pserialnum)
		{
			ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
			goto clean_up;
		}
		tmp	= strtok(res , " ");
		tmp	= strtok(NULL , " ");
		strncpy(*(char**)pserialnum , tmp , CCIS_SMALLSIZE);
	}
clean_up:
	return size*nmemb;
}


int Wait_For_UKCert(Channel* ch , const char* ukeysn , const char* devsn , const char* serialnum , const EVP_PKEY* tpm_key)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	MYSQL CasqlConn;
	MYSQL ServsqlConn;
	short connected	= 0;
	MYSQL_RES *res_ptr	= NULL;
	MYSQL_ROW row;
	FILE* certfp	= NULL;
	FILE* tmpcertfp	= NULL;
	char certpath[CCIS_PATHLEN];
	char tmpcertpath[CCIS_PATHLEN];
	char sql_command[CCIS_MIDSIZE];
	char ukeypin[7];
	BSNMsg response;

	mysql_init(&CasqlConn);
	if (ssl_connect)
	{
		mysql_ssl_set(&CasqlConn, server_private_key, server_cert, cacert, NULL, NULL);
	}
	if (!mysql_real_connect(&CasqlConn , cadb_ip , cadb_user , cadb_passwd , cadb_tablename , cadb_port , NULL , 0))
	{
		ccis_log_err("[devsn:%s]自动注册Ukey证书失败：CA数据库连接失败！" , devsn);
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
		ccis_log_err("[devsn:%s]自动注册Ukey证书失败：业务数据库连接失败！" , devsn);
		retv	= 1;
		goto clean_up;
	}

	connected	= 1;
	
	sprintf(sql_command , "SELECT data FROM certificate WHERE data like '%%CSR_SERIAL=%s%%'" , serialnum);
	if (mysql_query(&CasqlConn , sql_command))
	{
		ccis_log_err("[devsn:%s]自动注册Ukey证书失败：数据库查询错误！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	res_ptr	= mysql_store_result(&CasqlConn);

	int count	= 1;
	while (0 == (unsigned long) mysql_num_rows(res_ptr) && count < 21)
	{
		if (count == 20)
		{
			ccis_log_err("[devsn:%s]自动注册Ukey证书失败：等待超时！" , devsn);
			retv	= 1;
			goto clean_up;
		}
		ccis_log_debug("[devsn:%s]第%d次获取证书失败！" , devsn , count ++);
		sleep(5);
		if (mysql_query(&CasqlConn , sql_command))
		{
			ccis_log_err("[devsn:%s]自动注册Ukey证书失败：数据库查询错误！" , devsn);
			retv	= 1;
			goto clean_up;
		}
		res_ptr	= mysql_store_result(&CasqlConn);
	}

	ccis_log_debug("[devsn:%s]从CA获取自动注册Ukey证书成功！" , devsn);
	sprintf(certpath , "/tmp/%s.crt" , ukeysn);
	sprintf(tmpcertpath , "/tmp/%s.tmp" , ukeysn);

	tmpcertfp = fopen(tmpcertpath , "w+");
	if (!tmpcertfp)
	{
		ccis_log_err("[devsn:%s]自动注册UKey证书失败：证书文件打开失败！错误原因：%s" , devsn , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	while ((row = mysql_fetch_row(res_ptr)) != NULL)
	{
		fputs(row[0] , tmpcertfp);
	}
	fflush(tmpcertfp);
	if (Remove_CRT_Head(tmpcertpath , certpath))
	{
		ccis_log_err("[devsn:%s]Ukey自动注册证书颁发失败：证书头移除失败！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	ccis_log_info("[devsn:%s]Ukey自动注册证书获取完成，证书地址：%s" , devsn , certpath);

/*
	Ukey证书已从CA获取到本地，开始发送给客户端
*/
	response.head.type	= CCIS_UKEY_REGISTER;
	response.head.errcode	= CCIS_UR_SEND_CERT;
	response.head.status	= CCIS_PACKAGE_FIRST;
	response.body.bufLen	= 0;
	Write_Msg(ch->ssl , (void*)&response , sizeof(CTLMsg));

	if (Send_File(ch->ssl , certpath , CCIS_UKEY_REGISTER , CCIS_UR_SEND_CERT , NULL))
	{
		ccis_log_err("[devsn:%s]Ukey自注册证书(%s)发送失败！" , devsn , certpath);
		retv	= 1;
		goto clean_up;
	}

	memset (&response , 0 , sizeof(BSNMsg));
	Change_Ukey_PIN(ukeypin);
	response.head.type	= CCIS_UKEY_REGISTER;
	response.head.errcode	= CCIS_UR_SEND_CERT;
	response.head.status	= CCIS_PACKAGE_FINISHED;

/*
	Ukey证书已经发送给客户端，并且PIN码已修改，现在更新数据库，将新的pin码暂存到type21的newpin字段，标记registered字段为已颁发(1)
*/
	sprintf(sql_command , "update type21 set newpin ='%s',certsn='%s',regsign='1' where ukeysn ='%s'" , ukeypin , serialnum , ukeysn);
	if (mysql_query(&ServsqlConn , sql_command))
	{
		ccis_log_alert("[devsn:%s]Ukey(%s) PIN码未能修改：数据库错误！" , devsn , ukeysn);
		strcpy(ukeypin , "123456");
	}
	ccis_log_debug("[devsn:%s]Ukey(%s) PIN码已修改为：%s" , devsn , ukeysn , ukeypin);
	
	if (Encrypt_String_By_Server(tpm_key , ukeypin , response.buffer , &(response.body.bufLen)))
	{
		ccis_log_err("[devsn:%s]Ukey(%s)自动注册证书颁发失败：PIN码加密失败！" , devsn , ukeysn);
		response.head.errcode	= CCIS_UNKNOW_ERROR;
		retv	= 1;
		goto clean_up;
	}
	Write_Msg(ch->ssl , (void*)&response , sizeof(BSNMsg));

	ccis_log_info("[devsn:%s]自注册Ukey(%s)证书已颁发完成！" , devsn , ukeysn);

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

int Get_CADB_Configure()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	conf_flag	= 1;
	int retv	= 0;
	char* tmp_user;
	char* tmp_passwd;

	if (!keyFile)
	{
		keyFile = g_key_file_new();
		if (!keyFile)
		{
			ccis_log_alert("配置文件句柄创建失败！");
			retv	= 1;
			goto clean_up;
		}
	}

	if (!g_file_test(CONF_FILE_PATH , G_FILE_TEST_EXISTS))
	{
		printf("配置文件不存在！\n");
		ccis_log_emerg("配置文件丢失！");
		retv	= 1;
		goto clean_up;
	}

	ca_regaddr	= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "UKEYREG" , "CA_REGADDR");
	if (!ca_regaddr)
	{
		ccis_log_err("Ukey自动注册配置项缺失！");
		retv	= 1;
		goto clean_up;
	}
	cadb_ip		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "UKEYREG" , "CADB_IP");
	if (!cadb_ip)
	{
		ccis_log_err("Ukey自动注册配置项缺失！");
		retv	= 1;
		goto clean_up;
	}
	tmp_user	= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "UKEYREG" , "CADB_USER");
	if (!tmp_user)
	{
		ccis_log_err("Ukey自动注册配置项缺失！");
		retv	= 1;
		goto clean_up;
	}
	tmp_passwd	= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "UKEYREG" , "CADB_PASSWD");
	if (!tmp_passwd)
	{
		ccis_log_err("Ukey自动注册配置项缺失！");
		retv	= 1;
		goto clean_up;
	}
	cadb_tablename	= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "UKEYREG" , "CADB_TALBENAME");
	if (!cadb_tablename)
	{
		ccis_log_err("Ukey自动注册配置项缺失！");
		retv	= 1;
		goto clean_up;
	}
	cadb_port	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "UKEYREG" , "CADB_PORT");
	if (cadb_port <1 || cadb_port > 65535)
		cadb_port	= 80;

	cadb_user	= malloc(128);
	cadb_passwd	= malloc(128);

	if (Base64_Decode(tmp_user , strlen(tmp_user) , cadb_user , 128))
	{
		ccis_log_err("CA数据库用户名解密失败！");
		retv	= 1;
		goto clean_up;
	}
	if (Base64_Decode(tmp_passwd , strlen(tmp_passwd) , cadb_passwd , 128))
	{
		ccis_log_err("CA数据库密码解密失败！");
		retv	= 1;
		goto clean_up;
	}

clean_up:
	if (retv)
		Free_CADB_Configure();
	if (tmp_user)
		free(tmp_user);
	if (tmp_passwd)
		free(tmp_passwd);
	return retv;
}

void Free_CADB_Configure()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	conf_flag	= 0;
	if (ca_regaddr)
		free(ca_regaddr);
	if (cadb_ip)
		free(cadb_ip);
	if (cadb_user)
		free(cadb_user);
	if (cadb_passwd)
		free(cadb_passwd);
	if (cadb_tablename)
		free(cadb_tablename);
	ca_regaddr	= NULL;
	cadb_ip		= NULL;
	cadb_user	= NULL;
	cadb_passwd	= NULL;
	cadb_tablename	= NULL;
}

void Change_Ukey_PIN(char* ukeypin)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	srand(time(NULL));
	sprintf(ukeypin , "%d" , rand()%900000 + 100000);
}

int Remove_CRT_Head(const char* sourcefile , const char* desfile)
{
	if (!sourcefile || !desfile)
		return -1;

	int retv	= 0;
	FILE* sourcefp	= fopen(sourcefile , "r");
	FILE* desfp	= fopen(desfile , "w");
	char buffer[CCIS_MAXSIZE]	= {0};

	if (!sourcefp || !desfp)
	{
		ccis_log_err("证书(%s)头内容去除失败：文件打开失败！错误原因：%s" , sourcefile , strerror(errno));
		retv	= 1;
		goto clean_up;
	}

	int i	= 0;
	while (fgets(buffer , CCIS_MAXSIZE , sourcefp) != NULL)
	{
		if (++i > 7)
			fputs(buffer , desfp);
		memset (buffer , 0 , CCIS_MAXSIZE * sizeof(char));
	}

clean_up:
	if (sourcefp)
		fclose(sourcefp);
	if (desfp)
		fclose(desfp);
	return retv;
}
