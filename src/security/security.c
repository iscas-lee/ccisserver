#include "security.h"
#include "openssl/md5.h"
#include "../log/ccis_log.h"
#include "../database/dbquery.h"
#define NON_MAIN
#include "ca/apps.h"
#undef NON_MAIN

/*******ONLY FOR PBC********/
#define MDLEN	16
#define CHARSIZE	26
#define INTSIZE	10
/***************************/

int	Compute_String_MD5(const char* string , char* result);		//计算字符串MD5值
int	Compute_File_MD5(const char* filepath , char* result);		//计算文件MD5值
int	Decrypt_String_By_Server(char* pk_path , char* str , char* result , int len_in , int* len_out);			//服务端解密字符串
int	Encrypt_String_By_Server(EVP_PKEY* prikey , char* input , char* output , int* len_out);	//服务端加密字符串
int	Base64_Encode(char *input, int len_in, char *output, int len_out);		//base64加密
int	Base64_Decode(char *input, int len_in, char *output, int len_out);		//base64解密
RSA*	Read_RSA_From_PEM(char* pk_path);
int	Make_MD5_For_PBC(char *pcFlag, int iLen, char *pcSour, char *pcDest);	//征信特供MD5计算函数
void	MD5Digest(char *pszInput, char *pszOutPut);			//征信计算MD5核心函数
int	Store_New_Password(pRing ring);					//存储新的征信密码
int	GetSha1FromCert(const char* certpath , char* result , int outlen);	//计算证书SHA1值

int Compute_String_MD5(const char* string , char* result)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (string == NULL || result == NULL)
	{
	//	LOGGER(0 , "service" , "计算字符串MD5值失败：原字符串不可为空！");
		return -1;
	}
        unsigned char md5_value[16];
        MD5_CTX md5;
        if (MD5_Init(&md5))
	{
		if (MD5_Update(&md5 , string , strlen(string)))
		{
			if (MD5_Final(md5_value , &md5))
			{
				for (int i = 0 ; i < 16 ; i ++)
                			snprintf(result + i * 2 , 2 + 1 , "%02x" , md5_value[i]);
        			result[32]      = '\0';
				return 0;
			}
			else
			{
	//			LOGGER(0 , "service" , "计算字符串MD5值失败：MD5_Final Failed");
				return -1;
			}
		}
		else
		{
	//		LOGGER(0 , "service" , "计算字符串MD5值失败：MD5_Update Failed");
			return -1;
		}
	}
	else
	{
	//	LOGGER(0 , "service" , "计算字符串MD5值失败：MD5_Init Failed");
	}
	return -1;
		
}

int Compute_File_MD5(const char* filepath , char* result)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!filepath || result == NULL)
	{
//		LOGGER(0 , "service" , "无法计算文件MD5：文件路径不可为空！");
		printf("无法计算文件MD5：文件路径不可为空！\n");
		return -1;
	}
	FILE* fp	= fopen(filepath , "r");
	if (!fp)
	{
//		LOGGER(0 , "service" , "无法计算文件MD5：文件无法打开！文件路径：%s，错误码：%d" , filepath , errno);
		printf("无法计算文件MD5：文件无法打开！文件路径：%s，错误码：%d\n" , filepath , errno);
		return -1;
	}
	unsigned char data[MAXSIZE];
	unsigned char md5_value[16];
	MD5_CTX md5;
	if (MD5_Init(&md5) != 1)
	{
//		LOGGER(0 , "service" , "无法计算文件MD5：MD5_Init Failed");
		fclose(fp);
		return -1;
	}
	while (1)
	{
		int ret	= fread(data , sizeof(char) , MAXSIZE , fp);
		if (ret == -1)
		{
//			LOGGER(0 , "service" , "无法计算文件MD5：文件读取失败！文件路径：%s，错误码：%d" , filepath , errno);
			fclose(fp);
			return -1;
		}
		if (MD5_Update(&md5 , data , ret) != 1)
		{
//			LOGGER(0 , "service" , "无法计算文件MD5：MD5_Update Failed");
			fclose(fp);
			return -1;
		}
		if (ret == 0 || ret < MAXSIZE)
		{
			break;
		}
	}
	fclose(fp);
	if (MD5_Final(md5_value , &md5) != 1)
	{
//		LOGGER(0 , "service" , "无法计算文件MD5：MD5_Final Failed");
		return -1;
	}
	for (int i = 0 ; i < 16 ; i ++)
	{
		snprintf(result + i * 2 , 2 + 1 , "%02x" , md5_value[i]);
	}
	result[32]	= '\0';
	return 0;
	
}

int Decrypt_String_By_Server(char* pk_path , char* str , char* result , int len_in , int* len_out)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	RSA* server_rsa		= Read_RSA_From_PEM(pk_path);
	if (!server_rsa)
	{
		printf("RSA 提取失败！\n");
		retv	= 1;
		goto clean_up;
	}

	retv	= server_decrypt_long_data(str , len_in , result , server_rsa);
clean_up:
	if (server_rsa)
		RSA_free(server_rsa);
	return retv;
}

int Encrypt_String_By_Server(EVP_PKEY* prikey , char* input , char* output , int* len_out)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!prikey || !input || !output || !len_out)
	{
		return 1;
	}

	*len_out	= server_encrypt_long_data(input , output , prikey->pkey.rsa);
	if (*len_out <= 0)
	{
		printf("encrypt failed\n");
		return 1;
	}

#ifdef DEBUG
	printf("加密后长度：%d\n" , *len_out);
#endif
	return 0;
}

int Base64_Encode(char* input , int len_in , char* output , int len_out)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	BIO* pstBase64	= NULL;
	BIO* pstBMem	= NULL;
	BUF_MEM* pstBMemPtr	= NULL;

	if (!input || !output)
		return -1;

	pstBase64	= BIO_new(BIO_f_base64());
	BIO_set_flags(pstBase64 , BIO_FLAGS_BASE64_NO_NL);

	pstBMem		= BIO_new(BIO_s_mem());
	pstBase64	= BIO_push(pstBase64 , pstBMem);
	BIO_write(pstBase64 , input , len_in);
	BIO_flush(pstBase64);
	BIO_get_mem_ptr(pstBase64 , &pstBMemPtr);

	if (pstBMemPtr->length > len_out)
	{
		printf("Output Space not enough \n");
		retv	= 1;
		goto clean_up;
	}

	strncpy(output , pstBMemPtr->data , pstBMemPtr->length);

clean_up:
	BIO_free_all(pstBase64);
	return retv;
}

int Base64_Decode(char* input , int len_in , char* output , int len_out)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	int iReadLen	= 0;
	BIO* pstBase64	= NULL;
	BIO* pstBMem	= NULL;

	if (!input || !output)
		return -1;

	pstBase64	= BIO_new(BIO_f_base64());
	BIO_set_flags(pstBase64 , BIO_FLAGS_BASE64_NO_NL);

	pstBMem		= BIO_new_mem_buf(input , len_in);
	pstBMem		= BIO_push(pstBase64 , pstBMem);
	iReadLen	= BIO_read(pstBMem , output , len_in);		//warning

	if (iReadLen > len_out)
	{
		printf("Out Space not enough\n");
		retv	= 1;
		goto clean_up;
	}
	output[iReadLen] = '\0';

clean_up:
	BIO_free_all(pstBMem);
	return retv;
}

RSA* Read_RSA_From_PEM(char* pk_path)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	RSA* result	= NULL;
	FILE* fp	= NULL;
	if (!pk_path)
		return NULL;

	fp	= fopen(pk_path , "r");
	if (!fp)
		goto clean_up;

	result	= PEM_read_RSAPrivateKey(fp , NULL , NULL , PRIVATEKEY_PWD);

clean_up:
	if (fp)
		fclose(fp);
	return result;
}

int Make_MD5_For_PBC(char *pcFlag, int iLen, char *pcSour, char *pcDest) {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRelt = 0;
    char acRand[iLen + 1];
    char acTemp[BUFSIZE];
    unsigned char aucMD5[MDLEN];

    memset(acTemp, 0, BUFSIZE);
    memset(acRand, 0, iLen + 1);
    srand((unsigned) time(NULL));
    for (int i = 0; i < iLen; i++) {
        switch (pcFlag[i]) {
            case '0':
                acRand[i] = 'A' + rand() % CHARSIZE;
                break;
            case '1':
                acRand[i] = 'a' + rand() % CHARSIZE;
                break;
            case '2':
                acRand[i] = '0' + rand() % INTSIZE;
                break;
            default:
                acRand[i] = 'x';
                iRelt = 1;
                break;
        }
    }

    strcpy(acTemp, acRand);
    strcat(acTemp, pcSour);
    strcpy(pcDest, acRand);
    //Compute_String_MD5(acTemp, aucMD5);
	MD5Digest(acTemp , aucMD5);
    for (int i = 0; i < MDLEN; i++) {
        sprintf(acRand, "%02x", aucMD5[i]);
        strcat(pcDest, acRand);
    }

    return iRelt;
}

void MD5Digest(char *pszInput, char *pszOutPut)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	MD5_CTX mcContext;
	unsigned int iLen = strlen(pszInput);

	MD5_Init(&mcContext);
	MD5_Update(&mcContext, (unsigned char *) pszInput, iLen);
	MD5_Final((unsigned char *) pszOutPut, &mcContext);
}

/*int Check_Cert_In_CA(char* certfile)
{
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
*/
int Store_New_Password(pRing ring)	//status=1表示服务端已获取新密码，未更新至客户端。reason=1表示由于过期自动触发
{
	if (!ring)
		return -1;

	int retv	= 0;
	char* sql_command	= NULL;
	char base64_pwd[CCIS_MIDSIZE];
	Do_Connect();
	memset (base64_pwd , 0 , sizeof(char) * CCIS_MIDSIZE);
	if (Base64_Encode(ring->pbcinfo.Pwd , strlen(ring->pbcinfo.Pwd) , base64_pwd , CCIS_MIDSIZE))
	{
		ccis_log_alert("账号[%s]密码加密失败！无法存储至数据库！" , ring->pbcinfo.User);
		retv	= 1;
		goto clean_up;
	}
	sql_command	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_command)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	sprintf(sql_command , "'%s','%s','%s','%s','%s','%d','%d','%s'" , ring->pbcinfo.Orgid , ring->devsn , ring->ukeysn , ring->pbcinfo.User , base64_pwd , 1 , 1 , "CCISServer");	//reason==1表示密码过期因此重新分配密码
	retv	= DB_Insert_Data("org03" , "orgid,devsn,ukeysn,usrid,usrpwd,status,reason,operator" , sql_command);
	if (retv)
		ccis_log_emerg("[%s:%d]SQL插入失败！SQL返回值：%d" , __FUNCTION__ , __LINE__ , retv);

clean_up:
	Do_Close();
	if (sql_command)
		free(sql_command);
	return retv;
}

int GetSha1FromCert(const char* certpath , char* result , int output_len)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!certpath || !result)
		return -1;
	int retv	= 0;
	unsigned char cMin	= 0;
	unsigned char cMax	= 0;
	unsigned short iNum	= 0;
	unsigned char *cMd5	= NULL;

	X509* pstTemp	= load_cert(NULL , certpath , FORMAT_PEM , NULL , NULL , "certificate");
	if (pstTemp)
	{
		X509_digest(pstTemp , EVP_sha1() , pstTemp->sha1_hash , NULL);
		memset (result , 0 , output_len * sizeof(char));
		cMd5	= pstTemp->sha1_hash;
		if (!cMd5)
		{
			ccis_log_err("X509_digest Error !");
			retv	= 1;
			goto clean_up;
		}
		for (int i = 0 ; i < SHA_DIGEST_LENGTH ; i ++)
		{
			iNum	= *(cMd5 + i);
			cMin	= iNum % 16;
			cMax	= iNum / 16;
			if (cMin >= 10)
				cMin	= cMin - 10 + 'a';
			else
				cMin	= cMin + '0';

			if (cMax >= 10)
				cMax	= cMax - 10 + 'a';
			else
				cMax	= cMax + '0';
			
			*(result + ((i << 1) + 1))	= cMin;
			*(result + ((i << 1) + 0))	= cMax;
		}
	}
	else
	{
		retv	= 1;
		ccis_log_err("获取证书X509失败！");
		goto clean_up;
	}

clean_up:
	if (pstTemp)
		X509_free(pstTemp);
	return retv;
}
