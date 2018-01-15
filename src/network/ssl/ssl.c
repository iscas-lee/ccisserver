#include "ssl.h"
#include "../network.h"
#include "../../log/ccis_log.h"
#define NON_MAIN
#include "../../security/ca/apps.h"
#undef NON_MAIN

int	Init_SSL();
void	Close_SSL();
int	SSL_Verify_Client_Cert(SSL* ssl);
int	Verify_Callback_Server(int ok , X509_STORE_CTX* pstCtx);
int	Verify_Callback_Client(int ok , X509_STORE_CTX* pstCtx);
int	Write_Msg(SSL* ssl , const void* buffer , int bufSize);
int	Read_Msg(SSL* ssl , char* buffer , int bufSize);
int	SSL_CTX_use_PrivateKey_file_pass(SSL_CTX* pstCtx , char* filename , char* pwd);
static int	Init_ServerSSL();
static int	Init_ClientSSL();

int Init_SSL()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	SSL_load_error_strings();
	SSL_library_init();
	SSLeay_add_ssl_algorithms();

	retv	= Init_ServerSSL();
	if (retv)
	{
		ccis_log_emerg("服务器SSL_CTX初始化失败！返回码：%d" , retv);
		goto clean_up;
	}

	retv	= Init_ClientSSL();
	if (retv)
	{
		ccis_log_emerg("收费客户端SSL_CTX初始化失败！返回码：%d" , retv);
		goto clean_up;
	}
clean_up:
	return retv;
}

int Verify_Callback_Server(int ok , X509_STORE_CTX* pstCtx)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	return ok;
}

int Verify_Callback_Client(int ok , X509_STORE_CTX* pstCtx)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	return ok;
}

int SSL_Verify_Client_Cert(SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	X509* pstClientCert	= NULL;
	char* pcStr	= NULL;
	pstClientCert	= SSL_get_peer_certificate(ssl);
	if (pstClientCert)
	{
		int ret	= SSL_get_verify_result(ssl);
		if (ret != X509_V_OK)
		{
			retv	= 1;
			goto clean_up;
		}
		pcStr	= X509_NAME_oneline(X509_get_subject_name(pstClientCert), 0, 0);
		if (!pcStr)
		{
			retv	= 1;
			goto clean_up;
		}

		char *CertStatusReq[16]	= {"-issuer" , cacert , "-CAfile" , cacert , "-cert" , (char*)pstClientCert , "-url" , cahost};
		if (SSL_CheckCertStatus(CertStatusReq) == V_OCSP_GERTSTATUS_GOOD)
		{
			retv	= 0;
			ccis_log_info("SSL证书验证通过！");
			goto clean_up;
		}
		else
		{
			ccis_log_err("SSL证书验证失败！");
			retv	= 2;
			goto clean_up;
		}
	}
	else
	{
		ccis_log_err("[%s:%d]无法获取对端证书！" , __FUNCTION__ , __LINE__);
		retv	= 1;
	}

clean_up:
	if (pstClientCert)
	{
		X509_free(pstClientCert);
		pstClientCert	= NULL;
	}
	if (pcStr)
	{
		free(pcStr);
		pcStr	= NULL;
	}

	return retv;
}

int Write_Msg(SSL* ssl , const void* buffer , int bufSize)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif

	int retv		= 1;

	struct itimerval itv;
	itv.it_interval.tv_sec	= 0;
	itv.it_interval.tv_usec	= 0;
	itv.it_value.tv_sec	= 2;			//这里设置两秒，实际上在代码逻辑中只会让其运行一秒
	itv.it_value.tv_usec	= 0;

	int timer		= 0;
	int send_ret		= 0;

#ifdef DEBUG
	CTLMsg *this	= (CTLMsg*)buffer;
	printf("*************\n");
	printf("Writing Querysn : %s\n" , this->body.querysn);
	printf("Writing Type : 0x%x\n" , this->head.type);
	printf("Writing Errcode : 0x%x\n" , this->head.errcode);
	printf("Writing Status : 0x%x\n" , this->head.status);
	printf("*************\n");
#endif
	if ((send_ret = SSL_write(ssl , buffer , bufSize)) < 0)
	{
		int err		= SSL_get_error(ssl , send_ret);
#ifdef DEBUG
		unsigned long sslerr	= ERR_get_error();
		ccis_log_err("SSL Error String : %s" , ERR_error_string(sslerr , NULL));
#endif
		if (err == SSL_ERROR_WANT_WRITE)
		{
			setitimer(ITIMER_VIRTUAL , &itv , NULL);
			while(getitimer(ITIMER_VIRTUAL , &itv ) == 0)
			{
				if(itv.it_value.tv_sec != 0)			//此处判断导致实际只会运行一秒
				{
					send_ret	= SSL_write(ssl , buffer , bufSize);
					timer ++;
					if (send_ret == bufSize)
					{
						retv	= 0;
						itv.it_value.tv_sec	= 0;
						itv.it_value.tv_usec	= 0;
						setitimer(ITIMER_VIRTUAL , &itv , NULL);
						goto clean_up;
					}
				}
				else
				{
					ccis_log_err("数据重发失败：超时！");
					printf("重发超时！\n");
					retv	= 1;
					goto clean_up;
				}
			}
			ccis_log_err("数据重发失败：定时器出错！");
			retv	= 2;
			goto clean_up;
		}
		else
		{
			ccis_log_err("数据发送未知错误！");
			ccis_log_err("SSL get error returned %d , errno msg is %s" , err , strerror(errno));
			unsigned long sslerr	= ERR_get_error();
			ccis_log_err("SSL Error String : %s" , ERR_error_string(sslerr , NULL));
			retv	= 3;
			goto clean_up;
		}
	}
	else
		retv	= 0;

clean_up:
	return retv;
}

int Read_Msg(SSL* ssl , char* buffer , int bufSize)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 1;
	char read_buffer[bufSize];
	memset(read_buffer , 0 , bufSize);
	int read_ret	= SSL_read(ssl , &read_buffer , bufSize);
	if (read_ret == 0)
	{
		retv	= 1;
	}
	else if (read_ret < 0)
	{
		int errcode	= SSL_get_error(ssl , read_ret);
		if (errcode != SSL_ERROR_WANT_READ)
		{
			ccis_log_err("SSL_read errcode %d , err msg %s" , errcode , strerror(errno));
			unsigned long sslerr	= ERR_get_error();
			ccis_log_err("SSL Error String : %s" , ERR_error_string(sslerr , NULL));
		}

		if (errcode == SSL_ERROR_SSL)
			retv	= -2;
		else
			retv	= -1;
	}
	else
	{
		retv	= 0;
		memcpy(buffer , read_buffer , bufSize);
	}

	return retv;
}

int SSL_CTX_use_PrivateKey_file_pass(SSL_CTX* pstCtx , char* filename , char* pwd)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	EVP_PKEY *pkey = NULL;
	BIO *key = NULL;

	key = BIO_new(BIO_s_file());
	BIO_read_filename(key, filename);
	pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, pwd);
	if (pkey == NULL)
	{
		ccis_log_err("PEM_read_bio_PrivateKey err , errno %d" , errno);
		return -1;
	}
	if (SSL_CTX_use_PrivateKey(pstCtx, pkey) <= 0)
	{
		ccis_log_err("SSL_CTX_use_PrivateKey err");
		return -1;
	}
	BIO_free(key);
	return 1;
}

void Close_SSL()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	ccis_log_info("正在回收SSL资源...");
	if (pstCtx)
		SSL_CTX_free(pstCtx);
	ERR_free_strings();
	ccis_log_info("SSL资源回收完成！");
}

static int Init_ServerSSL()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;

	pstCtx	= SSL_CTX_new(TLSv1_server_method());
	if (!pstCtx)
	{
		ERR_print_errors_fp(stderr);
		retv	= -1;
		goto clean_up;
	}

	s_server_verify	= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE;
	SSL_CTX_set_verify(pstCtx , s_server_verify , Verify_Callback_Server);

	if ((!SSL_CTX_load_verify_locations(pstCtx , cacert , NULL)) || (!SSL_CTX_set_default_verify_paths(pstCtx)))
	{
		ccis_log_err("SSL_CTX_load_verify_locations error");
		retv	= -2;
		goto clean_up;
	}

	if (SSL_CTX_use_certificate_file(pstCtx , server_cert , SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		retv	= -3;
		goto clean_up;
	}

	if (SSL_CTX_use_PrivateKey_file_pass(pstCtx , server_private_key , PRIVATE_KEY_PWD) <= 0)
	{
		ERR_print_errors_fp(stderr);
		retv	= -4;
		goto clean_up;
	}

	if (!SSL_CTX_check_private_key(pstCtx))
	{
		ccis_log_err("Private key does not match the certificate public key");
		retv	= -5;
		goto clean_up;
	}

clean_up:
	return retv;
}

static int Init_ClientSSL()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	clientCtx	= SSL_CTX_new(TLSv1_client_method());
	//clientCtx	= SSL_CTX_new(SSLv23_client_method());
	if (!clientCtx)
	{
		ERR_print_errors_fp(stderr);
		retv	= -1;
		goto clean_up;
	}

	s_client_verify	= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	SSL_CTX_set_verify(clientCtx , s_client_verify , Verify_Callback_Client);
	SSL_CTX_set_timeout(clientCtx , 5);

/*
	if ((!SSL_CTX_load_verify_locations(clientCtx , cacert , NULL)) || (!SSL_CTX_set_default_verify_paths(clientCtx)))
*/
	if ((!SSL_CTX_load_verify_locations(clientCtx , cacert , NULL)))
	{
		ccis_log_err("SSL_CTX_load_verify_locations error");
		retv	= -2;
		goto clean_up;
	}

	SSL_CTX_set_default_passwd_cb_userdata(clientCtx , PRIVATE_KEY_PWD);

	if (SSL_CTX_use_certificate_file(clientCtx , client_cert , SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		retv	= -3;
		goto clean_up;
	}

	if (SSL_CTX_use_PrivateKey_file(clientCtx , client_private_key , SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		retv	= -4;
		goto clean_up;
	}

/*
	if (SSL_CTX_use_PrivateKey_file_pass(clientCtx , client_private_key , PRIVATE_KEY_PWD) <= 0)
	{
		ERR_print_errors_fp(stderr);
		retv	= -4;
		goto clean_up;
	}
*/

	if (!SSL_CTX_check_private_key(clientCtx))
	{
		ccis_log_err("Private key does not match the certificate public key");
		retv	= -5;
		goto clean_up;
	}

	SSL_CTX_set_mode(clientCtx , SSL_MODE_AUTO_RETRY);

clean_up:
	return retv;
}
