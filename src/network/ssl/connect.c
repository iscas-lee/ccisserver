#include "connect.h"
#include "ssl.h"
#include "../../schedule/epoll/ccis_epoll.h"
#include "../../ccis.h"
#include "../../log/ccis_log.h"

int	SSL_HandShake(Channel* ch);
int	SSL_Connect(int* fd , SSL* ssl);

int SSL_HandShake(Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	if (!ch->tcpConnected)			//warning 争取修改成不需要epoll的方式
	{
		struct epoll_event tmp_event;
		int r	= epoll_wait(stEPOLL.epollfd , &tmp_event , 1 , 0);
		if (r == 1 && tmp_event.events & EPOLLOUT)
		{
			ch->tcpConnected	= 1;
			ch->events		= EPOLLIN | EPOLLOUT | EPOLLERR;
			Update_Events(ch);
		}
		else
		{
			Free_Channel(ch);
			retv	= -1;
			goto clean_up;
		}
	}
	
	if (ch->ssl == NULL)
	{
		ch->ssl		= SSL_new(pstCtx);
		if (ch->ssl == NULL)
		{
			ccis_log_err("[ip:%s]SSL握手失败：SSL_new Failed" , ch->r_ip);
			retv	= -1;
			goto clean_up;
		}
		retv	= SSL_set_fd(ch->ssl , ch->fd);
		if (!retv)
		{
			printf("[ip:%s]SSL握手失败：SSL与socket关联失败！\n" , ch->r_ip);
			retv	= -2;
			goto clean_up;
		}
		SSL_set_accept_state(ch->ssl);
	}

	int hs_ret	= SSL_do_handshake(ch->ssl);
	if (likely(hs_ret == 1))
	{
		if (ca_enable)
		{
			retv	= SSL_Verify_Client_Cert(ch->ssl);
			if (retv)
			{
				retv	= 1;
				ccis_log_err("[ip:%s]SSL握手失败：无效的客户端证书！" , ch->r_ip);
				goto clean_up;
			}
		}
		ccis_log_info("[ip:%s]SSL通道已建立！" , ch->r_ip);
		ch->sslConnected	= 1;
		goto clean_up;
	}
	int err	= SSL_get_error(ch->ssl , hs_ret);
	int oldev	= ch->events;
	if (err == SSL_ERROR_WANT_WRITE)
	{
		ch->events	|= EPOLLOUT;
		ch->events	&= ~EPOLLIN;
		ccis_log_err("[ip:%s]SSL握手失败：SSL_ERROR_WANT_WRITE" , ch->r_ip);
		if (oldev == ch->events)
		{
			retv	= -1;
			goto clean_up;
		}
		Update_Events(ch);
	}
	else if (err == SSL_ERROR_WANT_READ)
	{
		ch->events	|= EPOLLIN;
		ch->events	&= ~EPOLLOUT;
		ccis_log_err("[ip:%s]SSL握手失败：SSL_ERROR_WANT_READ" , ch->r_ip);
		if (oldev == ch->events)
		{
			retv	= -1;
			goto clean_up;
		}
		Update_Events(ch);
	}
	else
	{
		unsigned long io_err_code	= ERR_get_error();
		const char* const str	= ERR_reason_error_string(io_err_code);
		ccis_log_err("[ip:%s]SSL握手失败：%s" , ch->r_ip , str);
		Unregister_Events(ch);
		retv	= -1;
	}

clean_up:
	return retv;
}

int SSL_Connect(int* fd , SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	ssl	= SSL_new(pstCtx);
	SSL_set_fd(ssl , *fd);
	int ssl_ret = SSL_connect(ssl);
	if (ssl_ret == -1)
	{
		int err = SSL_get_error(ssl , ssl_ret);
		ccis_log_err("SSL Shake Failed : %d , errmsg = %s\n" , err , strerror(errno));
		ERR_print_errors_fp(stderr);
		//printf("%s\n" , ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	else if (ssl_ret == 0)
	{
		int err = SSL_get_error(ssl , ssl_ret);
		ccis_log_err("SSL Shake Failed : %d , errmsg = %s\n" , err , strerror(errno));
		ERR_print_errors_fp(stderr);
		while (ssl_ret == 0)
		{
			ssl_ret	= SSL_connect(ssl);
			if (ssl_ret == -1)
			{
				int err = SSL_get_error(ssl , ssl_ret);
				ccis_log_err("SSL Shake Failed : %d , errmsg = %s\n" , err , strerror(errno));
				ERR_print_errors_fp(stderr);
				return -1;
			}
			else if (ssl_ret > 0)
				break;
			else
			{
				int err = SSL_get_error(ssl , ssl_ret);
				ccis_log_err("SSL Shake Failed : %d , errmsg = %s\n" , err , strerror(errno));
				ERR_print_errors_fp(stderr);
				printf("Try again\n");
				sleep(1);
			}
		}
	}
	return 0;
}
