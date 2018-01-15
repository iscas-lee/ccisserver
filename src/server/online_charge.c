#include "online_charge.h"
#include "../log/ccis_log.h"
#include <errno.h>
#include "../network/network.h"
#include "../network/ssl/ssl.h"
#include "../network/ssl/connect.h"

void	OnlineCharge_Request(OlchgArgs* args);
void	OnlineCharge_Reconfirm(OlchgArgs* args);
void	OnlineCharge_Refunds(OlchgArgs* args);
OlchgArgs*	OnlineCharge_InitArgs(pSearch_Log log_node , pRing ring , SSL* ssl);
static CHGChannel*	Connect_ChargeServer(char* querysn);
static void	Disconnect_ChargeServer(CHGChannel* cntchannel);
extern int Update_Condition(pSearch_Log log_node , char* condition);

OlchgArgs* OnlineCharge_InitArgs(pSearch_Log log_node , pRing ring , SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!log_node || !ring || !ssl)
	{
		ccis_log_err("移动支付参数初始化失败：无效的参数值！");
		return NULL;
	}
	OlchgArgs* result	= (OlchgArgs*)calloc(1 , sizeof(OlchgArgs));
	if (!result)
	{
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	result->log_node	= log_node;
	result->ring		= ring;
	result->ssl		= ssl;

clean_up:
	return result;
}

void OnlineCharge_Request(OlchgArgs* args)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif

	BSNMsg response;
	memset(&response , 0 , sizeof(BSNMsg));
	int rep_sign	= 1;
	response.head.type	= CCIS_OLCHG_REQUEST;

	CHGChannel* cntchannel	= Connect_ChargeServer(args->log_node->querysn);
	if (!cntchannel)
	{
		ccis_log_err("[%s]移动支付失败：无法连接至收费服务器！" , args->log_node->querysn);
		response.head.errcode	= CCIS_OLCHG_CONNECT_FAILED;
		Update_Condition(args->log_node , "failed");
		goto clean_up;
	}
	ccis_log_debug("[%s]已连接至收费服务器！" , args->log_node->querysn);

	char order_str[CCIS_SMALLSIZE];
	sprintf(order_str , "zoneid=%s+devsn=%s+querysn=%s" , args->ring->zoneid , args->log_node->devsn , args->log_node->querysn);
	CHGMsg chgmsg;
	memset(&chgmsg , 0 , sizeof(CHGMsg));
	chgmsg.type	= OLCHG_GETQRCODE;
	strcpy(chgmsg.buffer , order_str);
	Write_Msg(cntchannel->ssl , (void*)&chgmsg , sizeof(CHGMsg));

	sleep(1);

	short failure	= 1;
	int timeouts	= olchg_timeout;
	CHGMsg msg;
	memset(&msg , 0 , sizeof(CHGMsg));

	//循环获取二维码
	while ((timeouts = timeouts - olchg_polling_interval))
	{
		Read_Msg(cntchannel->ssl , (char*)&msg , sizeof(CHGMsg));
		if (msg.errcode == OLCHG_QRCODE_SUCCESS)
		{
			failure	= 0;
			ccis_log_debug("[%s]获取到QRCode串！内容为：%s" , args->log_node->querysn , msg.buffer);
			ccis_log_debug("[%s]订单序列号：%s" , args->log_node->querysn , msg.orderid);
			break;
		}
		ccis_log_debug("[%s]未获取到QRCode串！" , args->log_node->querysn);
		memset(&msg , 0 , sizeof(CHGMsg));
		sleep(olchg_polling_interval);
	}
	if (failure)
	{
		ccis_log_err("[%s]二维码获取超时！" , args->log_node->querysn);
		Update_Condition(args->log_node , "failed");
		response.head.errcode	= CCIS_OLCHG_TIMEOUT;
		goto clean_up;
	}

	strcpy(args->log_node->orderid , msg.orderid);
	args->log_node->olchg_seq	= msg.seq;
	strcpy(response.buffer , msg.buffer);
	response.head.errcode	= CCIS_OLCHG_QRCODE;
	Write_Msg(args->ssl , (void*)&response , sizeof(BSNMsg));

	memset(&chgmsg , 0 , sizeof(CHGMsg));
	chgmsg.type	= OLCHG_FRESHSTATUS;
	chgmsg.seq	= args->log_node->olchg_seq;
	strcpy(chgmsg.orderid , args->log_node->orderid);
	Write_Msg(cntchannel->ssl , (void*)&chgmsg , sizeof(CHGMsg));

	sleep(5);

	//循环获取支付结果
	memset(&response , 0 , sizeof(BSNMsg));
	failure	= 1;
	timeouts	= olchg_timeout;
	memset(&msg , 0 , sizeof(CHGMsg));
	while ((timeouts = timeouts - olchg_polling_interval))
	{
		Read_Msg(cntchannel->ssl , (char*)&msg , sizeof(CHGMsg));
		if (msg.errcode == OLCHG_STATUS_SUCCESS)
		{
			ccis_log_info("[%s]移动支付付款成功！" , args->log_node->querysn);
			args->log_node->olchg_status	= OLCHG_STATUS_SUCCESS;
			failure	= 0;
			break;
		}
		else if (msg.errcode == OLCHG_STATUS_WAITING)
		{
			ccis_log_debug("[%s]用户暂未付款！" , args->log_node->querysn);
			memset(&msg , 0 , sizeof(CHGMsg));
			Write_Msg(cntchannel->ssl , (void*)&chgmsg , sizeof(CHGMsg));
			Update_Condition(args->log_node , "timeout");
			sleep(olchg_polling_interval);
			continue;
		}
		else if (msg.errcode == OLCHG_STATUS_INVALID)
		{
			ccis_log_debug("[%s]用户尚未扫码！" , args->log_node->querysn);
			memset(&msg , 0 , sizeof(CHGMsg));
			Write_Msg(cntchannel->ssl , (void*)&chgmsg , sizeof(CHGMsg));
			Update_Condition(args->log_node , "timeout");
			sleep(olchg_polling_interval);
			continue;
		}
		else
		{
			ccis_log_err("[%s]获取付款状态失败！" , args->log_node->querysn);
			Update_Condition(args->log_node , "failed");
			break;
		}
	}
	if (failure)
	{
		if (msg.errcode == OLCHG_STATUS_CLOSE)
		{
			response.head.errcode	= CCIS_OLCHG_CHARGE_CLOSE;
			ccis_log_err("[%s]移动支付失败：当前交易已关闭！" , args->log_node->querysn);
			Update_Condition(args->log_node , "failed");
			args->log_node->olchg_status	= OLCHG_STATUS_CLOSE;
			goto clean_up;
		}
		else if (msg.errcode == OLCHG_STATUS_TIMEOUT)
		{
			response.head.errcode	= CCIS_OLCHG_CHARGE_TIMEOUT;
			ccis_log_err("[%s]移动支付失败：当前交易已超时！" , args->log_node->querysn);
			Update_Condition(args->log_node , "timeout");
			args->log_node->olchg_status	= OLCHG_STATUS_TIMEOUT;
			goto clean_up;
		}
		else if (msg.errcode == OLCHG_STATUS_FAILED)
		{
			response.head.errcode	= CCIS_OLCHG_FAILED;
			ccis_log_err("[%s]移动支付失败：交易失败！" , args->log_node->querysn);
			Update_Condition(args->log_node , "failed");
			args->log_node->olchg_status	= OLCHG_STATUS_FAILED;
			goto clean_up;
		}
		else
		{
			response.head.errcode	= CCIS_OLCHG_FAILED;
			ccis_log_err("[%s]移动支付失败：用户未在规定时间内完成缴费！" , args->log_node->querysn);
			Update_Condition(args->log_node , "timeout");
			args->log_node->olchg_status	= OLCHG_STATUS_WAITING;
			goto clean_up;
		}
	}

	response.head.type	= CCIS_OLCHG_REQUEST;
	response.head.errcode	= CCIS_OLCHG_SUCCESS;
	Update_Condition(args->log_node , "success");
	args->log_node->chgnum	= 10;

clean_up:
	if (rep_sign)
		Write_Msg(args->ssl , (void*)&response , sizeof(CTLMsg));

	//投递签收状态
	if (cntchannel)
	{
		memset(&chgmsg , 0 , sizeof(CHGMsg));
		chgmsg.type	= OLCHG_SIGNUP;
		chgmsg.seq	= args->log_node->olchg_seq;
		strcpy(chgmsg.orderid , args->log_node->orderid);
		Write_Msg(cntchannel->ssl , (void*)&chgmsg , sizeof(CHGMsg));
		do{
			sleep(1);
			memset(&msg , 0 , sizeof(CHGMsg));
			int read_retv	= 0;
			if ((read_retv = Read_Msg(cntchannel->ssl , (char*)&msg , sizeof(CHGMsg)) != 0))
			{
				if (read_retv < 0)
					continue;
				ccis_log_err("[%s]该查询付款签收状态未确保投递至收费服务器！" , args->log_node->querysn);
				break;
			}
			if (msg.errcode == OLCHG_COMM_CONFIRM)
			{
				ccis_log_debug("[%s]查询付款签收状态成功投递" , args->log_node->querysn);
				break;
			}
		}while(1);
	}

	Disconnect_ChargeServer(cntchannel);
	return;
}

void OnlineCharge_Reconfirm(OlchgArgs* args)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!args)
		return;

	int rep_sign	= 1;
	CTLMsg response;
	response.head.type	= CCIS_OLCHG_RECONFIRM;

	CHGChannel* cntchannel	= Connect_ChargeServer(args->log_node->querysn);
	if (!cntchannel)
	{
		ccis_log_err("[%s]移动支付状态刷新失败：无法连接至收费服务器！" , args->log_node->querysn);
		Update_Condition(args->log_node , "failed");
		response.head.errcode	= CCIS_OLCHG_CONNECT_FAILED;
		goto clean_up;
	}
	ccis_log_debug("[%s]已连接至收费服务器！" , args->log_node->querysn);

	CHGMsg chgmsg;
	CHGMsg msg;
	memset(&msg , 0 , sizeof(CHGMsg));
	memset(&chgmsg , 0 , sizeof(CHGMsg));
	chgmsg.type	= OLCHG_FRESHSTATUS;
	strcpy(chgmsg.orderid , args->log_node->orderid);
	Write_Msg(cntchannel->ssl , (void*)&chgmsg , sizeof(CHGMsg));

	short failure	= 1;
	int timeouts	= olchg_timeout;
	while ((timeouts = timeouts - olchg_polling_interval))
	{
		Read_Msg(cntchannel->ssl , (char*)&msg , sizeof(CHGMsg));
		if (msg.type != OLCHG_FRESHSTATUS)		//丢弃所有非当前请求的报文
			continue;
		if (msg.errcode == OLCHG_STATUS_SUCCESS)
		{
			ccis_log_info("[%s]移动支付付款成功！" , args->log_node->querysn);
			args->log_node->olchg_status	= OLCHG_STATUS_SUCCESS;
			failure	= 0;
			break;
		}
		else if (msg.errcode == OLCHG_STATUS_WAITING)
		{
			ccis_log_debug("[%s]用户暂未付款！" , args->log_node->querysn);
			memset(&msg , 0 , sizeof(CHGMsg));
			Write_Msg(cntchannel->ssl , (void*)&chgmsg , sizeof(CHGMsg));
			Update_Condition(args->log_node , "failed");
			sleep(olchg_polling_interval);
			continue;
		}
		else
		{
			ccis_log_err("[%s]获取付款状态失败！" , args->log_node->querysn);
			Update_Condition(args->log_node , "failed");
			break;
		}
	}
	if (failure)
	{
		if (msg.errcode == OLCHG_STATUS_CLOSE)
		{
			response.head.errcode	= CCIS_OLCHG_CHARGE_CLOSE;
			ccis_log_err("[%s]移动支付失败：当前交易已关闭！" , args->log_node->querysn);
			Update_Condition(args->log_node , "failed");
			args->log_node->olchg_status	= OLCHG_STATUS_CLOSE;
			goto clean_up;
		}
		else if (msg.errcode == OLCHG_STATUS_TIMEOUT)
		{
			response.head.errcode	= CCIS_OLCHG_CHARGE_TIMEOUT;
			ccis_log_err("[%s]移动支付失败：当前交易已超时！" , args->log_node->querysn);
			Update_Condition(args->log_node , "timeout");
			args->log_node->olchg_status	= OLCHG_STATUS_TIMEOUT;
			goto clean_up;
		}
		else if (msg.errcode == OLCHG_STATUS_FAILED)
		{
			response.head.errcode	= CCIS_OLCHG_FAILED;
			ccis_log_err("[%s]移动支付失败：交易失败！" , args->log_node->querysn);
			Update_Condition(args->log_node , "failed");
			args->log_node->olchg_status	= OLCHG_STATUS_FAILED;
			goto clean_up;
		}
		else
		{
			response.head.errcode	= CCIS_OLCHG_FAILED;
			ccis_log_err("[%s]移动支付失败：用户未在规定时间内完成缴费！" , args->log_node->querysn);
			Update_Condition(args->log_node , "timeout");
			args->log_node->olchg_status	= OLCHG_STATUS_WAITING;
			goto clean_up;
		}
	}

	response.head.errcode	= CCIS_OLCHG_SUCCESS;
	Update_Condition(args->log_node , "success");
	args->log_node->chgnum	= 10;

clean_up:
	if (rep_sign)
		Write_Msg(args->ssl , (void*)&response , sizeof(CTLMsg));
	//投递签收状态
	if (cntchannel)
	{
		memset(&chgmsg , 0 , sizeof(CHGMsg));
		chgmsg.type	= OLCHG_SIGNUP;
		chgmsg.seq	= args->log_node->olchg_seq;
		strcpy(chgmsg.orderid , args->log_node->orderid);
		Write_Msg(cntchannel->ssl , (void*)&chgmsg , sizeof(CHGMsg));
		do{
			sleep(1);
			memset(&msg , 0 , sizeof(CHGMsg));
			int read_retv	= 0;
			if ((read_retv = Read_Msg(cntchannel->ssl , (char*)&msg , sizeof(CHGMsg)) != 0))
			{
				if (read_retv < 0)
					continue;
				ccis_log_err("[%s]该查询付款签收状态未确保投递至收费服务器！" , args->log_node->querysn);
				break;
			}
			if (msg.errcode == OLCHG_COMM_CONFIRM)
			{
				ccis_log_debug("[%s]查询付款签收状态成功投递" , args->log_node->querysn);
				break;
			}
		}while(1);
	}

	Disconnect_ChargeServer(cntchannel);
	return;
}

void OnlineCharge_Refunds(OlchgArgs* args)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
}

static CHGChannel* Connect_ChargeServer(char* querysn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif

	int retv	= 0;
	CHGChannel* result	= (CHGChannel*)calloc(1 , sizeof(CHGChannel));
	if (!result)
	{
		ccis_log_err("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}

	int chgsvr_sockfd	= Connect_Server(olchg_server , olchg_port , CCIS_NONBLOCK);
	if (chgsvr_sockfd <= 0)
	{
		ccis_log_err("[%s]移动支付失败：无法连接收费服务器！" , querysn);
		retv	 = 1;
		goto clean_up;
	}

#if 1
	SSL* chgsvr_ssl	= SSL_new(clientCtx);
	if (!chgsvr_ssl)
	{
		ccis_log_err("[%s]移动支付失败：无法初始化SSL套接字！%s" , querysn , strerror(errno));
		retv	 = 1;
		goto clean_up;
	}

	if (SSL_set_fd(chgsvr_ssl , chgsvr_sockfd) == 0)
	{
		ccis_log_err("[%s]移动支付失败：无法建立ssl与socket连接！" , querysn);
		retv	 = 1;
		chgsvr_ssl	= NULL;
		goto clean_up;
	}
	SSL_set_connect_state(chgsvr_ssl);
	ccis_log_debug("[%s]移动支付：SSL初始化完成" , querysn);

	int ssl_ret;
	int retry_counts	 = 0;
	while ((ssl_ret = SSL_do_handshake(chgsvr_ssl)) != 1)
	{
		int err	= SSL_get_error(chgsvr_ssl , ssl_ret);
		unsigned long io_errcode	= ERR_get_error();
		const char* const str	= ERR_reason_error_string(io_errcode);
		ccis_log_err("[%s]移动支付失败：SSL握手失败：%d！SSL错误码：%d , IO错误码：%s , 系统错误消息：%s" , querysn , ssl_ret , err , str , strerror(errno));
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
		{
			if (retry_counts ++ < 30)
			{
#if 0
				sleep(5);
#else
				usleep(100);
#endif
				continue;
			}
		}
		retv	 = 1;
		chgsvr_ssl	= NULL;
		goto clean_up;
	}
#else
	SSL* chgsvr_ssl	= NULL;
	if (SSL_Connect(&chgsvr_sockfd , chgsvr_ssl))
	{
		ccis_log_err("[%s]移动支付失败：SSL握手失败！" , querysn);
		retv	= 1;
		chgsvr_ssl	= NULL;
		goto clean_up;
	}
#endif

	ccis_log_debug("与收费服务器握手完成！");
	Set_NonBlock(chgsvr_sockfd , CCIS_NONBLOCK);
	result->sockfd	= chgsvr_sockfd;
	result->ssl	= chgsvr_ssl;

clean_up:
	if (retv && result)
	{
		if (chgsvr_sockfd > 0)
			close(chgsvr_sockfd);
		free(result);
		result	= NULL;
	}
	return result;
}

static void Disconnect_ChargeServer(CHGChannel* cntchannel)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!cntchannel)
		return;

	if (cntchannel->ssl)
		SSL_shutdown(cntchannel->ssl);
	if (cntchannel->sockfd > 0)
		close(cntchannel->sockfd);
	free(cntchannel);
	cntchannel	= NULL;
}
