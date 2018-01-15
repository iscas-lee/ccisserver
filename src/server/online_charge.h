#ifndef __CCIS_OLCHG_H__
#define	__CCIS_OLCHG_H__
#include "struct/server_struct.h"
#include "../security/struct/security_struct.h"
#include "../network/network.h"

/****************TYPE*********************/
#define	OLCHG_GETQRCODE		0x0010
#define	OLCHG_FRESHSTATUS	0x0011			//刷新支付结果
#define	OLCHG_SIGNUP		0x0012			//交易状态签收

/****************ERRCODE*****************/
#define	OLCHG_QRCODE_SUCCESS	0x0001			//二维码获取成功
#define	OLCHG_QRCODE_FAILED	0x0002			//二维码获取失败
#define	OLCHG_STATUS_SUCCESS	0x0003			//交易成功
#define	OLCHG_STATUS_FAILED	0x0004			//交易失败
#define	OLCHG_STATUS_TIMEOUT	0x0005			//交易已超时
#define	OLCHG_STATUS_CLOSE	0x0006			//交易关闭
#define	OLCHG_STATUS_WAITING	0x0007			//等待用户付款中
#define	OLCHG_STATUS_INVALID	0x0008			//用户尚未扫码
#define	OLCHG_COMM_CONFIRM	0x0060			//签收确认
#define	OLCHG_ORDER_INVAILED	0x00FF			//订单无效

typedef struct _OlchgArgs{
	pSearch_Log log_node;
	pRing ring;
	SSL* ssl;
}OlchgArgs;

typedef	struct _CHGMsg{
	unsigned int type;
	unsigned int errcode;
	unsigned int status;
	unsigned long long seq;
	char orderid[CHG_ORDERID_LEN];
	char buffer[CCIS_MAXSIZE];
}CHGMsg;

typedef struct _CHGChannel{
	int sockfd;
	SSL* ssl;
}CHGChannel;

extern OlchgArgs*	OnlineCharge_InitArgs(pSearch_Log log_node , pRing ring , SSL* ssl);	//初始化相关参数
extern void	OnlineCharge_Request(OlchgArgs* args);			//申请移动支付，将返回给客户端一个二维码串，以及第一轮的轮询结果
extern void	OnlineCharge_Reconfirm(OlchgArgs* args);		//确认收费结果，将返回给客户端表示是否收费成功
extern void	OnlineCharge_Refunds(OlchgArgs* args);			//退款

#endif
