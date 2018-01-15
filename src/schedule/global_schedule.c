#include "global_schedule.h"
#include "epoll/ccis_epoll.h"
#include "../network/ssl/connect.h"
#include "../log/ccis_log.h"
#include "../other/ccis_time.h"
#include "../other/ccis_string.h"
#include "../plugins/monitor.h"
#include "../plugins/register.h"
#include "../server/server.h"

int	Global_Schedule(Channel* ch);
int	handleRead(Channel* ch);
int	handleWrite(Channel* ch);
int	Unexpected_Hup(Channel* ch);

extern int iSockfd;

int Global_Schedule(Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	BSNMsg msg;
	pSearch_Log log_node	= NULL;
	int rd			= 0;
	int retv		= 0;

	memset(&msg , 0 , sizeof(BSNMsg));

	rd	= Read_Msg(ch->ssl , (char*)&msg , sizeof(BSNMsg));		//SSL_read
	if (unlikely(rd < 0))
	{
		if (rd == -1)
			return 1;
		else if (rd == -2)	//需要直接移除该连接的情况
		{
			pRing ring	= Find_Ring_Node_Accurate(NULL , ch->r_ip , ch->fd);
			if (ring)
			{
				ccis_log_err("[devsn:%s]设备连接出现异常，来自该设备的连接将被移除！" , ring->devsn);
				if (Client_Logout_Status(MONITOR_NORMAL , ring->devsn , 0 , NULL))
				{
					ccis_log_err("[devsn:%s]数据库操作：设备登出日志记录失败" , ring->devsn);
				}

				pSearch_Log tmpnode	= Find_Log_Node_By_Dev(ring->devsn);
				if (tmpnode)
				{
					if (Check_Newer_Log(tmpnode->querysn , tmpnode->lastpackage) == 0)
					{
						if ((tmpnode->falres & TYPECODE_MASK) == 0)
							if ((tmpnode->falres & ERRCODE_MASK) == 0)
								tmpnode->falres |= CCIS_ERR_SELF_CHECK;
							else
								tmpnode->falres	|= SELF_CHECK_SYNC;
						Upload_Log_Node(tmpnode);
					}
					Free_Log_Node(tmpnode->querysn);
				}

				Free_Ring_Node(ring->devsn);
			}
			Unregister_Events(ch);
			return 2;
		}
	}
	else if (unlikely(rd == 1))
	{
		ccis_log_info("[ip:%s]Remote is closed..." , ch->r_ip);
		pRing ring	= Find_Ring_Node_Accurate(NULL , ch->r_ip , ch->fd);
		if (ring)
		{
			ccis_log_info("[devsn:%s]设备已离线" , ring->devsn);
			if (Client_Logout_Status(MONITOR_NORMAL , ring->devsn , 0 , NULL))
			{
				ccis_log_err("[devsn:%s]数据库操作：设备登出日志记录失败" , ring->devsn);
			}
			pSearch_Log tmpnode	= Find_Log_Node_By_Dev(ring->devsn);		//设备离线的同时也检查内存中是否还存在未同步到数据库的查询节点
			if (tmpnode)
			{
				if (Check_Newer_Log(tmpnode->querysn , tmpnode->lastpackage) == 0)
				{
					if ((tmpnode->falres & TYPECODE_MASK) == 0)
						if ((tmpnode->falres & ERRCODE_MASK) == 0)
							tmpnode->falres	|= CCIS_ERR_SELF_CHECK;
						else
							tmpnode->falres	|= SELF_CHECK_SYNC;
					Upload_Log_Node(tmpnode);
				}
				Free_Log_Node(tmpnode->querysn);
			}
			Free_Ring_Node(ring->devsn);
		}
		Unregister_Events(ch);
		return 0;
	}
	else
	{
		ccis_log_debug("[ip:%s]Msg Type：%#06x" , ch->r_ip , msg.head.type);
		if (msg.head.type >= 0x0020 && msg.head.type <= 0x004F)	//征信业务报文
		{
			log_node	= Find_Log_Node(msg.body.querysn);
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring || ring->verified != CCIS_CLIENT_VERIFIED)
			{
				ccis_log_err("设备%s尚未经过认证！" , msg.body.devsn);
				goto clean_up;
			}
			retv		= Business_Schedule(log_node , ring , msg , ch);
		}
		else if (msg.head.type >= 0x0010 && msg.head.type <= 0x001F)	//客户端登陆报文
		{
			retv		= Client_Login_Schedule(msg , ch);
			if (retv < 0)			//某些特定的情况下，客户端将被直接踢除
			{
				pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
				if (ring)
				{
					ccis_log_info("[devsn:%s]设备验证不通过，连接已拒绝！" , ring->devsn);
					Free_Ring_Node(ring->devsn);
				}
				else
					ccis_log_info("[ip:%s]设备验证不通过，连接已拒绝！" , ch->r_ip);
				Unregister_Events(ch);
			}
		}
		else if (msg.head.type == CCIS_PING)
		{
			CTLMsg response;
			memset (&response , 0 , sizeof(CTLMsg));
			response.head.type	= CCIS_PING;
			Write_Msg(ch->ssl , (void*)&response , sizeof(CTLMsg));
		}
		else if (msg.head.type == CCIS_GET_TIME)
		{
			BSNMsg response;
			memset(&response , 0 , sizeof(BSNMsg));
			response.head.type	= CCIS_GET_TIME;
			char* tmp_time	= Get_Localtime();
			if (!tmp_time)
			{
				ccis_log_err("[%s:%d]本地时间获取失败！" , __FUNCTION__ , __LINE__);
				response.head.errcode	= CCIS_UNKNOW_ERROR;
			}
			else
			{
				response.head.errcode	= CCIS_SUCCESS;
				String_Replace(tmp_time , '/' , '-' , 0 , 0);
				strcpy(response.buffer , tmp_time);
				free(tmp_time);
			}
			Write_Msg(ch->ssl , (void*)&response , sizeof(BSNMsg));
		}
		else if (msg.head.type == CCIS_UKEY_REGISTER)
		{
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("设备%s尚未经过认证！" , msg.body.devsn);
				goto clean_up;
			}

			if (msg.head.errcode == CCIS_UR_REGISTER_SUCCESS)
				Update_UR_Sign(msg.body.reseve , CCIS_UR_REGISTER_SUCCESS);
			else if (msg.head.errcode == CCIS_UR_REGISTER_FAILED)
				Update_UR_Sign(msg.body.reseve , CCIS_UR_REGISTER_FAILED);
			else
				Ukey_Register(msg , ch , ring->tpm_key);
		}
		else if (msg.head.type == CCIS_TPM_REGISTER)
		{
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("设备%s尚未经过认证！" , msg.body.devsn);
				goto clean_up;
			}
			if (msg.head.errcode == CCIS_TPM_REGISTER_SUCCESS)
				Update_TPM_Sign(msg.body.devsn , CCIS_TPM_REGISTER_SUCCESS);
			else if (msg.head.errcode == CCIS_TPM_REGISTER_FAILED)
				Update_TPM_Sign(msg.body.devsn , CCIS_TPM_REGISTER_FAILED);
			else
				TPM_Register(msg , ch , ring->tpmsn);
		}
		else if (msg.head.type == CCIS_KEEPALIVE)
		{
			//Ignore
		}
		else
		{
			ccis_log_warning("[ip:%s]无效报文类型：0x%x" , ch->r_ip , msg.head.type);
			//Ignore
		}
	}

clean_up:
	return retv;
}

int handleRead(Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (ch->fd == iSockfd)
	{
		Channel* newch	= NULL;
		if((newch = Accept_Connection(iSockfd)) == NULL)
		{
			ccis_log_err("新连接接受失败！失败原因：%s" , strerror(errno));
			return -1;
		}
		return Register_Events(newch);
	}
	else if (ch->sslConnected)
	{
		return Global_Schedule(ch);
	}
	if (SSL_HandShake(ch) == 1)
	{
		Close_Socket(ch->fd);
		Unregister_Events(ch);
		return 1;
	}
	return 0;
}

int handleWrite(Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if(!ch->sslConnected)
	{
		return SSL_HandShake(ch);
	}

	ch->events	&= ~EPOLLOUT;
	return Update_Events(ch);
}

int Unexpected_Hup(Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	ccis_log_err("[ip:%s]对端套接字异常关闭，该套接字将被主动关闭并移除出连接池！" , ch->r_ip);
	pRing ring	= Find_Ring_Node_Accurate(NULL , ch->r_ip , ch->fd);
	if (ring)
	{
		ccis_log_info("[devsn:%s]设备已离线" , ring->devsn);
		if (Client_Logout_Status(MONITOR_NORMAL , ring->devsn , 0 , NULL))
		{
			ccis_log_err("[devsn:%s]数据库操作日志记录失败" , ring->devsn);
		}
		pSearch_Log tmpnode	= Find_Log_Node_By_Dev(ring->devsn);		//设备离线的同时也检查内存中是否还存在未同步到数据库的查询节点
		if (tmpnode)
		{
			if (Check_Newer_Log(tmpnode->querysn , tmpnode->lastpackage) == 0)
			{
				if ((tmpnode->falres & TYPECODE_MASK) == 0)
					if ((tmpnode->falres & ERRCODE_MASK) == 0)
						tmpnode->falres	|= CCIS_ERR_SELF_CHECK;
					else
						tmpnode->falres	|= SELF_CHECK_SYNC;
				Upload_Log_Node(tmpnode);
			}
			Free_Log_Node(tmpnode->querysn);
		}
		Free_Ring_Node(ring->devsn);
	}
	Unregister_Events(ch);
	return 0;
}
