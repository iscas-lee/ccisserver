#include "global_schedule.h"
#include "../database/dbquery.h"
#include "../other/ccis_string.h"
#include "../ccis.h"
#include "../security/security.h"
#include "../client/client_login.h"
#include "../log/ccis_log.h"
#include "../plugins/monitor.h"

int	Client_Login_Schedule(BSNMsg msg , Channel* ch);

int Client_Login_Schedule(BSNMsg msg , Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	int rep_sign	= 1;								//是否回应客户端报文
	BSNMsg	*response	= (BSNMsg*)malloc(sizeof(BSNMsg));
	if (!response)
		return 1;
	memset(response , 0 , sizeof(BSNMsg));
	int response_len	= 0;
	response->head.type	= msg.head.type;
	switch(msg.head.type)
	{
		case CCIS_CLIENT_CHECK_HASH:{						//验证客户端有效性
			ccis_log_info("[devsn:%s]设备正在验证版本..." , msg.body.devsn);
			retv	= Version_Check(msg.body.reseve , version_lowerlimit , version_upperlimit);
			if (retv < 0)
			{
				ccis_log_err("[devsn:%s]设备版本(%s)过低！" , msg.body.devsn , msg.body.reseve);
				response->head.errcode	= CCIS_LOW_VERSION;
				response_len	= sizeof(CTLMsg);
				retv	= -1;
				break;
			}
			else if (retv > 0)
			{
				ccis_log_err("[devsn:%s]设备版本(%s)过高！" , msg.body.devsn , msg.body.reseve);
				response->head.errcode	= CCIS_HIGH_VERSION;
				response_len	= sizeof(CTLMsg);
				retv	= -1;
				break;
			}
			ccis_log_info("[devsn:%s]设备版本(%s)验证通过" , msg.body.devsn  , msg.body.reseve);
			strcpy(response->body.reseve , version);
			ccis_log_info("[devsn:%s]设备正在验证hash值..." , msg.body.devsn);
			response_len	= sizeof(CTLMsg);
			char hashinfo[CCIS_MAXSIZE]	= {0};

			strcpy(hashinfo , msg.buffer);
			//分解字符串
			pHashInfo pstHash	= (pHashInfo)malloc(sizeof(HashInfo));
			if (!pstHash)
			{
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				retv	= 1;
				break;
			}
			memset(pstHash , 0 , sizeof(HashInfo));

			if (Analyze_Info(hashinfo , (char**)pstHash , 2 , "+"))
			{
				ccis_log_err("[devsn:%s]hash值解析失败！原hash字符串：%s" , msg.body.devsn , msg.buffer);
				response->head.errcode	= CCIS_CLIENT_CHECK_HASH_INVALID;
				Client_Login_Status(MONITOR_WARNING , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				Free_Hash(pstHash);
				retv	= -1;
				break;
			}

			//对比hash值
			if (Compare_Client_Hash(msg.body.devsn , pstHash))
			{
				response->head.errcode	= CCIS_CLIENT_CHECK_HASH_INVALID;
				retv	= -1;
				ccis_log_err("[devsn:%s]hash值不匹配！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_HASH_INVALID , NULL);
				Free_Hash(pstHash);
				goto clean_up;
			}

			Free_Hash(pstHash);

			//生成令牌环
			if (Check_LoginStatus(msg.body.devsn))
			{
				pRing tmp	= Find_Ring_Node(msg.body.devsn);
				ccis_log_err("[devsn:%s]该设备已经登陆！登陆来源IP：%s，已登陆来源IP：%s" , msg.body.devsn , ch->r_ip , tmp->ip);
				response->head.errcode	= CCIS_CLIENT_DUPLICATE_LOGIN;
				retv	= 1;
				goto clean_up;
			}

			pRing ring	= (pRing)malloc(sizeof(struct Ring));
			if (!ring)
			{
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				retv	= 1;
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				ccis_log_err("[devsn:%s]令牌环分配失败！" , msg.body.devsn);
				goto clean_up;
			}
			memset(ring , 0 , sizeof(struct Ring));

			Add_Ring_Node(ring);
			ring->verified	= CCIS_CLIENT_HASH_CHECKED;
			strncpy(ring->devsn , msg.body.devsn , DEVSN_LEN);
			strncpy(ring->ip , ch->r_ip , CCIS_IP_LEN);
			ring->fd	= ch->fd;
			if (zoneid)
				strncpy(ring->zoneid , zoneid , 3);
			X509* client_cert	= SSL_get_peer_certificate(ch->ssl);
			if (!client_cert)
			{
				response->head.errcode	= CCIS_CLIENT_CERT_ERROR;
				retv	= -1;
				ccis_log_err("[devsn:%s]无法获取对端证书！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_TPM_CERT_UNREACHABLE , NULL);
				goto clean_up;
			}
			ring->tpm_key	= X509_get_pubkey(client_cert);
			X509_free(client_cert);
			if (!ring->tpm_key)
			{
				response->head.errcode	= CCIS_CLIENT_CERT_ERROR;
				retv	= -1;
				ccis_log_err("[devsn:%s]无法获取对端公钥！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_TPM_PUBKEY_UNREACHABLE , NULL);
				goto clean_up;
			}

			response->head.errcode	= CCIS_CLIENT_CHECK_HASH_VALID;
			ccis_log_info("[devsn:%s]客户端Hash验证已通过！" , msg.body.devsn);
		}break;
		case CCIS_CLIENT_UPLOAD_SN:{						//首次开机，上传硬件SN
			response_len	= sizeof(BSNMsg);
			//搜索令牌环，该步骤的执行必须后于有效性验证
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				response->head.errcode	= CCIS_NO_PRE_RING_NODE;
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				retv	= -1;
				goto clean_up;
			}
			if (ring->verified & ~(CCIS_CLIENT_HASH_CHECKED))
			{
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				response->head.errcode	= CCIS_CLIENT_RECORD_HARDSN_FAILED;
				retv	= -1;
				goto clean_up;
			}

			//分解SN信息字符串
			pHardSN pstHard	= (pHardSN)malloc(sizeof(HardSN));
			if (!pstHard)
			{
				response->head.errcode	= CCIS_CLIENT_RECORD_HARDSN_FAILED;
				retv	= 1;
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				goto clean_up;
			}
			memset(pstHard , 0 , sizeof(HardSN));

			if (Analyze_Info(msg.buffer , (char**)pstHard , sizeof(HardSN) / sizeof(char*) , "+"))
			{
				response->head.errcode	= CCIS_CLIENT_RECORD_HARDSN_FAILED;
				ccis_log_err("[devsn:%s]硬件SN字符串解析失败！原SN字符串：%s" , msg.body.devsn , msg.buffer);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				retv	= -1;
				Free_HardSN(pstHard);
				goto clean_up;
			}

			//获取Ukey与TPM的注册状态，携带在reseve字段中发给客户端，字段由2bit组成，高位表示ukey状态，低位表示tpm状态
			Check_Register_Status(msg.body.devsn , pstHard->ukeysn , &(ring->tpm_regsign) , &(ring->ukey_regsign));
			int regstatus	= 0;
			if (ring->tpm_regsign)
				regstatus |= 1;
			if (ring->ukey_regsign)
				regstatus |= 2;
			sprintf(response->body.reseve , "%d" , regstatus);

			//根据ukeysn获取UKEY PIN码
			if (Check_Ukey_Bind_Status(pstHard->ukeysn))
			{
				ccis_log_err("[devsn:%s]无法获取用户Ukey[%s]的PIN码：Ukey已被绑定！" , msg.body.devsn , pstHard->ukeysn);
				retv	= -1;
				response->head.errcode	= CCIS_CLIENT_UKEY_ALREADY_USED;
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_UKEY_NOT_MATCHED , NULL);
				Free_HardSN(pstHard);
				goto clean_up;
			}
			char keypin[UKEYPIN_LEN];
			if (Get_UkeyPIN(msg.body.devsn , pstHard->tpmsn , pstHard->ukeysn , keypin , 0))
			{
				response->head.errcode	= CCIS_CLIENT_RECORD_HARDSN_FAILED;
				retv	= -1;
				ccis_log_err("[devsn:%s]无法获取用户Ukey[%s]的PIN码！" , msg.body.devsn , pstHard->ukeysn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_UKEY_PIN , NULL);
				Free_HardSN(pstHard);
				goto clean_up;
			}
#ifdef DEBUG
			ccis_log_debug("[devsn:%s]Ukey %s PIN码：%s" , msg.body.devsn , pstHard->ukeysn , keypin);
#endif
			
			if (Encrypt_String_By_Server(ring->tpm_key , keypin , response->buffer , &response->body.bufLen))
			{
				response->head.errcode	= CCIS_CLIENT_ENCRYPT_FAILED;
				retv	= -1;
				ccis_log_err("[devsn:%s]Ukey[%s] PIN码加密失败！" , msg.body.devsn , pstHard->ukeysn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_ENCRYPT_FAILED , NULL);
				goto clean_up;
			}

			/**********查找是否有未同步的新PIN码，有则放置在reseve中跟随注册状态用明文同步发送***********/
			if (!ring->ukey_regsign)
			{
				char newpin[CCIS_SMALLSIZE] = {0};
				if (Try_NewPIN(pstHard->ukeysn , newpin))
				{
					int i	= 0;
					while (response->body.reseve[i] != '\0' && i < CCIS_SMALLSIZE / 2)
						i ++;
					response->body.reseve[i] = '\0';
					char* pos	= &(response->body.reseve[i + 1]);
					strcpy(pos , newpin);
				}
			}
			/********************************************************************************************/

			//将SN信息挂入安全令牌环中，在执行系统信息入库时一并入库
			ring->pstHard	= pstHard;
			strncpy(ring->tpmsn , pstHard->tpmsn , TPMSN_LEN);
			strncpy(ring->ukeysn , pstHard->ukeysn , UKEYSN_LEN);

			response->head.errcode	= CCIS_CLIENT_RECORD_HARDSN_SUCCESS;
			ccis_log_info("[devsn:%s]客户端硬件SN号已缓存成功！" , msg.body.devsn);
		}break;
		case CCIS_CLIENT_MODIFY_SN:{					//日常开机，更改硬件SN
			response_len	= sizeof(BSNMsg);
			//搜索令牌环，该步骤的执行必须后于有效性验证
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				response->head.errcode	= CCIS_NO_PRE_RING_NODE;
				retv	= -1;
				goto clean_up;
			}
			if (ring->verified & ~(CCIS_CLIENT_HASH_CHECKED))
			{
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				response->head.errcode	= CCIS_CLIENT_MODIFY_HARDSN_FAILED;
				retv	= -1;
				goto clean_up;
			}

			//分解SN信息字符串
			pHardSN pstHard	= (pHardSN)malloc(sizeof(HardSN));
			if (!pstHard)
			{
				response->head.errcode	= CCIS_CLIENT_MODIFY_HARDSN_FAILED;
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				retv	= 1;
				goto clean_up;
			}
			memset(pstHard , 0 , sizeof(HardSN));
			
			if (Analyze_Info(msg.buffer , (char**)pstHard , sizeof(HardSN) / sizeof(char*) , "+"))
			{
				ccis_log_err("[devsn:%s]硬件SN字符串解析失败！原SN字符串：%s" , msg.body.devsn , msg.buffer);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				response->head.errcode	= CCIS_CLIENT_MODIFY_HARDSN_FAILED;
				retv	= -1;
				Free_HardSN(pstHard);
				goto clean_up;
			}

			//获取Ukey与TPM的注册状态，携带在reseve字段中发给客户端，字段由2bit组成，高位表示ukey状态，低位表示tpm状态
			Check_Register_Status(msg.body.devsn , pstHard->ukeysn , &(ring->tpm_regsign) , &(ring->ukey_regsign));
			int regstatus	= 0;
			if (ring->tpm_regsign)
				regstatus |= 1;
			if (ring->ukey_regsign)
				regstatus |= 2;
			sprintf(response->body.reseve , "%d" , regstatus);
			//获取UKEY PIN码
			char keypin[UKEYPIN_LEN];
			if (Get_UkeyPIN(msg.body.devsn , pstHard->tpmsn , pstHard->ukeysn , keypin , 1))
			{
				response->head.errcode	= CCIS_CLIENT_MODIFY_HARDSN_FAILED;
				ccis_log_err("[devsn:%s]无法获取用户Ukey[%s] PIN码！" , msg.body.devsn , pstHard->ukeysn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_UKEY_PIN , NULL);
				retv	= -1;
				Free_HardSN(pstHard);
				goto clean_up;
			}

			if (Encrypt_String_By_Server(ring->tpm_key , keypin , response->buffer , &response->body.bufLen))
			{
				response->head.errcode	= CCIS_CLIENT_ENCRYPT_FAILED;
				retv	= -1;
				ccis_log_err("[devsn:%s]Ukey[%s] PIN码加密失败！" , msg.body.devsn , pstHard->ukeysn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_ENCRYPT_FAILED , NULL);
				goto clean_up;
			}
			/**********查找是否有未同步的新PIN码，有则放置在reseve中跟随注册状态用明文同步发送***********/
			if (!ring->ukey_regsign)
			{
				char newpin[CCIS_SMALLSIZE] = {0};
				if (Try_NewPIN(pstHard->ukeysn , newpin))
				{
					int i	= 0;
					while (response->body.reseve[i] != '\0' && i < CCIS_SMALLSIZE / 2)
						i ++;
					response->body.reseve[i] = '\0';
					char* pos	= &(response->body.reseve[i + 1]);
					strcpy(pos , newpin);
				}
			}
			/********************************************************************************************/
			//将硬件SN挂入ring中
			ring->pstHard	= pstHard;
			strncpy(ring->tpmsn , pstHard->tpmsn , TPMSN_LEN);
			strncpy(ring->ukeysn , pstHard->ukeysn , UKEYSN_LEN);
			response->head.errcode	= CCIS_CLIENT_MODIFY_HARDSN_SUCCESS;
			ccis_log_info("[devsn:%s]客户端硬件SN已缓存成功！" , msg.body.devsn);
		}break;
		case CCIS_CLIENT_GET_UKEY_PIN:{				//获取UKEY PIN码
			response_len	= sizeof(BSNMsg);

			//搜索令牌环，该步骤的执行必须后于有效性验证
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				response->head.errcode	= CCIS_NO_PRE_RING_NODE;
				retv	= -1;
				goto clean_up;
			}
			if (ring->verified & ~(CCIS_CLIENT_HASH_CHECKED))
			{
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				response->head.errcode	= CCIS_CLIENT_NO_UKEY_PIN;
				retv	= -1;
				goto clean_up;
			}

			pUkeyBind pstUkeyBind	= NULL;
			pstUkeyBind	= (pUkeyBind)malloc(sizeof(UkeyBind));
			if (!pstUkeyBind)
			{
				response->head.errcode	= CCIS_CLIENT_NO_UKEY_PIN;
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				retv	= 1;
				goto clean_up;
			}
			memset(pstUkeyBind , 0 , sizeof(UkeyBind));

			if (Analyze_Info(msg.buffer , (char**)pstUkeyBind , sizeof(UkeyBind) / sizeof(char*) , "+"))
			{
				ccis_log_err("[devsn:%s]Ukey&TPM信息解析失败！原字符串：%s" , msg.body.devsn , msg.buffer);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				response->head.errcode	= CCIS_CLIENT_NO_UKEY_PIN;
				retv	= -1;
				Free_UkeyBind(pstUkeyBind);
				goto clean_up;
			}

			//获取Ukey与TPM的注册状态，携带在reseve字段中发给客户端，字段由2bit组成，高位表示ukey状态，低位表示tpm状态
			Check_Register_Status(msg.body.devsn , pstUkeyBind->ukeysn , &(ring->tpm_regsign) , &(ring->ukey_regsign));
			int regstatus	= 0;
			if (ring->tpm_regsign)
				regstatus |= 1;
			if (ring->ukey_regsign)
				regstatus |= 2;
			sprintf(response->body.reseve , "%d" , regstatus);

			char key_pin[UKEYPIN_LEN]	= {0};
			//获取PIN码
			retv	= Get_UkeyPIN(msg.body.devsn , pstUkeyBind->tpmsn , pstUkeyBind->ukeysn , key_pin , 1);
			if (retv)
			{
				if (retv == 2)
				{
					ccis_log_err("[devsn:%s]Ukey[%s]与TPM[%s]不匹配！" , msg.body.devsn , pstUkeyBind->ukeysn , pstUkeyBind->tpmsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_UKEY_NOT_MATCHED , NULL);
					response->head.errcode	= CCIS_CLIENT_UKEY_NOT_MATCHED;
					retv	= -1;
					Free_UkeyBind(pstUkeyBind);
					goto clean_up;
				}
				else
				{
					ccis_log_err("[devsn:%s]无法获取用户Ukey[%s] PIN码！" , msg.body.devsn , pstUkeyBind->ukeysn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_UKEY_PIN , NULL);
					response->head.errcode	= CCIS_CLIENT_NO_UKEY_PIN;
					retv	= -1;
					Free_UkeyBind(pstUkeyBind);
					goto clean_up;
				}
			}
#ifdef DEBUG
			ccis_log_debug("[devsn:%s]Ukey %s PIN码：%s" , msg.body.devsn , pstUkeyBind->ukeysn , key_pin);
#endif
			if (Encrypt_String_By_Server(ring->tpm_key , key_pin , response->buffer , &response->body.bufLen))
			{
				response->head.errcode	= CCIS_CLIENT_ENCRYPT_FAILED;
				ccis_log_err("[devsn:%s]Ukey[%s] PIN码加密失败！" , msg.body.devsn , pstUkeyBind->ukeysn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_ENCRYPT_FAILED , NULL);
				retv	= -1;
				Free_UkeyBind(pstUkeyBind);
				goto clean_up;
			}
			/**********查找是否有未同步的新PIN码，有则放置在reseve中跟随注册状态用明文同步发送***********/
			if (!ring->ukey_regsign)
			{
				char newpin[CCIS_SMALLSIZE] = {0};
				if (Try_NewPIN(pstUkeyBind->ukeysn , newpin))
				{
					int i	= 0;
					while (response->body.reseve[i] != '\0' && i < CCIS_SMALLSIZE / 2)
						i ++;
					response->body.reseve[i] = '\0';
					char* pos	= &(response->body.reseve[i + 1]);
					strcpy(pos , newpin);
				}
			}
			/********************************************************************************************/

			response->head.errcode	= CCIS_CLIENT_UKEY_PIN_MATCHED;
			strncpy(ring->tpmsn , pstUkeyBind->tpmsn , TPMSN_LEN);
			strncpy(ring->ukeysn , pstUkeyBind->ukeysn , UKEYSN_LEN);
			ccis_log_info("[devsn:%s]用户Ukey PIN码已发送！" , msg.body.devsn);
			Free_UkeyBind(pstUkeyBind);
		}break;
		case CCIS_CLIENT_CHECK_UKEY_CERT:{			//验证UKEY证书
			ccis_log_debug("[devsn:%s]设备正在认证Ukey证书" , msg.body.devsn);
			response_len	= sizeof(CTLMsg);

			//搜索令牌环，该步骤的执行必须后于有效性验证
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				response->head.errcode	= CCIS_NO_PRE_RING_NODE;
				retv	= -1;
				goto clean_up;
			}
			if (ring->verified & ~(CCIS_CLIENT_HASH_CHECKED))
			{
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				response->head.errcode	= CCIS_CLIENT_CHECK_UKEY_CERT_INVALID;
				retv	= -1;
				goto clean_up;
			}

			//接收客户端Ukey证书，完毕后提交给CA认证，认证通过，设置verified |= CCIS_CLIENT_UKEY_CERT_VERIFIED
			char certpath[CCIS_PATHLEN];
			memset(certpath , 0 , sizeof(CCIS_PATHLEN));

			//组合证书路径
			strcpy(certpath , "/tmp/");
			strcat(certpath , msg.body.devsn);
			strcat(certpath , ".pem");

			if (Receive_Ukey_Cert(certpath , msg.buffer , msg.body.bufLen , msg.head.status))
			{
				ccis_log_err("[devsn:%s]用户Ukey证书接收失败！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_UKEY_CERT_INVALID , NULL);
				response->head.errcode	= CCIS_CLIENT_CHECK_UKEY_CERT_INVALID;
				retv	= 1;
				goto clean_up;
			}

			if (msg.head.status == CCIS_PACKAGE_FINISHED)
			{
				ccis_log_info("[devsn:%s]用户Ukey接收完成！" , msg.body.devsn);
				if (ca_enable)
				{
					if (Check_Cert_In_CA(certpath))
					{
						response->head.errcode	= CCIS_CLIENT_CHECK_UKEY_CERT_INVALID;
						ccis_log_info("[devsn:%s]用户Ukey证书验证未通过！" , msg.body.devsn);
						retv	= -1;
						Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_UKEY_CERT_INVALID , NULL);
					}
					else
					{
						ring->verified	|= CCIS_CLIENT_UKEY_CERT_VERIFIED;
						response->head.errcode	= CCIS_CLIENT_CHECK_UKEY_CERT_VALID;
						ccis_log_info("[devsn:%s]用户Ukey证书验证已通过！" , msg.body.devsn);
					}
				}
				else
				{
					ring->verified	|= CCIS_CLIENT_UKEY_CERT_VERIFIED;
					response->head.errcode	= CCIS_CLIENT_CHECK_UKEY_CERT_VALID;
					ccis_log_info("[devsn:%s]用户Ukey证书验证已通过！" , msg.body.devsn);
				}
			}
			else
			{
				rep_sign	= 0;
			}
		}break;
		case CCIS_CLIENT_LOGIN_PBC_FIRST:{				//首次验证征信用户名与密码
			response_len	= sizeof(CTLMsg);
			char pbcinfo[CCIS_SMALLSIZE]	= {0};
			int source_len	= 0;

			//查找令牌环
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				response->head.errcode	= CCIS_NO_PRE_RING_NODE;
				retv	= -1;
				goto clean_up;
			}
			if ((ring->verified & ~(CCIS_CLIENT_HASH_CHECKED | CCIS_CLIENT_UKEY_CERT_VERIFIED)) && ring->verified != CCIS_CLIENT_VERIFIED)
			{
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				retv	= -1;
				response->head.errcode	= CCIS_CLIENT_PBC_LOGIN_FAILED;
				goto clean_up;
			}

			
			//解密密文
#ifdef DEBUG
			printf("***********加密征信信息************\n");
			printf("Len = %d\n" , msg.body.bufLen);
			printf("Info : %s\n" , msg.buffer);
			printf("***********************************\n");
#endif
			if (Decrypt_String_By_Server(server_private_key , msg.buffer , pbcinfo , msg.body.bufLen , &source_len))
			{
				ccis_log_err("[devsn:%s]征信信息解密失败！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				response->head.errcode	= CCIS_CLIENT_DECRYPT_FAILED;
				retv	= -1;
				goto clean_up;
			}
#ifdef DEBUG
			printf("征信信息：%s\n" , pbcinfo);
#endif
			
			//分解字符串
			pPBCInfo pstPBC	= (pPBCInfo)malloc(sizeof(PBCInfo));
			if (!pstPBC)
			{
				retv	= 1;
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				goto clean_up;
			}
			memset(pstPBC , 0 , sizeof(PBCInfo));

			if (Analyze_Info(pbcinfo , (char**)pstPBC , sizeof(PBCInfo) / sizeof(char*) , "+"))
			{
				response->head.errcode	= CCIS_CLIENT_PBC_LOGIN_FAILED;
				ccis_log_err("[devsn:%s]征信信息解析失败！解密后征信信息：%s" , msg.body.devsn , pbcinfo);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				retv	= -1;
				Free_PBCInfo(pstPBC);
				goto clean_up;
			}

			if (Check_Orgid(msg.body.devsn , pstPBC->pbcid))
			{
				response->head.errcode	= CCIS_CLIENT_PBC_INVALIAD_PBCID;
				ccis_log_err("[devsn:%s] 征信账号验证失败：征信机构号%s尚未登记！" , msg.body.devsn , pstPBC->pbcid);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_INVALIAD_PBCID , NULL);
				retv	= 1;
				Free_PBCInfo(pstPBC);
				goto clean_up;
			}
			char updateinfo[CCIS_MIDSIZE];
			if (Check_Account_Status(ring->devsn , ring->ukeysn , updateinfo , &(response->body.bufLen) , ring->tpm_key->pkey.rsa) == 1)
			{
				ccis_log_info("[devsn:%s]即将发送帐密更新操作，密文密码长度：%d" , ring->devsn , response->body.bufLen);
				response->head.errcode	= CCIS_CLIENT_PBC_PWD_CHANGE;
				memcpy(response->buffer , updateinfo , response->body.bufLen);
				strcpy(ring->pbcinfo.Orgid , pstPBC->pbcid);
				strcpy(ring->pbcinfo.User , pstPBC->username);
				rep_sign	= 1;
				response_len	= sizeof(BSNMsg);
				Free_PBCInfo(pstPBC);
				goto clean_up;
			}

			//登陆征信以验证用户名密码
			char* newpwd	= NULL;
			if (Init_Curl())
			{
				ccis_log_err("[devsn:%s]征信账号验证失败：Curl初始化失败！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOGIN_FAILED , NULL);
				retv	= 6;
			}
			else
			{
				retv	= Connection_To_PBC(pstPBC->username , pstPBC->password , atoi(pstPBC->agt) , &newpwd);
				Clean_Curl();
			}
			printf("Connection_To_PBC returned %d\n" , retv);
			switch(retv)
			{
				case 0:{
					strcpy(ring->pbcinfo.Orgid , pstPBC->pbcid);
					strcpy(ring->pbcinfo.User , pstPBC->username);
					strcpy(ring->pbcinfo.Pwd , pstPBC->password);
					ring->agent	= atoi(pstPBC->agt);
					response->head.errcode	= CCIS_CLIENT_PBC_LOGIN_SUCCESS;
					ring->verified	= CCIS_CLIENT_VERIFIED;
					ccis_log_info("[devsn:%s]征信信息验证通过！" , msg.body.devsn);
					if (Check_PBCInfo_Change(msg.body.devsn , ring->ukeysn , pstPBC))
					{
						if (Record_PBCInfo_Change(msg.body.devsn , ring->ukeysn , pstPBC , 2 , 5 , "CCISClient"))
							ccis_log_alert("[devsn:%s]征信信息变更记录失败！可能会影响该设备后续功能使用，请联系管理员解决！" , msg.body.devsn);
					}
					Client_Login_Status(MONITOR_NORMAL , msg.body.devsn , CCIS_MONITOR_LOGIN_SUCCESS , NULL);
				}break;
				case 1:{
					response->head.errcode	= CCIS_CLIENT_PBC_PASSWORD_ERROR;
					ccis_log_err("[devsn:%s]征信密码错误！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_PASSWORD_ERROR , NULL);
				}break;
				case 2:{
					response->head.errcode	= CCIS_CLIENT_PBC_LOGIN_FAILED;
					ccis_log_err("[devsn:%s]征信中心登陆失败！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOGIN_FAILED , NULL);
				}break;
				case 3:{
					response->head.errcode	= CCIS_CLIENT_PBC_LOCKED;
					ccis_log_err("[devsn:%s]征信账号（%s）已被锁定！" , msg.body.devsn , pstPBC->username);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOCKED , NULL);
				}break;
				case 5:{
					response->head.errcode	= CCIS_CLIENT_PBC_CANNOT_EMPTY;
					ccis_log_err("[devsn:%s]征信账号或密码不可为空！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_CANNOT_EMPTY , NULL);
				}break;
				case 6:{
					response->head.errcode	= CCIS_CLIENT_PBC_REMOTE_SYSTEM_ERROR;
					ccis_log_err("[devsn:%s]征信中心系统异常，登陆失败！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_REMOTE_SYSTEM_ERROR , NULL);
				}break;
				case 7:{
					response->head.errcode	= CCIS_CLIENT_PBC_LOCAL_SYSTEM_ERROR;
					ccis_log_err("[devsn:%s]服务器系统异常，登录失败！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOCAL_SYSTEM_ERROR , NULL);
				}break;
				default:{
					ccis_log_err("[devsn:%s]征信中心登陆未知错误！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOGIN_FAILED , NULL);
					retv	= 3;
					response->head.errcode	= CCIS_UNKNOW_ERROR;
				}
			}
			if (newpwd)
			{
				ccis_log_notice("账号[%s]原密码已过期，服务器已主动为其修改密码！" , ring->pbcinfo.User);
				ccis_log_debug("征信密码已由[%s]修改为[%s]" , ring->pbcinfo.Pwd , newpwd);
				strcpy(ring->pbcinfo.Pwd , newpwd);
				if (Store_New_Password(ring))
				{
					ccis_log_emerg("账号[%s]的新密码未能记录到数据库！请联系管理员紧急操作！" , ring->pbcinfo.User);
				}
				else
					ccis_log_info("账号[%s]的新密码已经更新至数据库，将在客户端下次登陆时同步" , ring->pbcinfo.User);
			}
			Free_PBCInfo(pstPBC);
		}break;
		case CCIS_CLIENT_LOGIN_PBC_NORMAL:{			//日常开机验证征信账号信息
			response_len	= sizeof(CTLMsg);
			char pbcinfo[CCIS_SMALLSIZE]	= {0};
			int source_len	= 0;

			//查找令牌环
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				response->head.errcode	= CCIS_NO_PRE_RING_NODE;
				retv	= -1;
				goto clean_up;
			}
			if ((ring->verified & ~(CCIS_CLIENT_HASH_CHECKED | CCIS_CLIENT_UKEY_CERT_VERIFIED)) && ring->verified != CCIS_CLIENT_VERIFIED)
			{
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				retv	= -1;
				response->head.errcode	= CCIS_CLIENT_PBC_LOGIN_FAILED;
				goto clean_up;
			}

			if (Check_Ukey_TPM(msg.body.devsn , ring->tpmsn , ring->ukeysn))
			{
				ccis_log_err("[devsn:%s]Ukey绑定关系校验失败！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_UKEY_NOT_MATCHED , NULL);
				retv	= -1;
				response->head.errcode	= CCIS_CLIENT_UKEY_NOT_MATCHED;
				goto clean_up;
			}

			//解密密文
			if (Decrypt_String_By_Server(server_private_key , msg.buffer , pbcinfo , msg.body.bufLen , &source_len))
			{
				response->head.errcode	= CCIS_CLIENT_DECRYPT_FAILED;
				ccis_log_err("[devsn:%s]征信信息解密失败！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				retv	= -1;
				goto clean_up;
			}

			//分解字符串
			pPBCInfo pstPBC	= (pPBCInfo)malloc(sizeof(PBCInfo));
			if (!pstPBC)
			{
				retv	= 1;
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				goto clean_up;
			}
			memset(pstPBC , 0 , sizeof(PBCInfo));
			if (Analyze_Info(pbcinfo , (char**)pstPBC , sizeof(PBCInfo) / sizeof(char*) , "+"))
			{
				ccis_log_err("[devsn:%s]征信信息解析失败！解密后征信信息：%s" , msg.body.devsn , pbcinfo);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				response->head.errcode	= CCIS_CLIENT_PBC_LOGIN_FAILED;
				retv	= -1;
				Free_PBCInfo(pstPBC);
				goto clean_up;
			}

			if (Check_Orgid(msg.body.devsn , pstPBC->pbcid))
			{
				response->head.errcode	= CCIS_CLIENT_PBC_INVALIAD_PBCID;
				ccis_log_err("[devsn:%s] 征信账号验证失败：征信机构号%s尚未登记！" , msg.body.devsn , pstPBC->pbcid);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_INVALIAD_PBCID , NULL);
				retv	= 1;
				Free_PBCInfo(pstPBC);
				goto clean_up;
			}

			char updateinfo[CCIS_MIDSIZE];
			if (Check_Account_Status(ring->devsn , ring->ukeysn , updateinfo , &(response->body.bufLen) , ring->tpm_key->pkey.rsa) == 1)
			{
				ccis_log_info("[devsn:%s]即将发送帐密更新操作，密文密码长度：%d" , ring->devsn , response->body.bufLen);
				response->head.errcode	= CCIS_CLIENT_PBC_PWD_CHANGE;
				memcpy(response->buffer , updateinfo , response->body.bufLen);
				strcpy(ring->pbcinfo.Orgid , pstPBC->pbcid);
				strcpy(ring->pbcinfo.User , pstPBC->username);
				rep_sign	= 1;
				response_len	= sizeof(BSNMsg);
				Free_PBCInfo(pstPBC);
				goto clean_up;
			}
			//登陆征信以验证用户名密码
			char* newpwd	= NULL;
			if (Init_Curl())
			{
				ccis_log_err("[devsn:%s]征信账号验证失败：Curl初始化失败！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOGIN_FAILED , NULL);
				retv	= 6;
			}
			else
			{
				retv	= Connection_To_PBC(pstPBC->username , pstPBC->password , atoi(pstPBC->agt) , &newpwd);
				Clean_Curl();
			}
			printf("Connection_To_PBC returned %d\n" , retv);
			switch(retv)
			{
				case 0:{
					response->head.errcode	= CCIS_CLIENT_PBC_LOGIN_SUCCESS;
					ring->verified	= CCIS_CLIENT_VERIFIED;
					strcpy(ring->pbcinfo.Orgid , pstPBC->pbcid);
					strcpy(ring->pbcinfo.User , pstPBC->username);
					strcpy(ring->pbcinfo.Pwd , pstPBC->password);
					ring->agent	= atoi(pstPBC->agt);
					ccis_log_info("[devsn:%s]征信信息验证通过！" , msg.body.devsn);
					if (Check_PBCInfo_Change(msg.body.devsn , ring->ukeysn , pstPBC))
					{
						if (Record_PBCInfo_Change(msg.body.devsn , ring->ukeysn , pstPBC , 2 , 5 , "CCISClient"))
							ccis_log_alert("[devsn:%s]征信信息变更记录失败！可能会影响该设备后续功能使用，请联系管理员解决！" , msg.body.devsn);
					}
					Client_Login_Status(MONITOR_NORMAL , msg.body.devsn , CCIS_MONITOR_LOGIN_SUCCESS , NULL);
				}break;
				case 1:{
					response->head.errcode	= CCIS_CLIENT_PBC_PASSWORD_ERROR;
					ccis_log_err("[devsn:%s]征信密码错误！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_PASSWORD_ERROR , NULL);
				}break;
				case 2:{
					response->head.errcode	= CCIS_CLIENT_PBC_LOGIN_FAILED;
					ccis_log_err("[devsn:%s]征信中心登陆失败！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOGIN_FAILED , NULL);
				}break;
				case 3:{
					response->head.errcode	= CCIS_CLIENT_PBC_LOCKED;
					ccis_log_err("[devsn:%s]征信账号（%s）已被锁定！" , msg.body.devsn , pstPBC->username);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOCKED , NULL);
				}break;
				case 5:{
					response->head.errcode	= CCIS_CLIENT_PBC_CANNOT_EMPTY;
					ccis_log_err("[devsn:%s]征信账号或密码不可为空！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_CANNOT_EMPTY , NULL);
				}break;
				case 6:{
					response->head.errcode	= CCIS_CLIENT_PBC_REMOTE_SYSTEM_ERROR;
					ccis_log_err("[devsn:%s]征信中心系统异常，登陆失败！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_REMOTE_SYSTEM_ERROR , NULL);
				}break;
				case 7:{
					response->head.errcode	= CCIS_CLIENT_PBC_LOCAL_SYSTEM_ERROR;
					ccis_log_err("[devsn:%s]服务器系统异常，登录失败！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOCAL_SYSTEM_ERROR , NULL);
				}break;
				default:{
					ccis_log_err("[devsn:%s]征信中心登陆未知错误！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_LOGIN_FAILED , NULL);
					response->head.errcode	= CCIS_UNKNOW_ERROR;
				}
			}
			if (newpwd)
			{
				ccis_log_notice("账号[%s]原密码已过期，服务器已主动为其修改密码！" , ring->pbcinfo.User);
				ccis_log_debug("征信密码已由[%s]修改为[%s]" , ring->pbcinfo.Pwd , newpwd);
				strcpy(ring->pbcinfo.Pwd , newpwd);
				if (Store_New_Password(ring))
				{
					ccis_log_emerg("账号[%s]的新密码未能记录到数据库！请联系管理员紧急操作！" , ring->pbcinfo.User);
				}
				else
					ccis_log_info("账号[%s]的新密码已经更新至数据库，将在客户端下次登陆时同步" , ring->pbcinfo.User);
			}
			Free_PBCInfo(pstPBC);
		}break;
		case CCIS_CLIENT_UPLOAD_SYSTEM_INFO:{			//首次开机，上传系统信息
			response_len	= sizeof(CTLMsg);
			
			//查找令牌环
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				response->head.errcode	= CCIS_NO_PRE_RING_NODE;
				retv	= -1;
				goto clean_up;
			}
			if ((ring->verified & ~(CCIS_CLIENT_HASH_CHECKED | CCIS_CLIENT_UKEY_CERT_VERIFIED)) && ring->verified != CCIS_CLIENT_VERIFIED)
			{
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				retv	= -1;
				response->head.errcode	= CCIS_CLIENT_RECORD_SYSTEM_INFO_FAILED;
				if (ring->pstHard)
				{
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
				}
				goto clean_up;
			}

			//分解字符串
			pSystemInfo pstSystem	= (pSystemInfo)malloc(sizeof(SystemInfo));
			if (!pstSystem)
			{
				retv	= 1;
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				response->head.errcode	= CCIS_CLIENT_RECORD_SYSTEM_INFO_FAILED;
				if (ring->pstHard)
				{
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
				}
				goto clean_up;
			}
			memset(pstSystem , 0 , sizeof(SystemInfo));
			if (Analyze_Info(msg.buffer , (char**)pstSystem , sizeof(SystemInfo) / sizeof(char*) , "+"))
			{
				ccis_log_err("[devsn:%s]系统信息解析失败！原系统信息字符串：%s" , msg.body.devsn , msg.buffer);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				retv	= -1;
				response->head.errcode	= CCIS_CLIENT_RECORD_SYSTEM_INFO_FAILED;
				free(pstSystem);
				if (ring->pstHard)
				{
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
				}
				goto clean_up;
			}

			//系统信息入库
			if (Insert_SystemInfo(msg.body.devsn , pstSystem))
			{
				ccis_log_err("[devsn:%s]系统信息插入失败！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_RECORD_SYSINFO_FAILED , NULL);
				retv	= -1;
				response->head.errcode	= CCIS_CLIENT_RECORD_SYSTEM_INFO_FAILED;
				Free_SystemInfo(pstSystem);
				if (ring->pstHard)
				{
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
				}
				goto clean_up;
			}

			Free_SystemInfo(pstSystem);
			pstSystem	= NULL;


			//假如存在硬件SN信息，入库
			if (ring->pstHard)
			{
				if (Insert_HardSN(msg.body.devsn , ring->pstHard))
				{
					response->head.errcode	= CCIS_CLIENT_RECORD_HARDSN_FAILED;
					ccis_log_err("[devsn:%s]硬件SN信息入库失败！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_RECORD_HARDSN_FAILED , NULL);
					Rollback_SystemInfo(msg.body.devsn);			//硬件信息入库失败则回滚系统信息
					retv	= -1;
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
					goto clean_up;
				}

				Free_HardSN(ring->pstHard);
				ring->pstHard	= NULL;
			}
			int bind_retv	= Bind_Ukey_TPM(msg.body.devsn , ring->tpmsn , ring->ukeysn);
			if (bind_retv == 1)
			{
				response->head.errcode	= CCIS_CLIENT_UKEY_ALREADY_USED;
				retv	= -1;
				ccis_log_err("[devsn:%s]设备使用的Ukey已被绑定过！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_UKEY_BIND_FAILED , NULL);
				Rollback_HardSN(msg.body.devsn);
				Rollback_SystemInfo(msg.body.devsn);
			}
			else if (bind_retv == -1)
			{
				response->head.errcode	= CCIS_CLIENT_UKEY_BIND_FAILED;
				ccis_log_err("[devsn:%s]Ukey与TPM绑定失败！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_UKEY_BIND_FAILED , NULL);
				retv	= -1;
				Rollback_HardSN(msg.body.devsn);
				Rollback_SystemInfo(msg.body.devsn);
			}
			else
			{
				response->head.errcode	= CCIS_CLIENT_RECORD_SYSTEM_INFO_SUCCESS;
				ccis_log_info("[devsn:%s]系统信息记录成功！" , msg.body.devsn);
			}
		}break;
		case CCIS_CLIENT_MODIFY_SYSTEM_INFO:{			//日常开机，变更系统信息
			response_len	= sizeof(CTLMsg);

			//查找令牌环
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				response->head.errcode	= CCIS_NO_PRE_RING_NODE;
				retv	= -1;
				goto clean_up;
			}
			if (ring->verified != CCIS_CLIENT_VERIFIED && ((ring->verified & ~(CCIS_CLIENT_HASH_CHECKED | CCIS_CLIENT_UKEY_CERT_VERIFIED))))
			{
				retv	= -1;
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				response->head.errcode	= CCIS_CLIENT_MODIFY_SYSTEM_INFO_FAILED;
				if (ring->pstHard)
				{
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
				}
				goto clean_up;
			}

			//分解字符串
			pSystemInfo pstSystem	= (pSystemInfo)malloc(sizeof(SystemInfo));
			if (!pstSystem)
			{
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				retv	= 1;
				response->head.errcode	= CCIS_CLIENT_MODIFY_SYSTEM_INFO_FAILED;
				if (ring->pstHard)
				{
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
				}
				goto clean_up;
			}
			memset(pstSystem , 0 , sizeof(SystemInfo));
			if (Analyze_Info(msg.buffer , (char**)pstSystem , sizeof(SystemInfo) / sizeof(char*) , "+"))
			{
				ccis_log_err("[devsn:%s]系统信息解析失败！原系统信息字符串：%s" , msg.body.devsn , msg.buffer);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_DECRYPT_FAILED , NULL);
				retv	= -1;
				response->head.errcode	= CCIS_CLIENT_MODIFY_SYSTEM_INFO_FAILED;
				Free_SystemInfo(pstSystem);
				if (ring->pstHard)
				{
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
				}
				goto clean_up;
			}

			//系统信息入库
			if (Modify_SystemInfo(msg.body.devsn , pstSystem))
			{
				ccis_log_err("[devsn:%s]系统信息更新失败！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_MODIFY_SYSINFO_FAILED , NULL);
				retv	= -1;
				response->head.errcode	= CCIS_CLIENT_MODIFY_SYSTEM_INFO_FAILED;
				Free_SystemInfo(pstSystem);
				if (ring->pstHard)
				{
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
				}
				goto clean_up;
			}

			Free_SystemInfo(pstSystem);
			pstSystem	= NULL;

			//假如存在硬件SN信息，入库
			if (ring->pstHard)
			{
				if (Modify_HardSN(msg.body.devsn , ring->pstHard))
				{
					response->head.errcode	= CCIS_CLIENT_MODIFY_HARDSN_FAILED;
					ccis_log_err("[devsn:%s]硬件SN更新失败！" , msg.body.devsn);
					Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_MODIFY_HARDSN_FAILED , NULL);
					retv	= -1;
					Free_HardSN(ring->pstHard);
					ring->pstHard	= NULL;
					goto clean_up;
				}

				Free_HardSN(ring->pstHard);
				ring->pstHard	= NULL;
			}
			response->head.errcode	= CCIS_CLIENT_MODIFY_SYSTEM_INFO_SUCCESS;
			ccis_log_info("[devsn:%s]系统信息变更成功！" , msg.body.devsn);
		}break;
		case CCIS_CLIENT_PWD_CHANGE:{
			//查找令牌环
			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			rep_sign	= 0;
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				retv	= -1;
				goto clean_up;
			}
			if ((ring->verified & ~(CCIS_CLIENT_HASH_CHECKED | CCIS_CLIENT_UKEY_CERT_VERIFIED)) && ring->verified != CCIS_CLIENT_VERIFIED)
			{
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				retv	= -1;
				goto clean_up;
			}
			if (msg.head.errcode == CCIS_CLIENT_PWD_CHANGE_SUCCESS)
			{
				if (Update_Account_Status(ring->devsn , ring->ukeysn , ring->pbcinfo.User , 2))
					ccis_log_err("[devsn:%s]账号[%s]密码更新成功，但数据库状态位更新失败！" , ring->devsn , ring->pbcinfo.User);
				else
					ccis_log_info("[devsn:%s]账号[%s]密码更新成功！" , ring->devsn , ring->pbcinfo.User);
			}
			else
				ccis_log_err("账号[%s]密码更新失败！即将在下次登陆时再次更新！" , ring->pbcinfo.User);
		}break;
		case CCIS_CLIENT_PBC_QUERY:{
			response_len		= sizeof(CTLMsg);

			pRing ring	= Find_Ring_Node_Accurate(msg.body.devsn , NULL , ch->fd);
			if (!ring)
			{
				ccis_log_err("[devsn:%s]无法找到安全令牌！" , msg.body.devsn);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_NO_PRE_RING , NULL);
				response->head.errcode	= CCIS_NO_PRE_RING_NODE;
				retv	= -1;
				goto clean_up;
			}
			if ((ring->verified & ~(CCIS_CLIENT_HASH_CHECKED | CCIS_CLIENT_UKEY_CERT_VERIFIED)) && ring->verified != CCIS_CLIENT_VERIFIED)
			{
				ccis_log_err("[devsn:%s]设备尚未经过有效性验证！verified = 0x%x" , msg.body.devsn , ring->verified);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_FLOW_INVALID , NULL);
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				retv	= -1;
				goto clean_up;
			}

			//需要检测Orgid与devsn的关系，Orgid以明文放在buffer中
			if (Check_Orgid(msg.body.devsn , msg.buffer))
			{
				response->head.errcode	= CCIS_CLIENT_PBC_INVALIAD_PBCID;
				ccis_log_err("[devsn:%s] 征信账号验证失败：征信机构号%s尚未登记！" , msg.body.devsn , msg.buffer);
				Client_Login_Status(MONITOR_ERROR , msg.body.devsn , CCIS_MONITOR_LOGIN_PBC_INVALIAD_PBCID , NULL);
				retv	= 1;
				goto clean_up;
			}

			//先检查是否存在该设备的密码记录，如果有则直接发送，不存在则插入一条记录，status为0,管理网站上搜索出为0的记录表示等待颁发帐号密码
			char result[CCIS_MIDSIZE];
			retv	= Query_PBC_Account(msg.body.devsn , ring->ukeysn , msg.buffer , result);
			if (retv == 0)
				response->head.errcode	= CCIS_CLIENT_PBC_QUERY_SUCCESS;
			else if (retv == 1)
			{
				response->head.errcode	= CCIS_CLIENT_PBC_ISSUED_SUCCESS;
				response->body.bufLen	= server_encrypt_long_data(result , response->buffer , ring->tpm_key->pkey.rsa);
				if (response->body.bufLen <= 0)
				{
					ccis_log_err("[devsn:%s]帐号信息加密失败！" , msg.body.devsn);
					response->body.bufLen	= 0;
					response->head.errcode	= CCIS_CLIENT_PBC_QUERY_FAILED;
				}
				else
				{
					response_len		= sizeof(BSNMsg);
					ccis_log_info("[devsn:%s]帐号信息加密成功！即将发送..." , msg.body.devsn);
				}
			}
			else if (retv == 2)
				response->head.errcode	= CCIS_CLIENT_PBC_DOUBLE_QUERY;
			else if (retv == 3)
				response->head.errcode	= CCIS_CLIENT_PBC_ALREADY_EXIST;
			else if (retv == 4)
				response->head.errcode	= CCIS_CLIENT_PBC_QUERY_FAILED;
			else
				response->head.errcode	= CCIS_UNKNOW_ERROR;
			retv	= 0;
		}break;
		default:{						//未知报文不予回应
			rep_sign	= 0;
		}
	}

clean_up:
	if (rep_sign)
		Write_Msg(ch->ssl , (void*)response , response_len);
	if (response)
		free(response);
	return retv;
}
