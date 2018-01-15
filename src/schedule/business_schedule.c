#include "global_schedule.h"
#include "../ccis.h"
#include "../server/server.h"
#include "../camera/FaceMatcher.h"
#include "../network/network.h"
#include "../log/ccis_log.h"
#include "../other/ccis_thread.h"

int	Business_Schedule(pSearch_Log log_node , pRing ring , BSNMsg msg , Channel* ch);		//业务调度，根据log_node中待处理的业务名称，给予对应的处理，处理完毕后填充待发送报文，不负责登陆流程,会执行报文发送，会设置falres字段。
int	Update_Condition(pSearch_Log log_node , char* condition);

int Business_Schedule(pSearch_Log log_node , pRing ring ,  BSNMsg msg , Channel* ch)	//0：成功，1：失败，2：需要维持
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	BSNMsg* response	= (BSNMsg*)malloc(sizeof(BSNMsg));
	if (!response)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return 1;
	}
	memset(response , 0 , sizeof(BSNMsg));
	int response_len	= 0;
	int rep_sign		= 1;		//1表示需要发送报文，0表示无需发送报文

	if (log_node)
	{
		log_node->lastpackage	= time(NULL);
		strcpy(response->body.querysn , log_node->querysn);
	}

	switch(msg.head.type)
	{
		case CCIS_RECEIVE_ID_INFO:{
			response_len	= sizeof(CTLMsg);

			char idinfo[CCIS_MAXSIZE]	= {0};
			int source_len			= 0;
			response->head.type		= CCIS_RECEIVE_ID_INFO;

			//数据解密
			if(Decrypt_String_By_Server(server_private_key , msg.buffer , idinfo , msg.body.bufLen , &source_len))
			{
				response->head.errcode	= CCIS_ID_DECRYPT_FAILED;
				ccis_log_err("[devsn:%s]身份证信息解密失败！" , msg.body.devsn);
				retv	= 1;
				break;
			}

			ccis_log_debug("[ip:%s]idinfo = %s" , ch->r_ip , idinfo);

			//分解字符串
			pID_Info pstID	= (pID_Info)malloc(sizeof(struct ID_Info));
			if (!pstID)
			{
				ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				response->head.errcode	= CCIS_ID_INIT_NODE_FAILED;
				retv	= 1;
				break;
			}
			memset (pstID , 0 , sizeof(struct ID_Info));
			if (Analyze_ID_Info(idinfo , pstID))
			{
				ccis_log_err("[ip:%s]身份证信息解析失败！" , ch->r_ip);
				response->head.errcode	= CCIS_ID_INCOMPLETE_INFO;
				Free_IDInfo(pstID);
				pstID	= NULL;
				retv	= 1;
				break;
			}

			if (interval_s > 0)
			{
				log_node	= Find_LastBusiness(pstID->id , msg.body.devsn);		//流程维持
				if (log_node)
				{
					Analyze_FlowProcess(log_node , &response->head.type , &response->head.errcode);
					if (response->head.errcode != CCIS_PROCESS_INVALID)
					{
						ccis_log_info("[ip:%s]找到尚未完成的流程！" , ch->r_ip);
						response->head.control	= 1;
						Print_Log_Struct(log_node);
						Add_Log_Node(log_node);
						strcpy(response->body.querysn , log_node->querysn);
						strcpy(response->body.reseve , log_node->report_type);
						Free_IDInfo(pstID);
						pstID	= NULL;
						retv	= 0;
						break;
					}
					else
					{
						log_node	= NULL;
					}
				}
				ccis_log_debug("[ip:%s]未找到此人未完成流程，将继续正常执行！" , ch->r_ip);
			}

			response->head.type	= CCIS_RECEIVE_ID_INFO;

			if (Init_Log_Node(&log_node))
			{
				response->head.errcode	= CCIS_ID_INIT_NODE_FAILED;
				ccis_log_alert("[ip:%s]查询节点初始化失败！" , ch->r_ip);
				Free_IDInfo(pstID);
				pstID	= NULL;
				log_node	= NULL;
				retv	= 1;
				break;
			}

			if (Init_FlowNode(&log_node->cur_flow , 1))
			{
				ccis_log_alert("[ip:%s]流程控制节点初始化失败！" , ch->r_ip);
				response->head.errcode	= CCIS_ID_INIT_NODE_FAILED;
				Free_IDInfo(pstID);
				pstID	= NULL;
				free(log_node);
				log_node	= NULL;
				retv	= 1;
				break;
			}
			SET_PROCCODE(log_node->falres , CCIS_PROC_IDCARD_CHECK);
			strcpy(log_node->orgid , ring->pbcinfo.Orgid);

			if (Init_Curl())
			{
				ccis_log_err("[ip:%s]无法初始化Curl变量！" , ch->r_ip);
				retv	= 9;
			}
			else
			{
				retv	= Check_ID_Info(log_node , ring , pstID , msg.body.devsn);
				Clean_Curl();
			}
			if (retv >= 0 && retv <= 8)
			{
				ccis_log_info("[%s]新查询节点已建立！" , log_node->querysn);
				strcpy(response->body.querysn , log_node->querysn);
				pSearch_Log tmp_log	= Add_Log_Node(log_node);
				if (tmp_log)
				{
					if (Check_Newer_Log(tmp_log->querysn , tmp_log->lastpackage) == 0)
					{
						if (Upload_Log_Node(tmp_log))
						{
							ccis_log_warning("[%s]实时自检时更新数据库失败，节点将不会被移除！" , tmp_log->querysn);
						}
						else
							Free_Log_Node(tmp_log->querysn);
					}
					else
					{
						char *package_time	= Get_String_From_Time(&tmp_log->lastpackage);
						if (!package_time)
							ccis_log_notice("[%s]流程内存中数据已过时，将不会被更新进数据库中！" , tmp_log->querysn);
						else
						{
							ccis_log_notice("[%s]流程内存中数据(%s)已过时，将不会被更新进数据库中！" , tmp_log->querysn , package_time);
							free(package_time);
						}
						Free_Log_Node(tmp_log->querysn);
					}
					
				}
			}
			switch(retv)
			{
				case 0:{
					Update_Condition(log_node , "verified");
					ccis_log_info("[%s]身份证核验通过！" , log_node->querysn);
					response->head.errcode	= CCIS_ID_CHECK_SUCCESS;
				}break;
				case 1:{
					if (constrain_verify)
					{
						Update_Condition(log_node , "failed");
						ccis_log_err("[%s]公安部未登记此人[%s]高清照片！" , log_node->querysn , log_node->idnum);
						response->head.errcode	= CCIS_ID_NO_POLICE_PHOTO;
						log_node->vfyret	= CCIS_ERR_ID_NO_POLICE_PHOTO & ERRCODE_MASK;
						log_node->falres	|= CCIS_ERR_ID_NO_POLICE_PHOTO;
					}
					else
					{
						Update_Condition(log_node , "verified");
						response->head.errcode	= CCIS_ID_CHECK_SUCCESS;
						log_node->vfyret	= CCIS_ERR_ID_NO_POLICE_PHOTO & ERRCODE_MASK;
						ccis_log_warning("[%s]公安部未登记此人[%s]高清照片！" , log_node->querysn , log_node->idnum);
					}
				}break;
				case 2:{
					if (constrain_verify)
					{
						Update_Condition(log_node , "failed");
						ccis_log_err("[%s]身份证号码[%s]与姓名不匹配！" , log_node->querysn , log_node->idnum);
						response->head.errcode	= CCIS_ID_INFO_NOT_MATCH;
						log_node->vfyret	= CCIS_ERR_ID_NAME_NOT_MATCH & ERRCODE_MASK;
						log_node->falres	|= CCIS_ERR_ID_NAME_NOT_MATCH;
					}
					else
					{
						Update_Condition(log_node , "verified");
						response->head.errcode	= CCIS_ID_CHECK_SUCCESS;
						log_node->vfyret	= CCIS_ERR_ID_NAME_NOT_MATCH & ERRCODE_MASK;
						ccis_log_warning("[%s]身份证号码[%s]与姓名不匹配！" , log_node->querysn , log_node->idnum);
					}
				}break;
				case 3:{
					if (constrain_verify)
					{
						Update_Condition(log_node , "failed");
						ccis_log_err("[%s]身份证号码[%s]无效！" , log_node->querysn , log_node->idnum);
						response->head.errcode	= CCIS_ID_INVALID_NUMBER;
						log_node->vfyret	= CCIS_ERR_ID_INVALID_IDNUM & ERRCODE_MASK;
						log_node->falres	|= CCIS_ERR_ID_INVALID_IDNUM;
					}
					else
					{
						Update_Condition(log_node , "verified");
						response->head.errcode	= CCIS_ID_CHECK_SUCCESS;
						log_node->vfyret	= CCIS_ERR_ID_INVALID_IDNUM & ERRCODE_MASK;
						ccis_log_warning("[%s]身份证号码[%s]无效！" , log_node->querysn , log_node->idnum);
					}
				}break;
				case 4:{
					if (constrain_verify)
					{
						Update_Condition(log_node , "failed");
						ccis_log_err("[%s]身份证[%s]核验不通过！" , log_node->querysn , log_node->idnum);
						response->head.errcode	= CCIS_ID_POLICE_CHECK_ERROR;
						log_node->vfyret	= CCIS_ERR_ID_CHECK_FAILED & ERRCODE_MASK;
						log_node->falres	|= CCIS_ERR_ID_CHECK_FAILED;
					}
					else
					{
						Update_Condition(log_node , "verified");
						response->head.errcode	= CCIS_ID_CHECK_SUCCESS;
						log_node->vfyret	= CCIS_ERR_ID_CHECK_FAILED & ERRCODE_MASK;
						ccis_log_warning("[%s]身份证[%s]核验不通过！" , log_node->querysn , log_node->idnum);
					}
				}break;
				case 5:{
					if (constrain_verify)
					{
						Update_Condition(log_node , "failed");
						ccis_log_err("[%s]无法下载此人[%s]公安部照片！" , log_node->querysn , log_node->idnum);
						response->head.errcode	= CCIS_ID_POLICE_PHOTO_DOWNLOAD_FAILED;
						log_node->vfyret	= CCIS_ERR_ID_DOWNLOAD_PHOTO_ERR & ERRCODE_MASK;
						log_node->falres	|= CCIS_ERR_ID_DOWNLOAD_PHOTO_ERR;
					}
					else
					{
						Update_Condition(log_node , "verified");
						response->head.errcode	= CCIS_ID_CHECK_SUCCESS;
						log_node->vfyret	= CCIS_ERR_ID_DOWNLOAD_PHOTO_ERR & ERRCODE_MASK;
						ccis_log_warning("[%s]无法下载此人[%s]公安部照片！" , log_node->querysn , log_node->idnum);
					}
				}break;
				case 6:{
					if (constrain_verify)
					{
						Update_Condition(log_node , "failed");
						ccis_log_err("[%s]无法连接到公安部身份核查服务器！" , log_node->querysn);
						response->head.errcode	= CCIS_ID_LINK_SERVER_FAILED;
						log_node->vfyret	= CCIS_ERR_ID_POLICE_LINK_ERROR & ERRCODE_MASK;
						log_node->falres	|= CCIS_ERR_ID_POLICE_LINK_ERROR;
					}
					else
					{
						Update_Condition(log_node , "verified");
						response->head.errcode	= CCIS_ID_CHECK_SUCCESS;
						log_node->vfyret	= CCIS_ERR_ID_POLICE_LINK_ERROR & ERRCODE_MASK;
						ccis_log_warning("[%s]无法连接到公安部身份核查服务器！" , log_node->querysn);
					}
				}break;
				case 7:{
					Update_Condition(log_node , "failed");
					ccis_log_err("[%s]征信账号或密码错误！" , log_node->querysn);
					response->head.errcode	= CCIS_ID_LINK_SERVER_PWD_ERROR;
					log_node->vfyret		= CCIS_ERR_ID_PASSWD_ERROR & ERRCODE_MASK;
					log_node->falres		|= CCIS_ERR_ID_PASSWD_ERROR;
				}break;
				default:{
					if (constrain_verify)
					{
						Update_Condition(log_node , "failed");
						ccis_log_err("[ip:%s]身份证核验未知错误！" , ch->r_ip);
						response->head.errcode	= CCIS_UNKNOW_ERROR;
						log_node->vfyret	= CCIS_ERR_UNKNOW_ERROR & ERRCODE_MASK;
						log_node->falres	|= CCIS_ERR_UNKNOW_ERROR;
					}
					else
					{
						Update_Condition(log_node , "verified");
						response->head.errcode	= CCIS_ID_CHECK_SUCCESS;
						log_node->vfyret	= CCIS_ERR_UNKNOW_ERROR & ERRCODE_MASK;
						ccis_log_warning("[ip:%s]身份证核验未知错误！" , ch->r_ip);
					}
				}
			}
			Insert_Info_To_DB(log_node , CCIS_RECEIVE_ID_INFO);
			Free_IDInfo(pstID);
			pstID	= NULL;
		}break;
		case CCIS_RECEIVE_ID_PHOTO:{
			response->head.type	= CCIS_RECEIVE_ID_PHOTO;
			response_len	= sizeof(CTLMsg);

			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}

			if (Check_Process_Flow(&log_node->cur_flow , CCIS_RECEIVE_ID_PHOTO))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			retv	= Receive_ID_Photo(log_node , msg.buffer , msg.body.bufLen , msg.head.status);
			switch(retv)
			{
				case 0:{
					if (unlikely(msg.head.status == CCIS_PACKAGE_FINISHED))
					{
						response->head.errcode	= CCIS_ID_PHOTO_SAVE_SUCCESS;
						ccis_log_info("[%s]身份证照片%s已接收完毕！" , log_node->querysn , log_node->idpic_path);
						Update_Condition(log_node , "done");
						if (Check_Newer_Log(log_node->querysn , log_node->lastpackage) == 0)
							Insert_Info_To_DB(log_node , CCIS_RECEIVE_ID_PHOTO);
					}
					else
					{
						Update_Condition(log_node , "incomplete");
						rep_sign	= 0;				//不回包
					}
				}break;
				default:{
					retv	= 1;
					ccis_log_err("[%s]身份证照片%s接收失败！" , log_node->querysn , log_node->idpic_path);
					response->head.errcode	= CCIS_ID_PHOTO_SAVE_FAILED;
					Update_Condition(log_node , "failed");
					log_node->falres	|= CCIS_ERR_ID_IDPHOTO_RECV_FAILED;
				}
			}
		}break;
		case CCIS_RECEIVE_VIS_PHOTO:{
			response->head.type	= CCIS_RECEIVE_VIS_PHOTO;
			response_len	= sizeof(CTLMsg);
			
			if(!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}

			SET_PROCCODE(log_node->falres , CCIS_PROC_FACE_MATCH);
			if (Check_Process_Flow(&log_node->cur_flow , CCIS_RECEIVE_VIS_PHOTO))
			{
				retv	= 1;
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				response->head.errcode	= CCIS_PROCESS_INVALID;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			retv	= Receive_Vis_Photo(log_node , msg.buffer , msg.body.bufLen , msg.head.status);
			switch(retv)
			{
				case 0:{
					if (unlikely(msg.head.status == CCIS_PACKAGE_FINISHED))
					{
						ccis_log_info("[%s]现场照片%s接收完毕，即将开始人脸比对..." , log_node->querysn , log_node->sppic_path);
						retv = Face_Check(log_node->ctrscr , &log_node->rctrscr , log_node->sppic_path , log_node->idpic_path , log_node->authpic_path , &(log_node->comp_time));
						if (!retv)
						{
							ccis_log_info("[%s]人脸比对通过！比对分值：%f" , log_node->querysn , log_node->rctrscr);
							log_node->retry_time	= 0;
							Update_Condition(log_node , "matched");
							response->head.errcode	= CCIS_FM_COMPARE_PASS;
							sprintf(response->body.reseve , "%d" , report_limit);
							RESET_ERRCODE(log_node->falres);
						}
						else
						{
							if (log_node->retry_time == 0)
							{
								log_node->retry_time ++;
								ccis_log_info("[%s]人脸比对不通过！比对分值：%f，允许执行重试" , log_node->querysn , log_node->rctrscr);
								Update_Condition(log_node , "retry");
								response->head.errcode	= CCIS_FM_COMPARE_NOT_MATCH;
								log_node->falres	|= CCIS_ERR_FM_COMPARE_NOT_PASS;
							}
							else
							{
								response->head.errcode	= CCIS_FM_COMPARE_NOT_MATCH;
								Update_Condition(log_node , "not_matched");
								ccis_log_info("[%s]人脸比对不通过！比对分值：%f，重试次数已超限" , log_node->querysn , log_node->rctrscr);
								log_node->falres	|= CCIS_ERR_FM_COMPARE_NOT_PASS;
							}
						}
						if (Check_Newer_Log(log_node->querysn , log_node->lastpackage) == 0)
							Insert_Info_To_DB(log_node , CCIS_RECEIVE_VIS_PHOTO);
					}
					else
					{
						Update_Condition(log_node , "incomplete");
						rep_sign	= 0;
					}
				}break;
				default:{
					ccis_log_err("[%s]现场照片接收未知错误！" , log_node->querysn);
					retv	= 1;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_FM_VIS_PHOTO_RECV_FAILED;
					log_node->falres	|= CCIS_ERR_FM_VIS_PHOTO_RECV_ERR;
					if (Check_Newer_Log(log_node->querysn , log_node->lastpackage) == 0)
						Insert_Info_To_DB(log_node , CCIS_RECEIVE_VIS_PHOTO);
				}
			}
		}break;
		case CCIS_DOWNLOAD_REPORT:{
			response->head.type	= CCIS_DOWNLOAD_REPORT;
			response_len	= sizeof(CTLMsg);
			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}

			SET_PROCCODE(log_node->falres , CCIS_PROC_REPORT_WORKING);
			if (Check_Process_Flow(&log_node->cur_flow , CCIS_DOWNLOAD_REPORT))
			{
				retv	= 1;
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				response->head.errcode	= CCIS_PROCESS_INVALID;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}
			int report_type	= atoi(msg.body.reseve);
			if (report_type == 0)
			{
				if ((report_limit & 2) == 0)
					strcpy(log_node->report_type , REPORT_SIMPLE);
				else
					strcpy(log_node->report_type , REPORT_NORMAL);
			}
			else if ((report_limit & report_type) != 0)
			{
				if (report_type == 1)
					strcpy(log_node->report_type , REPORT_SIMPLE);
				else if (report_type == 2)
					strcpy(log_node->report_type , REPORT_NORMAL);
				else
				{
					retv	= 1;
					ccis_log_err("[%s]所选报告类型%d不被支持！服务器当前支持类型：%d" , log_node->querysn , report_type , report_limit);
					sprintf(response->body.reseve , "%d" , report_limit);		//同时将支持的类型再次返回给客户端
					response->head.errcode	= CCIS_RP_TYPE_INVALID;
					break;
				}
			}
			else
			{
				retv	= 1;
				ccis_log_err("[%s]所选报告类型%d不被支持！服务器当前支持类型：%d" , log_node->querysn , report_type , report_limit);
				sprintf(response->body.reseve , "%d" , report_limit);
				response->head.errcode	= CCIS_RP_TYPE_INVALID;
				break;
			}

			if (!Init_Curl())
			{
				retv	= Receive_PhoneNumber(log_node , ring , response->buffer , msg.buffer , ch->ssl);
				Clean_Curl();
			}
			else
			{
				ccis_log_err("[%s]Curl初始化失败！" , log_node->querysn);
				retv	= 8;
			}
			ccis_log_debug("[%s]Receive_PhoneNumber returned %d" , log_node->querysn , retv);
			switch(retv)
			{
				case 0:{		//报告发送成功
					Update_Condition(log_node , "success");
					ccis_log_info("[%s]报告发送成功！" , log_node->querysn);
					strcpy(log_node->querysgn , "2");		//将查询成功标识置2
					rep_sign	= 0;
				}break;
				case 1:{			//未打印报告
					retv	= 0;
					response_len	= sizeof(BSNMsg);
					Update_Condition(log_node , "unprint");
					ccis_log_info("[%s]存在未打印报告，正在等待用户选择..." , log_node->querysn);
					response->head.errcode	= CCIS_RP_UNPRINT_REPORT_EXIST;
				}break;
				case 2:{		//需要收费
					retv	= 0;
					Update_Condition(log_node , "charge");
					ccis_log_info("[%s]查询次数已超限，本次查询应当收费，正在等待用户选择..." , log_node->querysn);
					response->head.errcode	= CCIS_RP_SHOULD_CHARGE;
					response->head.status	= CCIS_PACKAGE_FINISHED;
					Get_Last_ChargeNum(log_node);
					sprintf(response->buffer , "%d" , log_node->chgnum);
					int tmp_type	= charge_type;
					if (log_node->chgnum)
						tmp_type	&= 0xFFFD;	//假如有上次未使用的收费金额，则暂时取消移动支付支持
					sprintf(response->body.reseve , "%d" , tmp_type);		//给出支持的支付方式
					response_len	= sizeof(BSNMsg);
				}break;
				case 3:{	//征信系统用户名或密码错误
					log_node->falres	|= CCIS_ERR_REP_USER_PWD_ERROR;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_QUERY_UP_ERROR;
					ccis_log_err("[%s]报告下载失败：征信系统用户名或密码错误！" , log_node->querysn);
				}break;
				case 4:{	//征信系统服务器连接失败
					log_node->falres	|= CCIS_ERR_REP_LINK_FAILED;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_QUERY_LINK_SERVER_FAILED;
					ccis_log_err("[%s]报告下载失败：征信系统服务器连接失败！" , log_node->querysn);
				}break;
				case 5:{	//获取报告号失败
					log_node->falres	|= CCIS_ERR_REP_INDEXNO_ERROR;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_REPNO_ERROR;
					ccis_log_err("[%s]报告下载失败：获取报告号失败！" , log_node->querysn);
				}break;
				case 6:{	//获取异议号失败
					log_node->falres	|= CCIS_ERR_REP_INDEXNO_ERROR;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_DISNO_ERROR;
					ccis_log_err("[%s]报告下载失败：获取异议号失败！" , log_node->querysn);
				}break;
				case 7:{	//获取收费信息失败
					log_node->falres	|= CCIS_ERR_REP_INDEXNO_ERROR;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_CHARGEINFO_ERROR;
					ccis_log_err("[%s]报告下载失败：获取收费信息失败！" , log_node->querysn);
				}break;
				default:{	//未知错误
					if ((log_node->falres & 0x0F) == 0)
						log_node->falres	|= CCIS_ERR_UNKNOW_ERROR;
					Update_Condition(log_node , "failed");
					ccis_log_err("[%s]报告下载失败：征信查询系统未知错误！" , log_node->querysn);
					response->head.errcode	= CCIS_UNKNOW_ERROR;
				}
			}
			if (Check_Newer_Log(log_node->querysn , log_node->lastpackage) == 0)
				Insert_Info_To_DB(log_node , CCIS_DOWNLOAD_REPORT);
		}break;
		case CCIS_DOWNLOAD_REPORT_EXIST:{
			response->head.type	= CCIS_DOWNLOAD_REPORT_EXIST;
			response_len	= sizeof(CTLMsg);
			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				retv	= 1;
				break;
			}
			SET_PROCCODE(log_node->falres , CCIS_PROC_REPORT_WORKING);
			if (Check_Process_Flow(&log_node->cur_flow , CCIS_DOWNLOAD_REPORT_EXIST))
			{
				response->head.errcode	= CCIS_PROCESS_INVALID;
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			retv	= Send_Old_Report(log_node , ring , ch->ssl);

			if (!retv)
			{
				ccis_log_info("[%s]未打印报告(%s)发送成功！" , log_node->querysn , log_node->report_path);
				retv	= Update_Unprint_Sign(log_node->idnum , log_node->querysn , CCIS_DOWNLOAD_REPORT_EXIST , NULL , &(log_node->unprint_up_flag));
				Update_Condition(log_node , "success");
				strcpy(log_node->querysgn , "2");		//将查询成功标识置2,表示下载报告成功
				rep_sign	= 0;
			}
			else
			{
				ccis_log_err("[%s]未打印报告(%s)发送失败！" , log_node->querysn , log_node->report_path);
				Update_Condition(log_node , "failed");
				response->head.errcode	= CCIS_RP_DOWNLOAD_FAILED;
				log_node->falres	|= CCIS_ERR_REP_REPORT_SEND_FAILED;
			}
			if (Check_Newer_Log(log_node->querysn , log_node->lastpackage) == 0)
				Insert_Info_To_DB(log_node , CCIS_DOWNLOAD_REPORT_EXIST);
		}break;
		case CCIS_DOWNLOAD_REPORT_NEW:{
			response->head.type	= CCIS_DOWNLOAD_REPORT_NEW;
			response_len	= sizeof(CTLMsg);

			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}
			SET_PROCCODE(log_node->falres , CCIS_PROC_REPORT_WORKING);
			if (Check_Process_Flow(&log_node->cur_flow , CCIS_DOWNLOAD_REPORT_NEW))
			{
				retv	= 1;
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}
			if (!Init_Curl())
			{
				retv	= Download_New_Report(log_node , ring , ch->ssl);
				Clean_Curl();
			}
			else
				retv	= 8;
			ccis_log_debug("[%s]Download_New_Report returned %d" , log_node->querysn , retv);
			switch(retv)
			{
				case 0:{		//报告发送成功
					Update_Unprint_Sign(log_node->idnum , log_node->querysn , CCIS_DOWNLOAD_REPORT_NEW , log_node->old_report_path , &(log_node->unprint_up_flag));
					Update_Condition(log_node , "success");
					ccis_log_info("[%s]报告发送成功！" , log_node->querysn);
					strcpy(log_node->querysgn , "2");		//将查询成功标识置2
					rep_sign	= 0;
				}break;
				case 2:{		//需要收费
					retv	= 0;
					Update_Condition(log_node , "charge");
					ccis_log_info("[%s]查询次数已超限，本次查询应当收费，正在等待用户选择..." , log_node->querysn);
					response->head.errcode	= CCIS_RP_SHOULD_CHARGE;
					response->head.status	= CCIS_PACKAGE_FINISHED;
					Get_Last_ChargeNum(log_node);
					sprintf(response->buffer , "%d" , log_node->chgnum);
					int tmp_type	= charge_type;
					if (log_node->chgnum)
						tmp_type	&= 0xFFFD;	//假如有上次未使用的收费金额，则暂时取消移动支付支持
					sprintf(response->body.reseve , "%d" , tmp_type);		//给出支持的支付方式
					response_len	= sizeof(BSNMsg);
				}break;
				case 3:{	//征信系统用户名或密码错误
					log_node->falres	|= CCIS_ERR_REP_USER_PWD_ERROR;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_QUERY_UP_ERROR;
					ccis_log_err("[%s]报告下载失败：征信系统用户名或密码错误！" , log_node->querysn);
				}break;
				case 4:{	//征信系统服务器连接失败
					log_node->falres	|= CCIS_ERR_REP_LINK_FAILED;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_QUERY_LINK_SERVER_FAILED;
					ccis_log_err("[%s]报告下载失败：征信系统服务器连接失败！" , log_node->querysn);
				}break;
				case 5:{	//获取报告号失败
					log_node->falres	|= CCIS_ERR_REP_INDEXNO_ERROR;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_REPNO_ERROR;
					ccis_log_err("[%s]报告下载失败：获取报告号失败！" , log_node->querysn);
				}break;
				case 6:{	//获取异议号失败
					log_node->falres	|= CCIS_ERR_REP_INDEXNO_ERROR;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_DISNO_ERROR;
					ccis_log_err("[%s]报告下载失败：获取异议号失败！" , log_node->querysn);
				}break;
				case 7:{	//获取收费信息失败
					log_node->falres	|= CCIS_ERR_REP_INDEXNO_ERROR;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_CHARGEINFO_ERROR;
					ccis_log_err("[%s]报告下载失败：获取收费信息失败！" , log_node->querysn);
				}break;
				default:{		//未知错误
					if ((log_node->falres & 0x0F) == 0)
						log_node->falres	|= CCIS_ERR_UNKNOW_ERROR;
					Update_Condition(log_node , "failed");
					ccis_log_warning("[%s]报告查询未知错误！" , log_node->querysn);
					response->head.errcode	= CCIS_UNKNOW_ERROR;
				}
			}
			if (Check_Newer_Log(log_node->querysn , log_node->lastpackage) == 0)
				Insert_Info_To_DB(log_node , CCIS_DOWNLOAD_REPORT);
		}break;
		case CCIS_OLCHG_REQUEST:{		//申请移动支付
			response->head.type	= CCIS_OLCHG_REQUEST;
			response_len		= sizeof(CTLMsg);
			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}
			SET_PROCCODE(log_node->falres , CCIS_PROC_OLCHG);

			if (Check_Process_Flow(&log_node->cur_flow , CCIS_OLCHG_REQUEST))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			if ((charge_type & 2) == 0)
			{
				response->head.errcode	= CCIS_OLCHG_NOTSUPPORT;
				ccis_log_err("[%s]收费失败：服务器不支持移动支付方式！" , msg.body.querysn);
				break;
			}

			Update_Condition(log_node , "waiting");

			OlchgArgs* args	= OnlineCharge_InitArgs(log_node , ring , ch->ssl);
			if (!args)
			{
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				ccis_log_err("[%s]收费失败：移动支付参数初始化失败！" , msg.body.querysn);
				break;
			}

			if (Create_ASync_Thread((void*)OnlineCharge_Request , (void*)args , &(log_node->t_list)))
			{
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				ccis_log_err("[%s]收费失败：移动支付线程创建失败！%s" , msg.body.querysn , strerror(errno));
				break;
			}
			ccis_log_info("[%s]移动支付线程已创建" , msg.body.querysn);

			rep_sign	= 0;
		}break;
		case CCIS_OLCHG_RECONFIRM:{		//获取移动支付结果
			response->head.type	= CCIS_OLCHG_RECONFIRM;
			response_len		= sizeof(CTLMsg);
			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}

			if (Check_Process_Flow(&log_node->cur_flow , CCIS_OLCHG_RECONFIRM))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			if (log_node->olchg_status == OLCHG_STATUS_SUCCESS)
			{
				response->head.errcode	= CCIS_OLCHG_SUCCESS;
				ccis_log_debug("[%s]移动支付重新确认：移动支付收款成功！" , msg.body.querysn);
				Update_Condition(log_node , "success");
				break;
			}

			OlchgArgs* args	= OnlineCharge_InitArgs(log_node , ring , ch->ssl);
			if (!args)
			{
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				ccis_log_err("[%s]移动支付重确认失败：移动支付参数初始化失败！" , msg.body.querysn);
				break;
			}

			if (Create_ASync_Thread((void*)OnlineCharge_Reconfirm , (void*)args , &(log_node->t_list)))
			{
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				ccis_log_err("[%s]移动支付重确认失败：移动支付线程创建失败！%s" , msg.body.querysn , strerror(errno));
				break;
			}
			ccis_log_info("[%s]移动支付重确认线程已创建" , msg.body.querysn);
			rep_sign	= 0;
		}break;
		case CCIS_OLCHG_REFUNDS:{		//移动支付退款
			response->head.type	= CCIS_OLCHG_REFUNDS;
			response_len		= sizeof(CTLMsg);
			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}

			if (Check_Process_Flow(&log_node->cur_flow , CCIS_OLCHG_REFUNDS))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			if (Create_ASync_Thread((void*)OnlineCharge_Refunds , NULL , &(log_node->t_list)))
			{
				response->head.errcode	= CCIS_UNKNOW_ERROR;
				ccis_log_err("[%s]收费失败：移动支付线程创建失败！%s" , msg.body.querysn , strerror(errno));
				break;
			}
			ccis_log_info("[%s]移动支付退款线程已创建" , msg.body.querysn);
			rep_sign	= 0;
		}break;
		case CCIS_GET_CHARGE_RESULT:{
			response->head.type	= CCIS_GET_CHARGE_RESULT;
			response_len		= sizeof(CTLMsg);
			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}

			SET_PROCCODE(log_node->falres , CCIS_PROC_CHARGE);
			if (Check_Process_Flow(&log_node->cur_flow , CCIS_GET_CHARGE_RESULT))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			retv	= Get_Charge_Result(log_node , msg.buffer);

			switch(retv)
			{
				case 0:{				//收费成功，返回已收总金额数量
					ccis_log_notice("[%s]收费成功！当前收费总金额：%d元" , log_node->querysn , log_node->chgnum);
					sprintf(response->buffer , "%d" , log_node->chgnum);
					response_len	= sizeof(BSNMsg);
					response->head.errcode	= CCIS_CHARGE_CONFIRM_SUCCESS;
					Update_Condition(log_node , "success");
				}break;
				default:{
					log_node->falres	|= CCIS_ERR_CHG_GETINFO_FAILED;
					ccis_log_alert("[%s]收费信息获取未知错误！" , log_node->querysn);
					response->head.errcode	= CCIS_RP_QUERY_UNKNOW_ERROR;
					Update_Condition(log_node , "failed");
				}
			}
		}break;
		case CCIS_RETREAT_CHARGE:{
			response->head.type	= CCIS_RETREAT_CHARGE;
			response_len		= sizeof(CTLMsg);

			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}

			SET_PROCCODE(log_node->falres , CCIS_PROC_CHARGE);
			if (Check_Process_Flow(&log_node->cur_flow , CCIS_RETREAT_CHARGE))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			retv	= Retreat_Charge_Log(log_node);
			if (retv == 0)
			{
				ccis_log_notice("[%s]用户退费已成功！" , log_node->querysn);
				response->head.errcode	= CCIS_CHARGE_RETREAT_SUCCESS;
				Update_Condition(log_node , "success");
				log_node->falres	|= CCIS_ERR_CHG_RETREATED;
			}
			else
			{
				response->head.errcode	= CCIS_CHARGE_RETREAT_FAILED;
				ccis_log_alert("[%s]用户退费失败，请联系管理员！" , log_node->querysn);
				Update_Condition(log_node , "failed");
				log_node->falres	|= CCIS_ERR_CHG_RETREAT_FAILED;
			}
		}break;
		case CCIS_DOWNLOAD_REPORT_CHARGE:{
			response->head.type	= CCIS_DOWNLOAD_REPORT_CHARGE;
			response_len		= sizeof(CTLMsg);

			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}

			log_node->falres	|= CCIS_PROC_REPORT_WORKING;

			if (Check_Process_Flow(&log_node->cur_flow , CCIS_DOWNLOAD_REPORT_CHARGE))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			if (!Init_Curl())
			{
				retv	= Download_Charge_Report(log_node , ring , ch->ssl);
				Clean_Curl();
			}
			else
			{
				ccis_log_err("[%s]Curl初始化失败！" , log_node->querysn);
				retv	= 8;
			}

			switch(retv)
			{
				case 0:{
					rep_sign	= 0;
					ccis_log_info("[%s]报告发送成功！" , log_node->querysn);
					strcpy(log_node->querysgn , "2");		//将查询成功标识置2
					if (log_node->unprint_up_flag)
						Update_Unprint_Sign(log_node->idnum , log_node->querysn , CCIS_DOWNLOAD_REPORT_CHARGE , log_node->old_report_path , &(log_node->unprint_up_flag));
					Update_Condition(log_node , "success");
				}break;
				case 2:{		//金额不够
					ccis_log_err("[%s]用户收费金额不足！当前收费%d元" , log_node->querysn ,log_node->chgnum);
					response->head.errcode	= CCIS_CHARGE_NOT_ENOUGH;
					Update_Condition(log_node , "not_enough");
				}break;
				case 3:{
					ccis_log_err("[%s]征信系统用户名或密码错误！" , log_node->querysn);
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_QUERY_UP_ERROR;
					log_node->falres	|= CCIS_ERR_REP_USER_PWD_ERROR;
				}break;
				case 4:{
					ccis_log_err("[%s]征信中心服务器连接失败！" , log_node->querysn);
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_QUERY_LINK_SERVER_FAILED;
					log_node->falres	|= CCIS_ERR_REP_LINK_FAILED;
				}break;
				case 5:{
					ccis_log_err("[%s]报告号获取失败！" , log_node->querysn);
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_REPNO_ERROR;
					log_node->falres	|= CCIS_ERR_REP_INDEXNO_ERROR;
				}break;
				case 6:{
					ccis_log_err("[%s]异议号获取失败！" , log_node->querysn);
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_DISNO_ERROR;
					log_node->falres	|= CCIS_ERR_REP_INDEXNO_ERROR;
				}break;
				case 7:{	//获取收费信息失败
					log_node->falres	|= CCIS_ERR_REP_INDEXNO_ERROR;
					Update_Condition(log_node , "failed");
					response->head.errcode	= CCIS_RP_CHARGEINFO_ERROR;
					ccis_log_err("[%s]报告下载失败：获取收费信息失败！" , log_node->querysn);
				}break;
				default:{
					response->head.errcode	= CCIS_RP_QUERY_UNKNOW_ERROR;
					Update_Condition(log_node , "failed");
					ccis_log_warning("[%s]收费报告查询未知错误！" , log_node->querysn);
					if ((log_node->falres & 0x0F) == 0)
						log_node->falres	|= CCIS_ERR_REP_OTHER_ERROR;
				}
			}

			if (!Check_Newer_Log(log_node->querysn , log_node->lastpackage))
				Insert_Info_To_DB(log_node , CCIS_DOWNLOAD_REPORT_CHARGE);
		}break;
		case CCIS_GET_PRINT_RESULT:{
			response->head.type	= CCIS_GET_PRINT_RESULT;
			response_len	= sizeof(CTLMsg);
			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}

			if (Check_Process_Flow(&log_node->cur_flow , CCIS_GET_PRINT_RESULT))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				log_node->falres	|= CCIS_ERR_GLOBAL_PROCESS_INVALID;
				Update_Condition(log_node , "failed");
				break;
			}

			Get_Print_Result(log_node , msg.head.errcode);
			if (auto_upload)
			{
				char* orgname	= NULL;
				char* devname	= NULL;
				do{
					orgname	= (char*)malloc(CCIS_MIDSIZE * sizeof(char));
					if (!orgname)
					{
						ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
						ccis_log_err("[%s]上传失败！" , log_node->querysn);
						break;
					}
					devname	= (char*)malloc(CCIS_MIDSIZE * sizeof(char));
					if (!devname)
					{
						ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
						ccis_log_err("[%s]上传失败！" , log_node->querysn);
						break;
					}
					if (Get_OrgDevName(log_node->orgid , log_node->devsn , orgname , devname))
					{
						ccis_log_err("征信机构名称/设备名称获取失败！");
						ccis_log_err("[%s]上传失败！" , log_node->querysn);
						break;
					}
					pSearch_Log tmp_node	= Dump_Log_Node(log_node);
					if (unlikely(!tmp_node))
					{
						ccis_log_err("[%s]自动上传失败！" , tmp_node->querysn);
					}
					else
					{
						strcpy(tmp_node->orgname , orgname);
						strcpy(tmp_node->devname , devname);
						if (Create_ASync_Thread((void*)Upload_CU_Thread , (void*)tmp_node , NULL))
							ccis_log_err("[%s]自动上传失败！" , tmp_node->querysn);
						else
							ccis_log_info("[%s]自动上传线程已创建，请等待上传结果..." , tmp_node->querysn);
						//free(tmp_node);		//会导致线程中变量乱码，回收移至上传函数中做
					}
					break;
				}while(0);
				if (orgname)
					free(orgname);
				if (devname)
					free(devname);
			}
			Business_Done(log_node);
			response->head.errcode	= CCIS_SUCCESS;
		}break;
		case CCIS_WORK_DONE:{
			response->head.type	= CCIS_WORK_DONE;
			response_len	= sizeof(CTLMsg);
			retv	= 0;
			response->head.errcode	= CCIS_SUCCESS;
			if (!log_node)
			{
				break;
			}

			if (!strcmp(log_node->querysgn , "0"))
				strcpy(log_node->querysgn , "1");
			ccis_log_info("[%s]流程即将结束..." , log_node->querysn);
			if (Check_Newer_Log(log_node->querysn , log_node->lastpackage) == 0)
			{
				if (auto_upload)
				{
					char* orgname	= NULL;
					char* devname	= NULL;
					do{
						orgname	= (char*)malloc(CCIS_MIDSIZE * sizeof(char));
						if (!orgname)
						{
							ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
							ccis_log_err("[%s]上传失败！" , log_node->querysn);
							break;
						}
						devname	= (char*)malloc(CCIS_MIDSIZE * sizeof(char));
						if (!devname)
						{
							ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
							ccis_log_err("[%s]上传失败！" , log_node->querysn);
							break;
						}
						if (Get_OrgDevName(log_node->orgid , log_node->devsn , orgname , devname))
						{
							ccis_log_err("征信机构名称获取失败！");
							ccis_log_err("[%s]上传失败！" , log_node->querysn);
							break;
						}
						pSearch_Log tmp_node	= Dump_Log_Node(log_node);
						if (unlikely(!tmp_node))
						{
							ccis_log_err("[%s]自动上传失败！" , tmp_node->querysn);
						}
						else
						{
							strcpy(tmp_node->orgname , orgname);
							strcpy(tmp_node->devname , devname);
							if (Create_ASync_Thread((void*)Upload_CU_Thread , (void*)tmp_node , NULL))
								ccis_log_err("[%s]自动上传失败！" , tmp_node->querysn);
							else
								ccis_log_info("[%s]自动上传线程已创建，请等待上传结果..." , tmp_node->querysn);
						}
					}while(0);
					if (orgname)
						free(orgname);
					if (devname)
						free(devname);
				}
				Business_Done(log_node);
			}

		}break;
		case CCIS_RESEND_REPORT:{
			response->head.type	= CCIS_RESEND_REPORT;
			response_len	= sizeof(CTLMsg);
			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}
			if (Check_Process_Flow(&log_node->cur_flow , CCIS_RESEND_REPORT))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				break;
			}
			if (log_node->retry_time > 1)		//重发次数超限
			{
				ccis_log_err("[%s]报告重发次数超限，不予执行重发流程！" , log_node->querysn);
				response->head.errcode	= CCIS_RP_RETRY_DENY;
				Update_Condition(log_node , "failed");
				retv	= 1;
				break;
			}
			retv	= Resend_Report(log_node , ring , ch->ssl);
			if (retv)
			{
				ccis_log_err("[%s]报告重发失败！" , log_node->querysn);
				log_node->falres	|= CCIS_ERR_UNKNOW_ERROR;
				response->head.errcode	= CCIS_RP_DOWNLOAD_FAILED;
				Update_Condition(log_node , "failed");
				retv	= 1;
			}
			else
			{
				ccis_log_info("[%s]报告重发成功！" , log_node->querysn);
				Update_Condition(log_node , "success");
				rep_sign	= 0;
			}

			log_node->retry_time ++;
		}break;
		case CCIS_RESEND_REPORT_NOEN:{
			response->head.type	= CCIS_RESEND_REPORT_NOEN;
			response_len	= sizeof(CTLMsg);
			if (!log_node)
			{
				ccis_log_err("[%s]未找到对应的查询节点！" , msg.body.querysn);
				retv	= 1;
				response->head.errcode	= CCIS_NO_PRE_LOG_NODE;
				break;
			}
			if (Check_Process_Flow(&log_node->cur_flow , CCIS_RESEND_REPORT_NOEN))
			{
				ccis_log_err("[%s]流程非法！当前已完成流程：%d，当前条件：%s，期望执行：0x%x" , log_node->querysn , log_node->cur_flow.node_index , log_node->cur_flow.Condition , msg.head.type);
				retv	= 1;
				response->head.errcode	= CCIS_PROCESS_INVALID;
				break;
			}
			if (log_node->retry_time > 1)
			{
				ccis_log_err("[%s]报告重发次数超限，不予执行重发流程！" , log_node->querysn);
				response->head.errcode	= CCIS_RP_RETRY_DENY;
				Update_Condition(log_node , "failed");
				retv	= 1;
				break;
			}
			retv	= Resend_Report_NoEN(log_node , ring , ch->ssl);
			if (retv)
			{
				ccis_log_err("[%s]报告重发失败！" , log_node->querysn);
				log_node->falres	|= CCIS_ERR_UNKNOW_ERROR;
				response->head.errcode	= CCIS_RP_DOWNLOAD_FAILED;
				Update_Condition(log_node , "failed");
				retv	= 1;
			}
			else
			{
				ccis_log_info("[%s]报告重发成功！" , log_node->querysn);
				Update_Condition(log_node , "success");
				rep_sign	= 0;
			}
			log_node->retry_time ++;
		}break;
		default:{
			rep_sign	= 0;
		};
	}
clean_up:
	if (rep_sign)
	{
		if (log_node)
			strcpy(response->body.querysn , log_node->querysn);
		Write_Msg(ch->ssl , (void*)response , response_len);
	}
	free(response);
	return retv;
}

int Update_Condition(pSearch_Log log_node , char* condition)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!condition)
		strcpy(log_node->cur_flow.Condition , "none");
	else
		strcpy(log_node->cur_flow.Condition , condition);
	return 0;
}
