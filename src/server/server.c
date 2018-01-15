#include "server.h"
#include "../network/network.h"
#include "stdio.h"
#include "errno.h"
#include "string.h"
#include "pbc/pbc.h"
#include "../other/ccis_compress.h"
#include "../database/dbquery.h"
#include "../security/security.h"
#include "../log/ccis_log.h"
#include "../other/ccis_time.h"

void	Print_Log_Struct(pSearch_Log log_node);
int	Analyze_ID_Info(char* idinfo , pID_Info pstID);						//将信息字符串转换为ID_Info结构体
pSearch_Log	Find_LastBusiness(const char* idnum , const char* devsn);			//查找是否存在未完成节点
void	Analyze_FlowProcess(pSearch_Log log_node , int* type , int* errcode);			//解析falres字段以确定type与errcode，并设置流程节点
int	Make_User_Info_Struct(pSearch_Log log_node , struct UserInfoStruct* pstUserInfo);	//创建用户信息结构体
int	Check_ID_Info(pSearch_Log log_node , pRing ring , pID_Info pstID , char* devsn);	//检测身份证信息合法性
int	Get_Querysn(pSearch_Log log_node);							//插入数据库获取querysn
int	Receive_ID_Photo(pSearch_Log log_node, char* photobuf , int bufLen , int status);	//接收身份证照片
int	Receive_Vis_Photo(pSearch_Log log_node , char* photobuf , int bufLen , int status);	//接收现场照片并执行人脸比对
int	Receive_Inf_Photo(pSearch_Log log_node , char* photobuf , int bufLen , int status);	//接收红外照片
int	Receive_PhoneNumber(pSearch_Log log_node , pRing ring , char* buffer , char* phonenumber , SSL* ssl);	//接收手机号并且查找上次未打印报告/下载新报告
int	Get_Last_ChargeNum(pSearch_Log log_node);						//获取上次收费金额
int	Download_New_Report(pSearch_Log log_node , pRing ring , SSL* ssl);			//下载&发送新报告
int	Get_Unprint_Report(char* idnum , char* buffer , char* old_report_path , char* old_repno , char* report_type , bool* unprint_up_flag);	//查询是否有未打印报告
int	Send_Old_Report(pSearch_Log log_node , pRing ring , SSL* ssl);				//发送未打印报告
int	Resend_Report(pSearch_Log log_node , pRing ring , SSL* ssl);				//报告重发
int	Resend_Report_NoEN(pSearch_Log log_node , pRing ring , SSL* ssl);			//报告重发(非加密格式)
int	Compress_Encrypt_Send_Report(pSearch_Log log_node , pRing ring , SSL* ssl , int type , char* en_md5);	//压缩、加密并发送报告
int	Send_String_To_Client(char* buf_str , int length , BSNMsg response , SSL* ssl);		//发送长字符串
int	Send_File(SSL* ssl , char* filepath , int type , int errcode , char* querysn);		//发送文件
int	Send_Report_To_Client(SSL* ssl , pSearch_Log log_node , pRing ring , int type , int errcode);	//将报告发送给客户端
int	Get_Charge_Result(pSearch_Log log_node , char* chargebuf);				//获取收费结果
int	Retreat_Charge_Log(pSearch_Log log_node);						//退币操作
int	Download_Charge_Report(pSearch_Log log_node , pRing ring ,  SSL* ssl);			//下载并发送收费报告
int	Get_Print_Result(pSearch_Log log_node , int p_result);					//获取打印结果
int	Update_Unprint_Sign(char* idnum , char* ignore_querysn , int sign , const char* old_report_path , bool* unprint_up_flag);	//更新上次未打印报告的标记
int	Insert_Info_To_DB(pSearch_Log log_node , int type);					//实时入库函数，根据type决定需要入库的数据
int	Business_Done(pSearch_Log log_node);							//流程结束
void	Free_IDInfo(pID_Info pstID);
int	Check_Newer_Log(char* querysn , time_t lastpackage);					//当前记录与数据库中的记录相对比最后报文时间，内存中的时间更大时返回0
int	Upload_Log_Node(pSearch_Log log_node);
int	Get_OrgDevName(const char* orgid , const char* devsn , char* orgname , char* devname);	//获取征信机构名称和设备名称
int	Cleanup_ExpiredReport();								//清理过期的未打印报告
int	Correct_DataBase();									//校准当日查询记录

void Print_Log_Struct(pSearch_Log log_node)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	ccis_log_debug("********************************************");
	ccis_log_debug("查询时间:\t%s" , log_node->querydt);
	ccis_log_debug("来源设备:\t%s" , log_node->devsn);
	ccis_log_debug("来源网点:\t%s" , log_node->orgid);
	ccis_log_debug("查询序列号:\t%s", log_node->querysn);
	ccis_log_debug("身份证号码:\t%s", log_node->idnum);
	ccis_log_debug("姓名:\t\t%s", log_node->idname);
	ccis_log_debug("性别:\t\t%s", log_node->idsex);
	ccis_log_debug("民族:\t\t%s", log_node->nation);
	ccis_log_debug("生日:\t\t%s", log_node->birthdt);
	ccis_log_debug("住址:\t\t%s", log_node->addr);
	ccis_log_debug("有效期:\t\t%s-%s", log_node->idstartdt, log_node->idenddt);
	ccis_log_debug("签发机关:\t%s", log_node->issauth);
	ccis_log_debug("人脸比对阈值:\t%f" , log_node->ctrscr);
	ccis_log_debug("人脸比对分值:\t%f" , log_node->rctrscr);
	ccis_log_debug("手机号码:\t%s" , log_node->phonenum);
	ccis_log_debug("已收费金额:\t%d" , log_node->chgnum);
	ccis_log_debug("身份证照片路径:\t%s", log_node->idpic_path);
	ccis_log_debug("公安部照片路径:\t%s", log_node->authpic_path);
	ccis_log_debug("现场照片路径:\t%s", log_node->sppic_path);
	ccis_log_debug("征信报告路径:\t%s", log_node->report_path);
	ccis_log_debug("错误码:\t\t0x%x" , log_node->falres);
	ccis_log_debug("最后报文时间:\t%s" , Get_String_From_Time(&log_node->lastpackage));
	ccis_log_debug("当前执行流程:\t%s" , log_node->cur_flow.FlowName);
	ccis_log_debug("当前条件:\t%s" , log_node->cur_flow.Condition);
	ccis_log_debug("********************************************");
}

int Analyze_ID_Info(char* idinfo , pID_Info pstID)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int id_item_num	= sizeof(struct ID_Info) / sizeof(char*);
	if (Analyze_Info(idinfo , (char**)pstID , id_item_num , "+"))
	{
		ccis_log_err("用户身份证信息不完整！");
		return 1;
	}
	return 0;
}

pSearch_Log Find_LastBusiness(const char* idnum , const char* devsn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	/*
		先从log_list链表中查找该身份证号有没有未完成节点
		找不到再从数据库中找该身份证号以前的未完成查询记录
		select querysn,lastpackage from biz01 where idnum='idnum' and querysgn<>'1' and querysgn<>'2' order by querysn desc;
	*/
	if (!Search_List)
	{
		ccis_log_emerg("无法找到业务查询链表！");
		return NULL;
	}

	pSearch_Log tmp_node	= Search_List->log_node;
	pSearch_Log result	= NULL;
	char* sql_command	= NULL;
	char* sql_domain	= NULL;
	Query_Info* q_ret	= NULL;
	int undo		= 0;			
	int memory		= 0;

	Do_Connect();
	while (tmp_node)
	{
		if(!strcmp(tmp_node->devsn , devsn) && !strcmp(tmp_node->idnum , idnum))
		{
			result	= tmp_node;
			memory	= 1;
			goto clean_up;
		}
		tmp_node	= tmp_node->next;
	}

	sql_command	= (char*)malloc(CCIS_MIDSIZE * sizeof(char));
	if (!sql_command)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		result	= NULL;
		goto clean_up;
	}
	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		result	= NULL;
		goto clean_up;
	}
	sql_domain	= (char*)malloc(CCIS_MIDSIZE * sizeof(char));
	if (!sql_domain)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		result	= NULL;
		goto clean_up;
	}

	memset(sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);
	memset(q_ret , 0 , sizeof(Query_Info));
	sprintf(sql_command , "idnum='%s' and devsn='%s' and querysgn <> '1' and querysgn<>'2' order by querydt desc" , idnum , devsn);
	sprintf(sql_domain , "querysn,idnum,qyear,qnum,idtype,idname,idsex,nation,birthdt,addr,idstartdt,idenddt,issauth,orgid,chkret,devsn,querydt,phonenum,disid,chgno,repno,vfyret,rctrscr,ctrscr,querysgn,prtsgn,falres,lastpackage,chgnum,reptype,flow,condt,cptimes");
	int sql_ret	= DB_Select_Data("biz01" , sql_domain , sql_command , q_ret);
	if (sql_ret != 0)
	{
		if (sql_ret != -1)
			ccis_log_err("[%s:%d]Database Select Failed ! Errcode : %d" , __FUNCTION__ , __LINE__ , sql_ret);
		result	= NULL;
		goto clean_up;
	}
	else
	{
		result	= (pSearch_Log)malloc(sizeof(struct Search_Log));
		if (!result)
		{
			ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
			goto clean_up;
		}
		memset(result , 0 , sizeof(struct Search_Log));

		//解析biz01表数据
		if (q_ret->res_data[0][0])
			strcpy(result->querysn , q_ret->res_data[0][0]);
		if (q_ret->res_data[0][1])
			strcpy(result->idnum , q_ret->res_data[0][1]);
		if (q_ret->res_data[0][2])
			strcpy(result->qyear , q_ret->res_data[0][2]);
		if (q_ret->res_data[0][3])
			result->qnum	= atoi(q_ret->res_data[0][3]);
		if (q_ret->res_data[0][4])
			strcpy(result->idtype , q_ret->res_data[0][4]);
		if (q_ret->res_data[0][5])
			strcpy(result->idname , q_ret->res_data[0][5]);
		if (q_ret->res_data[0][6])
			strcpy(result->idsex , q_ret->res_data[0][6]);
		if (q_ret->res_data[0][7])
			strcpy(result->nation , q_ret->res_data[0][7]);
		if (q_ret->res_data[0][8])
			strcpy(result->birthdt , q_ret->res_data[0][8]);
		if (q_ret->res_data[0][9])
			strcpy(result->addr , q_ret->res_data[0][9]);
		if (q_ret->res_data[0][10])
			strcpy(result->idstartdt , q_ret->res_data[0][10]);
		if (q_ret->res_data[0][11])
			strcpy(result->idenddt , q_ret->res_data[0][11]);
		if (q_ret->res_data[0][12])
			strcpy(result->issauth , q_ret->res_data[0][12]);
		if (q_ret->res_data[0][13])
			strcpy(result->orgid , q_ret->res_data[0][13]);
		if (q_ret->res_data[0][14])
			strcpy(result->chkret , q_ret->res_data[0][14]);
		if (q_ret->res_data[0][15])
			strcpy(result->devsn , q_ret->res_data[0][15]);
		if (q_ret->res_data[0][16])
			strcpy(result->querydt , q_ret->res_data[0][16]);
		if (q_ret->res_data[0][17])
			strcpy(result->phonenum , q_ret->res_data[0][17]);
		if (q_ret->res_data[0][18])
			strcpy(result->disid , q_ret->res_data[0][18]);
		if (q_ret->res_data[0][19])
			strcpy(result->chgno , q_ret->res_data[0][19]);
		if (q_ret->res_data[0][20])
			strcpy(result->repno , q_ret->res_data[0][20]);
		if (q_ret->res_data[0][21])
			result->vfyret	= atoi(q_ret->res_data[0][21]);
		if (q_ret->res_data[0][22])
			result->rctrscr	= strtof(q_ret->res_data[0][22] , NULL);
		if (q_ret->res_data[0][23])
			result->ctrscr	= strtof(q_ret->res_data[0][23] , NULL);
		if (q_ret->res_data[0][24])
			strcpy(result->querysgn , q_ret->res_data[0][24]);
		if (q_ret->res_data[0][25])
			strcpy(result->prtsgn , q_ret->res_data[0][25]);
		if (q_ret->res_data[0][26])
			result->falres	= atoi(q_ret->res_data[0][26]);
		if (q_ret->res_data[0][28])
			result->lastpackage	= Get_Time_From_String(q_ret->res_data[0][28]);
		else
		{
			result	= NULL;
			goto clean_up;
		}
		if (q_ret->res_data[0][29])
			result->chgnum	= atoi(q_ret->res_data[0][29]);
		if (q_ret->res_data[0][30])
			strcpy(result->report_type , q_ret->res_data[0][30]);
		else
			sprintf(result->report_type , "%d" , report_limit);
		
		if (q_ret->res_data[0][31])
			result->cur_flow.node_index	= atoi(q_ret->res_data[0][31]);
		else
		{
			result	= NULL;
			goto clean_up;
		}
		if (q_ret->res_data[0][32])
			strcpy(result->cur_flow.Condition , q_ret->res_data[0][32]);
		else
		{
			result	= NULL;
			goto clean_up;
		}
		if (q_ret->res_data[0][33])
			result->comp_time	= atoi(q_ret->res_data[0][33]);

		memset(q_ret , 0 , sizeof(Query_Info));
		memset(sql_command , 0 , CCIS_MIDSIZE * sizeof(char));

		sprintf(sql_command , "querysn='%s'" , result->querysn);
		sprintf(sql_domain , "idpath,authpath,sppath,reppath");

		if (DB_Select_Data("biz02" , sql_domain , sql_command , q_ret))
		{
			ccis_log_err("[%s:%d] Database Select Failed" , __FUNCTION__ , __LINE__);
			undo	= 1;
			goto clean_up;
		}

		if (q_ret->res_data[0][0])
			strcpy(result->idpic_path , q_ret->res_data[0][1]);
		else
		{
			result	= NULL;
			goto clean_up;
		}
		if (q_ret->res_data[0][1])
			strcpy(result->authpic_path , q_ret->res_data[0][2]);
		else
		{
			result	= NULL;
			goto clean_up;
		}
		if (q_ret->res_data[0][2])
			strcpy(result->sppic_path , q_ret->res_data[0][3]);
		if (q_ret->res_data[0][3])
			strcpy(result->report_path , q_ret->res_data[0][5]);
	}
	
clean_up:
	Do_Close();
	if (result && !undo)			//有结果并且undo标记位不为1
	{
		time_t cur_time	= time(NULL);
		double passsec	= Compute_PassSecond(result->lastpackage , cur_time);
		if (passsec > interval_s)
		{
			char* str_time	= Get_String_From_Time(&result->lastpackage);
			if (!str_time)
			{
				ccis_log_debug("上次查询时间：未知");
				ccis_log_debug("上次查询序列号：%s" , result->querysn);
			}
			else
			{
				ccis_log_debug("上次查询时间：%s" , str_time);
				ccis_log_debug("上次查询序列号：%s" , result->querysn);
				free(str_time);
				str_time	= NULL;
			}
			str_time	= Get_String_From_Time(&cur_time);
			if (!str_time)
			{
				ccis_log_debug("当前查询时间：未知");
			}
			else
				ccis_log_debug("当前查询时间：%s" , str_time);
			free(str_time);
			ccis_log_debug("时间已超限，距离上次流程时间已过%.2f秒，允许维持时间：%d秒" , passsec , interval_s);
			//TODO:对于时间超限的查询，应该将其从内存中更新进数据库并且删除，或将其在数据库中的querysgn值置1，防止多次被查找出来
			Upload_Log_Node(result);
			if (memory)
				Free_Log_Node(result->querysn);
			result	= NULL;							
		}
	}
	else
		result	= NULL;
	if (sql_command)
	{
		free(sql_command);
		sql_command	= NULL;
	}
	if (sql_domain)
		free(sql_domain);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return result;
}

/*
	return values:
		0：成功
		1~8：失败，但是已经进入数据库
		9：失败，且未进入数据库
*/
int Check_ID_Info(pSearch_Log log_node , pRing ring , pID_Info pstID , char* devsn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	struct UserInfoStruct* pstUserInfo	= NULL;
	char* newpwd	= NULL;
	if (!pstID || !log_node)
	{
		retv	= 9;
		goto clean_up;
	}

	strncpy(log_node->idnum, pstID->id , sizeof(log_node->idnum) - 1);
	strncpy(log_node->idname, pstID->name , sizeof(log_node->idname) - 1);
	strncpy(log_node->idsex, pstID->sex , sizeof(log_node->idsex) - 1);
	strncpy(log_node->nation, pstID->nation , sizeof(log_node->nation) - 1);
	strncpy(log_node->birthdt, pstID->birthday , sizeof(log_node->birthdt) - 1);
	strncpy(log_node->addr, pstID->address , sizeof(log_node->addr) - 1);
	log_node->addr[strlen(log_node->addr)]	= '\0';
	strncpy(log_node->issauth, pstID->authority , sizeof(log_node->issauth) - 1);
	strncpy(log_node->devsn , devsn , sizeof(log_node->devsn) - 1);
	log_node->ctrscr = strtof(pstID->ctrscr, NULL);

	char* token	= strsep(&pstID->period , "-");
	if (token)
	{
		strncpy(log_node->idstartdt , token , sizeof (log_node->idstartdt) - 1);
		token	= strsep(&pstID->period , "-");
		if (token)
		{
			if(strcmp(token , "长期") == 0)
				strcpy(log_node->idenddt , "29991231");
			else
				strncpy(log_node->idenddt , token , sizeof (log_node->idenddt) - 1);
		}
		else
		{
			ccis_log_err("身份证有效期解析失败！");
			retv	= 9;
			goto clean_up;
		}
	}
	else
	{
		retv	= 9;
		goto clean_up;
	}

	int sqlerr	= Get_Querysn(log_node);
	if (sqlerr)
	{
		ccis_log_alert("[%s]无法获取查询序列号！" , log_node->idnum);
		retv	= 9;
		goto clean_up;
	}

	pstUserInfo	= (struct UserInfoStruct*)malloc(sizeof(struct UserInfoStruct));
	if (!pstUserInfo)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 8;
		goto clean_up;
	}
	if (Make_User_Info_Struct(log_node , pstUserInfo))
	{
		ccis_log_err("[%s]创建身份信息结构体失败！" , log_node->querysn);
		retv	= 8;
		goto clean_up;
	}

	retv	= Download_Police_Photo(ring->pbcinfo.User , ring->pbcinfo.Pwd , &newpwd , pstUserInfo , log_node->authpic_path , ring->agent);

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

clean_up:
	if (pstUserInfo)
	{
		free(pstUserInfo);
		pstUserInfo	= NULL;
	}
	if (newpwd)
		free(newpwd);
	return retv;
}

int Get_Querysn(pSearch_Log log_node)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	char* sql_command	= NULL;
	Query_Info* q_ret	= NULL;
	Do_Connect();
	sql_command	= (char*)malloc(CCIS_MAXSIZE * sizeof(char));
	if (!sql_command)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));
	sprintf(sql_command , "idnum='%s' order by querydt desc" , log_node->idnum);
	retv	= DB_Select_Data("biz01" , "qnum" , sql_command , q_ret);
	if (retv != 0)
	{
		if (retv != -1)
			ccis_log_err("[%s:%d]SQL查询错误！SQL返回码：%d" , __FUNCTION__ , __LINE__ , retv);
		log_node->qnum	= 1;
	}
	else
	{
		if (q_ret->res_data[0][0])
			log_node->qnum	= atoi(q_ret->res_data[0][0]) + 1;
		else
			log_node->qnum	= 1;
	}

	memset(sql_command , 0 , CCIS_MAXSIZE * sizeof(char));
	sprintf(sql_command , "'%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%f','%s','%s','%d','%s','%d'" , log_node->devsn , log_node->orgid , log_node->idnum,log_node->qyear,log_node->qnum,log_node->querydt,log_node->idtype,log_node->idname,log_node->idsex,log_node->nation,log_node->birthdt,log_node->addr,log_node->idstartdt,log_node->idenddt,log_node->issauth,log_node->ctrscr,log_node->querysgn,log_node->prtsgn,log_node->falres,log_node->querydt,log_node->cur_flow.node_index);
	retv	= DB_Insert_Data("biz01" , "devsn,orgid,idnum,qyear,qnum,querydt,idtype,idname,idsex,nation,birthdt,addr,idstardt,idenddt,issauth,ctrscr,querysgn,prtsgn,falres,rept,flow",sql_command);
	if (retv != 0)
	{
		ccis_log_err("[%s:%d] DB Insert Failed" , __FUNCTION__ , __LINE__);
		retv	= 1;
		goto clean_up;
	}


	memset(sql_command , 0 , CCIS_MAXSIZE * sizeof(char));
	sprintf(sql_command , "idnum='%s' and querydt='%s' " , log_node->idnum , log_node->querydt);
	memset(q_ret , 0 , sizeof(Query_Info));

	retv	= DB_Select_Data("biz01" , "querysn" , sql_command , q_ret);
	if (retv != 0)
	{
		retv	= 1;
		ccis_log_err("[%s:%d]DB select failed" , __FUNCTION__ , __LINE__);
		goto clean_up;
	}

	if (q_ret->res_data[0][0])
		strcpy(log_node->querysn , q_ret->res_data[0][0]);
	else
	{
		ccis_log_alert("[%s:%d]DB Select Failed !" , __FUNCTION__ , __LINE__);
		retv	= 1;
		goto clean_up;
	}

	memset(sql_command , 0 , CCIS_MAXSIZE * sizeof(char));
	sprintf(sql_command , "'%s'" , log_node->querysn);
	retv	= DB_Insert_Data("biz02" , "querysn"  , sql_command);
	if (retv)
	{
		ccis_log_err("[%s:%d] DataBase Insert Failed" , __FUNCTION__ , __LINE__);
	}

clean_up:
	Do_Close();
	if (sql_command)
		free(sql_command);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Receive_ID_Photo(pSearch_Log log_node, char* photobuf , int bufLen , int status)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;

	FILE* fp	= NULL;
	if (status == CCIS_PACKAGE_UNFINISHED)
	{
		retv	= Write_File(log_node->idpic_path , photobuf , bufLen , status);
		if (retv != 0)
		{
			ccis_log_err("写入身份证照片文件[%s]失败！" , log_node->idpic_path);
			goto clean_up;
		}
	}
	else if (status == CCIS_PACKAGE_FIRST)
	{
		retv	= Get_Filepath(0 , log_node->idpic_path , log_node->idnum , NULL);
		if (retv != 0)
		{
			ccis_log_alert("[%s:%d]Get File Path Error ! errno = %d" , __FUNCTION__ , __LINE__ , retv);
			goto clean_up;
		}
		ccis_log_debug("目标图片路径：%s" , log_node->idpic_path);
		retv	= Write_File(log_node->idpic_path , photobuf , bufLen , status);
		if (retv != 0)
		{
			ccis_log_err("写入照片文件[%s]失败！" , log_node->idpic_path);
			goto clean_up;
		}
	}
	else
	{
		fp	= fopen(log_node->idpic_path , "r");
		if (!fp)
		{
			ccis_log_alert("无法打开身份证照片%s！失败原因：%s" , log_node->idpic_path , strerror(errno));
			retv	= errno;
		}
	}

clean_up:
	if (fp)
		fclose(fp);
	fp	= NULL;
	return retv;
}

int Receive_Vis_Photo(pSearch_Log log_node , char* photobuf , int bufLen , int status)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;

	FILE* fp	= NULL;
	if (status == CCIS_PACKAGE_UNFINISHED)
	{
		retv	= Write_File(log_node->sppic_path , photobuf , bufLen , status);
		if (retv != 0)
		{
			ccis_log_err("无法写入现场照片文件:%s！错误原因：%s" , log_node->sppic_path , strerror(errno));
			goto clean_up;
		}
	}
	else if (status == CCIS_PACKAGE_FIRST)
	{
		retv	= Get_Filepath(2 , log_node->sppic_path , log_node->idnum , log_node->querysn);
		if (retv != 0)
		{
			ccis_log_alert("[%s:%d]Get File Path Error ! errno = %d" , __FUNCTION__ , __LINE__ , retv);
			goto clean_up;
		}
		retv	= Write_File(log_node->sppic_path , photobuf , bufLen , status);
		if (retv != 0)
		{
			ccis_log_err("写入现场照片%s失败！失败原因：%s" , log_node->sppic_path , strerror(errno));
			goto clean_up;
		}
	}
	else
	{
		fp	= fopen(log_node->sppic_path , "r");
		if (!fp)
		{
			ccis_log_err("无法打开现场照片文件%s！错误原因：%s" , log_node->sppic_path , strerror(errno));
			retv	= errno;
		}
	}

clean_up:
	if (fp)
		fclose(fp);
	fp	= NULL;
	return retv;
}

int Receive_Inf_Photo(pSearch_Log log_node , char* photobuf , int bufLen , int status)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;

	FILE* fp	= NULL;
	if (status == CCIS_PACKAGE_UNFINISHED)
	{
		retv	= Write_File(log_node->infpic_path , photobuf , bufLen , status);
		if (retv != 0)
		{
			ccis_log_err("无法写入红外照片文件：%s！错误原因：%s" , log_node->infpic_path , strerror(errno));
			goto clean_up;
		}
	}
	else if (status == CCIS_PACKAGE_FIRST)
	{
		retv	= Get_Filepath(2 , log_node->infpic_path , log_node->idnum , log_node->querysn);
		if (retv != 0)
		{
			ccis_log_alert("[%s:%d]Get File Path Error ! errno = %d" , __FUNCTION__ , __LINE__ , retv);
			goto clean_up;
		}
		retv	= Write_File(log_node->infpic_path , photobuf , bufLen , status);
		if (retv != 0)
		{
			ccis_log_err("无法写入红外照片文件：%s！错误原因：%s" , log_node->infpic_path , strerror(errno));
			goto clean_up;
		}
	}
	else
	{
		fp	= fopen(log_node->infpic_path , "r");
		if (!fp)
		{
			ccis_log_err("无法打开红外照片文件%s！错误原因：%s" , log_node->infpic_path , strerror(errno));
			retv	= errno;
		}
	}

clean_up:
	if (fp)
		fclose(fp);
	fp	= NULL;
	return retv;
}

/*
	return value:
	0:成功发送报告文件
	1:存在未打印报告
	2:需要收费
	3:征信系统用户名或密码错误
	4:征信系统服务器连接失败
	5:获取报告号失败
	6:获取异议号失败
	7:获取收费信息失败
	8:查询未知错误
	-1:参数错误
	-2:系统错误
	-3:设备未认证
*/
int Receive_PhoneNumber(pSearch_Log log_node , pRing ring , char* buffer , char* phonenumber , SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!phonenumber || !log_node)
		return -1;

	int retv	= 0;
	char*	history	= NULL;
	char*	newpwd	= NULL;
	struct UserInfoStruct* pstUserInfo	= NULL;
	strncpy(log_node->phonenum , phonenumber , sizeof(log_node->phonenum));

	retv	= Get_Unprint_Report(log_node->idnum , buffer , log_node->old_report_path , log_node->old_repno , NULL , &(log_node->unprint_up_flag));
	if (unlikely(!retv))
	{
		retv	= 1;
		goto clean_up;
	}
	pstUserInfo	= (struct UserInfoStruct*)malloc(sizeof(struct UserInfoStruct));
	if (!pstUserInfo)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -2;
		goto clean_up;
	}
	if (Make_User_Info_Struct(log_node , pstUserInfo))
	{
		ccis_log_err("[%s]创建身份信息结构体失败！" , log_node->querysn);
		retv	= -2;
		goto clean_up;
	}

	retv	= Download_Report_Free(log_node->querysn , ring->pbcinfo.User , ring->pbcinfo.Pwd , &newpwd , pstUserInfo , log_node->repno , log_node->report_path , &history , ring->agent);
	if (newpwd)
	{
		ccis_log_notice("[devsn:%s]账号[%s]原密码已过期，服务器已主动为其修改密码！" , log_node->devsn , ring->pbcinfo.User);
		ccis_log_debug("[devsn:%s]征信密码已由[%s]修改为[%s]" , log_node->devsn , ring->pbcinfo.Pwd , newpwd);
		strcpy(ring->pbcinfo.Pwd , newpwd);
		if (Store_New_Password(ring))
		{
			ccis_log_emerg("[devsn:%s]账号[%s]的新密码未能记录到数据库！请联系管理员紧急操作！" , log_node->devsn , ring->pbcinfo.User);
		}
		else
			ccis_log_info("[devsn:%s]账号[%s]的新密码已经更新至数据库，将在客户端下次登陆时同步" , log_node->devsn , ring->pbcinfo.User);
	}
	if (retv)
	{
		if(retv == 5 && history)		//需要收费
		{
			BSNMsg response;
			memset(&response , 0 , sizeof(BSNMsg));
			response.head.type	= CCIS_DOWNLOAD_REPORT;
			response.head.errcode	= CCIS_RP_SHOULD_CHARGE;
			strcpy(response.body.querysn , log_node->querysn);

			if (Send_String_To_Client(history , strlen(history) , response , ssl))
			{
				retv	= -2;
				ccis_log_err("[%s]历史查询记录发送失败！" , log_node->querysn);
				goto clean_up;
			}
			retv	= 2;
		} 
		else
		{
			switch(retv)		//调整返回值防止冲突
			{
				case 1:
				case 2:
				case 3:
				case 4:{
					retv	+= 2;
				}break;
				case 6:retv	= 7;break;
				default:{
					retv	= 8;
				}
			}
		}
		goto clean_up;
	}

	/*发送报告号*/

	if (Send_Report_To_Client(ssl , log_node , ring , CCIS_DOWNLOAD_REPORT , CCIS_RP_REPORT_SENDING))
	{
		ccis_log_err("[%s]报告%s发送失败！" , log_node->querysn , log_node->report_path);
		log_node->falres	|= CCIS_ERR_REP_REPORT_SEND_FAILED;
		retv	= 8;
	}
	
clean_up:
	if (pstUserInfo)
	{
		free(pstUserInfo);
		pstUserInfo	= NULL;
	}
	if (history)
		free(history);
	if (newpwd)
		free(newpwd);
	return retv;
}

int Get_Last_ChargeNum(pSearch_Log log_node)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!log_node)
		return -1;

	int retv		= 0;
	char sql_condition[CCIS_MIDSIZE] = {0};
	char sql_command[CCIS_MIDSIZE] = {0};
	Query_Info* q_ret	= NULL;
	Query_Info* extra_ret	= NULL;
	char charge_comment[CCIS_SMALLSIZE] = {0};
	char last_querysn[QUERYSN_LEN]	= {0};
	char last_devsn[DEVSN_LEN]	= {0};
	int last_chgnum			= 0;
	Do_Connect();

	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));

	extra_ret		= (Query_Info*)calloc(1 , sizeof(Query_Info));
	if (!extra_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}

	sprintf(sql_condition , "idnum='%s' and prtsgn='0' and (querysgn='0' or querysgn='1') and (repno is NULL or repno='') and chgnum<>'0' order by querydt desc" , log_node->idnum);
	retv	= DB_Select_Data("biz01" , "querysn,devsn,chgnum,comment" , sql_condition , q_ret);			//查询上次收费并且未打印报告的金额
	if (retv == -1)
	{
		ccis_log_info("[%s]用户暂无未使用的缴费记录" , log_node->querysn);
	}
	else if (retv)
	{
		ccis_log_err("[%s:%d] Database Select Failed , returned %d" , __FUNCTION__ , __LINE__ , retv);
		goto clean_up;
	}

	/**********根据配置决定是否允许跨设备收费或跨网点收费************/
	int gotten	= 0;
	if (!cross_website)		//如果不允许跨网点
	{
		if (!cross_dev)		//同时也不允许跨设备
		{
			for (int i = 0 ; i < q_ret->num_rows ; i ++)
			{
				if (q_ret->res_data[i][1])
				{
					if (!strcmp(q_ret->res_data[i][1] , log_node->devsn))
					{
						if (q_ret->res_data[i][0])
							strncpy(last_querysn , q_ret->res_data[i][0] , QUERYSN_LEN);
						else
						{
							ccis_log_emerg("[%s]上次收费的查询序列号丢失？？" , log_node->querysn);
							retv	= 1;
							goto clean_up;
						}
						if (q_ret->res_data[i][2])
							last_chgnum	= atoi(q_ret->res_data[i][2]);
						if (q_ret->res_data[i][3])
							strcpy(charge_comment , q_ret->res_data[i][3]);
						gotten	= 1;
					}
					else
					{
						ccis_log_info("[%s]由于系统配置原因(禁止跨设备收费)，上次在设备[%s]中收取的费用将无法继承使用！" , log_node->querysn , q_ret->res_data[i][1]);
					}
				}
			}
			if (!gotten)
			{
				retv	= 1;
				goto clean_up;
			}
		}
		else
		{
			char website_belong[CCIS_SMALLSIZE];
			memset(extra_ret , 0 , sizeof(Query_Info));
			memset(sql_condition , 0 , sizeof(char) * CCIS_MIDSIZE);
			sprintf(sql_condition , "devsn='%s'" , log_node->devsn);
			retv    = DB_Select_Data("batch02" , "posid" , sql_condition , extra_ret);		//查询当前设备的所属网点
			if (retv)
			{
				ccis_log_err("[%s:%d]SQL Select Error , returned %d" , __FUNCTION__ , __LINE__ , retv);
				retv	= 1;
				goto clean_up;
			}
			if (extra_ret->res_data[0][0])
				strncpy(website_belong , extra_ret->res_data[0][0] , CCIS_SMALLSIZE);
			else
			{
				ccis_log_err("[%s]查询设备(%s)所属网点未知！无法判断跨网点收费业务！" , log_node->querysn , log_node->devsn);
				retv	= 1;
				goto clean_up;
			}
			if (extra_ret->ptr)
				mysql_free_result(extra_ret->ptr);

			//查询q_ret->res_data中每个devsn的所属网点
			int max_rows	= q_ret->num_rows > MAXROW ? MAXROW : q_ret->num_rows;
			short allow	= 0;
			for (int i = 0 ; i < max_rows ; i ++)
			{
				memset(extra_ret , 0 , sizeof(Query_Info));
				if (q_ret->res_data[i][1])
				{
					sprintf(sql_condition , "devsn='%s'" , q_ret->res_data[i][1]);
					retv	= DB_Select_Data("batch02" , "posid" , sql_condition , extra_ret);
					if (retv)
						continue;
					if (!strcmp(extra_ret->res_data[i][0] , website_belong))
					{
						if (q_ret->res_data[i][0])
							strncpy(last_querysn , q_ret->res_data[i][0] , QUERYSN_LEN);
						else
						{
							ccis_log_err("[%s]上次收费的查询序列号丢失？？" , log_node->querysn);
							retv	= 1;
							goto clean_up;
						}
						if (q_ret->res_data[i][2])
							last_chgnum	= atoi(q_ret->res_data[i][2]);
						if (q_ret->res_data[i][3])
							strcpy(charge_comment , q_ret->res_data[i][3]);
						allow	= 1;
						break;
					}
					else
						ccis_log_info("[%s]由于系统配置原因(禁止跨网点收费)，上次在设备[%s]中收取的费用将无法继承使用！" , log_node->querysn , last_devsn);
						
				}
				if (extra_ret->ptr)
					mysql_free_result(extra_ret->ptr);
				memset(extra_ret , 0 , sizeof(Query_Info));
			}
				if (!allow)
			{
				retv	= 1;
				goto clean_up;
			}
		}
	}
	else
	{
		if (q_ret->res_data[0][0])
			strncpy(last_querysn , q_ret->res_data[0][0] , QUERYSN_LEN);
		else
		{
			retv	= 1;
			goto clean_up;
		}
		if (q_ret->res_data[0][1])
			strncpy(last_devsn , q_ret->res_data[0][1] , DEVSN_LEN);
		else
		{
			retv	= 1;
				goto clean_up;
		}
		if (q_ret->res_data[0][2])
			last_chgnum	= atoi(q_ret->res_data[0][2]);
		if (q_ret->res_data[0][3])
			strcpy(charge_comment , q_ret->res_data[0][3]);
	}
	/****************************************************************/

	log_node->chgnum	= last_chgnum;
	ccis_log_notice("[%s]检测到该用户在流程[%s]中已缴费%d元！" , log_node->querysn , last_querysn , log_node->chgnum);
	if (log_node->chgnum > 0)
	{
		memset(sql_condition , 0 , sizeof(char) * CCIS_MIDSIZE);

		sprintf(sql_condition , "querysn='%s'" , last_querysn);
		if (strstr(charge_comment , "(") == NULL)
			sprintf(sql_command , "chgnum='0',comment='%s(used by %s)'" , charge_comment , log_node->querysn);
		else
			sprintf(sql_command , "chgnum='0'");

		retv	= DB_Update_Data("biz01" , sql_command , sql_condition);		//更新上次查询，使其收费金额置零，并且设置注释指明被哪条记录使用
		if (retv)
		{
			ccis_log_err("[%s]无法更新上一次收费记录，本次将认为前置收费金额为0元" , log_node->querysn);
			log_node->chgnum	= 0;
		}

		memset(sql_condition , 0 , sizeof(char) * CCIS_MIDSIZE);
		sprintf(sql_condition , "querysn='%s'" , log_node->querysn);
		sprintf(sql_command , "chgnum='%d',comment='+%d(Inherit from %s)'" , last_chgnum , last_chgnum , last_querysn);
		retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
		if (retv)
		{
			ccis_log_warning("[%s]收费金额继承关系记录失败！SQL returned : %d" , log_node->querysn , retv);
			retv	= 0;
		}
	}
	log_node->lastchgnum	= log_node->chgnum;

clean_up:
	Do_Close();
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	if (extra_ret)
	{
		if (extra_ret->ptr)
			mysql_free_result(extra_ret->ptr);
		free(extra_ret);
	}
	return retv;
}

/*
	return value:
	0:成功发送报告文件
	2:需要收费
	3:征信系统用户名或密码错误
	4:征信系统服务器连接失败
	5:获取报告号失败
	6:获取异议号失败
	7:获取收费信息失败
	8:查询未知错误
	-1:参数错误
	-2:系统错误
	-3:设备未认证
*/
int Download_New_Report(pSearch_Log log_node , pRing ring , SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	struct UserInfoStruct* pstUserInfo	= NULL;
	char* history	= NULL;			//保存历史查询记录
	char* newpwd	= NULL;			//保存新密码
	if (!ssl)
		return -1;
	
	pstUserInfo	= (struct UserInfoStruct*)malloc(sizeof(struct UserInfoStruct));
	if (!pstUserInfo)
	{
		ccis_log_emerg("[%s:%d][%s]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , log_node->querysn , strerror(errno));
		retv	= -2;
		goto clean_up;
	}
	if (Make_User_Info_Struct(log_node , pstUserInfo))
	{
		ccis_log_err("[%s]创建用户信息结构体失败！" , log_node->querysn);
		retv	= -2;
		goto clean_up;
	}

	retv	= Download_Report_Free(log_node->querysn , ring->pbcinfo.User , ring->pbcinfo.Pwd , &newpwd , pstUserInfo , log_node->repno , log_node->report_path , &history , ring->agent);
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
	if (retv)
	{
		if(retv == 5 && history)
		{
			BSNMsg response;
			memset(&response , 0 , sizeof(BSNMsg));
			response.head.type	= CCIS_DOWNLOAD_REPORT_NEW;
			response.head.errcode	= CCIS_RP_SHOULD_CHARGE;
			strcpy(response.body.querysn , log_node->querysn);

			if (Send_String_To_Client(history , strlen(history) , response , ssl))
			{
				retv	= -2;
				goto clean_up;
			}

			retv	= 2;
		} 
		else
		{
			switch(retv)
			{
				case 1:
				case 2:
				case 3:
				case 4:{
					retv	+= 2;
				}break;
				case 6:retv	= 7;break;
				default:{
					retv	= 8;
				}
			}
		}
		goto clean_up;
	}

	if (Send_Report_To_Client(ssl , log_node , ring , CCIS_DOWNLOAD_REPORT_NEW , CCIS_RP_REPORT_SENDING))
	{
		ccis_log_err("[%s]报告%s发送失败！" , log_node->querysn , log_node->report_path);
		log_node->falres	|= CCIS_ERR_REP_REPORT_SEND_FAILED;
		retv	= 8;
	}
clean_up:
	if (pstUserInfo)
	{
		free(pstUserInfo);
		pstUserInfo	= NULL;
	}
	if (history)
		free(history);
	if (newpwd)
		free(newpwd);
	return retv;
}

int Send_Old_Report(pSearch_Log log_node , pRing ring , SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	retv	= Get_Unprint_Report(log_node->idnum , NULL , log_node->report_path , log_node->repno , log_node->report_type , &(log_node->unprint_up_flag));
	if (unlikely(retv))
	{
		retv	= -1;
		ccis_log_err("[%s]无法找到未打印报告！" , log_node->querysn);
		goto clean_up;
	}
	else
	{
		ccis_log_debug("*****************已获得上次未打印报告数据*********************");
		ccis_log_debug("repno=%s" , log_node->repno);
		ccis_log_debug("report=%s" , log_node->report_path);
		ccis_log_debug("**************************************************************");
		retv	= Send_Report_To_Client(ssl , log_node , ring , CCIS_DOWNLOAD_REPORT_EXIST , CCIS_RP_REPORT_SENDING);
	}

clean_up:
	return retv;
}

int Resend_Report(pSearch_Log log_node , pRing ring , SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	return Send_Report_To_Client(ssl , log_node , ring , CCIS_RESEND_REPORT , CCIS_RP_REPORT_SENDING);
}

int Resend_Report_NoEN(pSearch_Log log_node , pRing ring , SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!log_node || !ssl || !ring)
		return -1;

	BSNMsg response;
	int retv	= 0;
	memset(&response , 0 , sizeof(BSNMsg));
	response.head.type	= CCIS_RESEND_REPORT_NOEN;
	response.head.errcode	= CCIS_RP_REPORT_SENDING;
	response.head.status	= CCIS_PACKAGE_FIRST;
	strcpy(response.buffer , log_node->repno);
	strcpy(response.body.querysn , log_node->querysn);
	Write_Msg(ssl , (void*)&response , sizeof(BSNMsg));

	char en_md5[CCIS_SMALLSIZE]	= {0};
	char comp_report[CCIS_PATHLEN]	= {0};
	strcpy(comp_report , "/run/");
	strcat(comp_report , log_node->idnum);
	strcat(comp_report , ".lz4");

	if (Compress_File(log_node->report_path , comp_report))
	{
		ccis_log_err("[%s]报告%s压缩失败！" , log_node->querysn , log_node->report_path);
		retv	= 1;
		goto clean_up;
	}
	ccis_log_debug("[%s]报告文件已压缩，压缩文件路径：%s" , log_node->querysn , comp_report);
	if (Compute_File_MD5(comp_report , en_md5))
	{
		ccis_log_err("[%s]加密报告MD5计算失败！" , log_node->querysn);
		retv	= 1;
		remove(comp_report);
		goto clean_up;
	}
	retv	= Send_File(ssl , comp_report , CCIS_RESEND_REPORT_NOEN , CCIS_RP_REPORT_SENDING , log_node->querysn);
	remove(comp_report);
	if (!retv)
		ccis_log_info("[%s]报告%s已发送完成！" , log_node->querysn , log_node->report_path);
	else
	{
		ccis_log_err("[%s]报告%s发送失败！" , log_node->querysn , log_node->report_path);
		retv	= 1;
		goto clean_up;
	}

	ccis_log_info("[%s]报告重发完成！即将发送MD5校验值..." , log_node->querysn);
	memset(&(response.buffer) , 0 , sizeof(char) * CCIS_MAXSIZE);
	response.head.status	= CCIS_PACKAGE_FINISHED;
	response.head.errcode	= CCIS_RP_DOWNLOAD_SUCCESS;
	if (Compute_File_MD5(log_node->report_path , response.buffer))
	{
		ccis_log_err("[%s]报告(%s)MD5计算失败！" , log_node->querysn , log_node->report_path);
		retv	= 1;
		goto clean_up;
	}
	response.body.bufLen	= strlen(response.buffer);
	strncpy(response.body.reseve , en_md5 , CCIS_SMALLSIZE - 1);
	Write_Msg(ssl , (void*)&response , sizeof(BSNMsg));

clean_up:
	return retv;
}

int Send_File(SSL* ssl , char* filepath , int msgtype , int msgerrcode , char* querysn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!filepath || !ssl)
	{
		return -1;
	}

	int retv	= 0;
	BSNMsg response;
	size_t iReadLen	= 0;
	int send_size	= 0;
	FILE* fp	= fopen(filepath , "rb");
	if (!fp)
	{
		retv	= -1;
		ccis_log_err("[%s]文件发送失败：无法打开文件！错误原因：%s" , __FUNCTION__ , strerror(errno));
		goto clean_up;
	}

	memset(&response , 0 , sizeof(BSNMsg));
	response.head.type	= msgtype;
	response.head.bodyLen	= sizeof(PackageBody) + CCIS_MAXSIZE;
	if (querysn)
		strcpy(response.body.querysn , querysn);

	while ((iReadLen = fread(response.buffer , sizeof(char) , CCIS_MAXSIZE , fp)) > 0)
	{
		send_size	+= iReadLen;
		response.head.seq	++;
		response.head.status	= CCIS_PACKAGE_UNFINISHED;
		response.head.errcode	= msgerrcode;
		response.body.bufLen	= iReadLen;

		retv	= Write_Msg(ssl , (void*)&response , sizeof(BSNMsg));
		if (retv)
		{
			ccis_log_err("[%s]文件发送失败，函数返回值：%d" , __FUNCTION__ , retv);
			retv	= -3;
			goto clean_up;
		}
		ccis_log_debug("已发送%d bytes，当前状态：0x%x" , send_size , response.head.status);
	}

clean_up:
	if (fp)
	{
		fclose(fp);
		fp	= NULL;
	}
	return retv;
}

int Send_Report_To_Client(SSL* ssl , pSearch_Log log_node , pRing ring , int type , int errcode)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ssl || !log_node)
		return -1;

	BSNMsg response;
	int retv	= 0;
	memset(&response , 0 , sizeof(BSNMsg));
	response.head.type	= type;
	response.head.errcode	= errcode;
	response.head.status	= CCIS_PACKAGE_FIRST;
	strcpy(response.buffer , log_node->repno);
	strcpy(response.body.querysn , log_node->querysn);
	Write_Msg(ssl , (void*)&response , sizeof(BSNMsg));

	char en_md5[CCIS_SMALLSIZE] = {0};		//保存加密报告的MD5

	if (Compress_Encrypt_Send_Report(log_node , ring , ssl , type , en_md5))
	{
		ccis_log_err("[%s]报告(%s)发送失败！" , log_node->querysn , log_node->report_path);
		retv	= 1;
		goto clean_up;
	}

	ccis_log_info("[%s]报告发送完成！即将发送MD5校验值..." , log_node->querysn);
	memset(&(response.buffer) , 0 , sizeof(char) * CCIS_MAXSIZE);
	response.head.status	= CCIS_PACKAGE_FINISHED;
	response.head.errcode	= CCIS_RP_DOWNLOAD_SUCCESS;
	if (Compute_File_MD5(log_node->report_path , response.buffer))
	{
		ccis_log_err("[%s]报告(%s)MD5计算失败！" , log_node->querysn , log_node->report_path);
		retv	= 1;
		goto clean_up;
	}
	response.body.bufLen	= strlen(response.buffer);
	strncpy(response.body.reseve , en_md5 , CCIS_SMALLSIZE - 1);
	Write_Msg(ssl , (void*)&response , sizeof(BSNMsg));

clean_up:
	return retv;
}

int Get_Charge_Result(pSearch_Log log_node , char* chargebuf)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!log_node)
		return -1;

	int retv	= 0;
	char* sql_condition	= NULL;
	char* sql_command	= NULL;
	Query_Info* q_ret	= NULL;
	char charge_comment[CCIS_SMALLSIZE]	= {0};
	Do_Connect();

	sql_condition	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));
	sql_command	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_command)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}

	memset(sql_condition , 0 , sizeof(char) * CCIS_SMALLSIZE);
	memset(&charge_comment , 0 , CCIS_SMALLSIZE);
	sprintf(sql_condition , "querysn='%s'" , log_node->querysn);

	int sql_ret	= DB_Select_Data("biz01" , "chgnum,comment" , sql_condition , q_ret);
	if (sql_ret != 0 && sql_ret != -1)
	{
		retv	= 1;
		ccis_log_err("[%s:%d][%s]DataBase Select Error , returned %d" , __FUNCTION__ , __LINE__ , log_node->querysn , sql_ret);
		goto clean_up;
	}

	if (sql_ret == 0)
	{
		if (q_ret->res_data[0][0])
		{
			log_node->chgnum	= atoi(q_ret->res_data[0][0]);
			ccis_log_debug("[%s]上次已缴费%d元" , log_node->querysn , log_node->chgnum);
			log_node->chgnum	+= atoi(chargebuf);
			ccis_log_debug("[%s]该次已缴费%d元" , log_node->querysn , log_node->chgnum);
		}
		if (q_ret->res_data[0][1])
		{
			strcpy(charge_comment , q_ret->res_data[0][1]);
		}
	}
	if (log_node->chgnum > 10)
		log_node->chgnum	= 10;

	memset(sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);

	sprintf(sql_command , "chgnum='%d',comment='%s+%s'" , log_node->chgnum , charge_comment , chargebuf);

	retv	= DB_Update_Data("biz01" , sql_command , sql_condition);

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	if (sql_command)
		free(sql_command);
	return retv;

}

int Retreat_Charge_Log(pSearch_Log log_node)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!log_node)
		return -1;
	if (!strcmp(log_node->querysgn , "2"))
	{
		ccis_log_err("[%s]退费操作无法执行！原因：报告%s已下载！" , log_node->querysn , log_node->report_path);
		return 1;
	}

	int retv		= 0;
	char* sql_condition	= NULL;
	char* sql_command	= NULL;
	Query_Info* q_ret	= NULL;
	char charge_comment[CCIS_SMALLSIZE];
	Do_Connect();

	sql_condition		= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	sql_command		= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_command)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	q_ret			= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));
	memset(&charge_comment , 0 , CCIS_SMALLSIZE);

	sprintf(sql_condition , "querysn='%s'" , log_node->querysn);

	if (DB_Select_Data("biz01" , "comment" , sql_condition , q_ret) == 0)
	{
		if (q_ret->res_data[0][0])
			strcpy(charge_comment , q_ret->res_data[0][0]);
	}

	sprintf(sql_command , "chgnum='0',comment='%s(retreated)'" , charge_comment);
	retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
	if (retv)
	{
		ccis_log_err("[%s:%d]SQL Update Error ！Returned %d" , __FUNCTION__ , __LINE__ , retv);
		ccis_log_err("[%s]退费失败，数据库错误！" , log_node->querysn);
		retv	= -1;
		goto clean_up;
	}
	log_node->chgnum	= 0;

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	if (sql_command)
		free(sql_command);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

/*
	return value:
	0:成功发送报告文件
	2:收费金额不足
	3:征信系统用户名或密码错误
	4:征信系统服务器连接失败
	5:获取报告号失败
	6:获取异议号失败
	7:获取收费信息失败
	8:查询未知错误
	-1:参数错误
	-2:系统错误
	-3:设备未认证
*/
int Download_Charge_Report(pSearch_Log log_node , pRing ring , SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!log_node || !ssl)
	{
		return -1;
	}

	int retv	= 0;
	struct UserInfoStruct* pstUserInfo	= NULL;
	char* newpwd	= NULL;

	if (log_node->chgnum < CHARGE_NUM)
	{
		ccis_log_notice("[%s]用户已交%d元，还差%d元" , log_node->querysn , log_node->chgnum , CHARGE_NUM - log_node->chgnum);
		return 2;
	}
	else
	{
		ccis_log_notice("[%s]用户已交%d元，准备下载报告" , log_node->querysn , log_node->chgnum);
	}

	pstUserInfo	= (struct UserInfoStruct*)malloc(sizeof(struct UserInfoStruct));
	if (!pstUserInfo)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= -1;
		goto clean_up;
	}
	if (Make_User_Info_Struct(log_node , pstUserInfo))
	{
		ccis_log_err("[%s]创建身份信息结构体失败！" , log_node->querysn);
		retv	= -1;
		goto clean_up;
	}

	retv	= Download_Report_Charge(log_node->querysn , ring->pbcinfo.User , ring->pbcinfo.Pwd , &newpwd , pstUserInfo , log_node->repno , log_node->chgno , log_node->report_path , ring->agent);

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
	if (retv)
	{
		ccis_log_debug("Download_Report_Charge returned %d" , retv);
		switch(retv)
		{
			case 1:
			case 2:
			case 3:
			case 4:{
				retv	+= 2;
			}break;
			case 6:retv	= 7;break;
			default:{
				retv	= 8;
			}
		}
		goto clean_up;
	}

	if (Send_Report_To_Client(ssl , log_node , ring , CCIS_DOWNLOAD_REPORT_CHARGE , CCIS_RP_REPORT_SENDING))
	{
		ccis_log_err("[%s]报告%s发送失败！" , log_node->querysn , log_node->report_path);
		log_node->falres	|= CCIS_ERR_REP_REPORT_SEND_FAILED;
		retv	= 8;
	}

clean_up:
	if (pstUserInfo)
		free(pstUserInfo);
	if (newpwd)
		free(newpwd);
	return retv;
	
}

int Get_Print_Result(pSearch_Log log_node , int p_result)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (p_result == CCIS_RP_PRINT_SUCCESS)
	{
		char* cur_time	= Get_Localtime();
		if (!cur_time)
		{
			ccis_log_alert("[%s][%s] Cannot Get Print Time !" , __FUNCTION__ , log_node->querysn);
		}
		else
		{
			strcpy(log_node->prtdttime , cur_time);
			free(cur_time);
		}
		strcpy(log_node->prtsgn , "1");
		log_node->falres	= CCIS_PROC_ALL_DONE;
		remove(log_node->report_path);
		ccis_log_info("[%s]报告文件(%s)已删除" , log_node->querysn , log_node->report_path);
	}
	else
	{
		strcpy(log_node->prtsgn , "0");
		log_node->falres	|= CCIS_ERR_REP_PRINT_FAILED;
	}
	return 0;
}

int Compress_Encrypt_Send_Report(pSearch_Log log_node , pRing ring , SSL* ssl , int type , char* en_md5)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	char comp_report[CCIS_PATHLEN]	= {0};
	char final_report[CCIS_PATHLEN]	= {0};
	strcpy(comp_report , "/run/");
	strcat(comp_report , log_node->idnum);
	strcat(comp_report , ".lz4");
	strcpy(final_report , comp_report);
	strcat(final_report , ".en");

	if (Compress_File(log_node->report_path , comp_report))
	{
		ccis_log_err("[%s]报告%s压缩失败！" , log_node->querysn , log_node->report_path);
		retv	= 1;
		goto clean_up;
	}
	else
	{
		ccis_log_debug("[%s]报告文件已压缩，压缩文件路径：%s" , log_node->querysn , comp_report);

		if (server_encrypt_file(comp_report , final_report , ring->tpm_key->pkey.rsa))
		{
			ccis_log_err("[%s]文件%s加密失败！" , log_node->querysn , comp_report);
			retv	= 1;
			remove(comp_report);
			goto clean_up;
		}

		ccis_log_debug("[%s]报告已加密，加密文件路径：%s" , log_node->querysn , final_report);

		if (Compute_File_MD5(final_report , en_md5))
		{
			ccis_log_err("[%s]加密报告MD5计算失败！" , log_node->querysn);
			retv	= 1;
			remove(comp_report);
			remove(final_report);
			goto clean_up;
		}

		retv	= Send_File(ssl , final_report , type , CCIS_RP_REPORT_SENDING , log_node->querysn);

		remove(comp_report);
		remove(final_report);
		if (!retv)
			ccis_log_info("[%s]报告%s已发送完成！" , log_node->querysn , log_node->report_path);
		else
			ccis_log_err("[%s]报告%s发送失败！" , log_node->querysn , log_node->report_path);
	}

clean_up:
	return retv;
}

int Send_String_To_Client(char* buf_str , int length , BSNMsg response , SSL* ssl)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!buf_str || !ssl)
	{
		return -1;
	}

	char* pos	= buf_str;

	if (length <= CCIS_MAXSIZE)
	{
		response.head.status	= CCIS_PACKAGE_FIRST;
		response.body.bufLen	= length;
		strncpy(response.buffer , pos , length);
		Write_Msg(ssl , (void*)&response , sizeof(BSNMsg));
	}
	else
	{
		response.head.status	= CCIS_PACKAGE_FIRST;
		response.body.bufLen	= CCIS_MAXSIZE;
		strncpy(response.buffer , pos , CCIS_MAXSIZE);
		if (Write_Msg(ssl , (void*)&response , sizeof(BSNMsg)))
		{
			return 1;
		}
		pos	+= CCIS_MAXSIZE;
		length	-= CCIS_MAXSIZE;

		while (length > 0)
		{
			response.head.status	= CCIS_PACKAGE_UNFINISHED;
			strncpy(response.buffer , pos , CCIS_MAXSIZE);
			length	-= CCIS_MAXSIZE;
			pos	+= CCIS_MAXSIZE;
			if (length <= 0)
			{
				response.body.bufLen	= strlen(response.buffer);
			}
			else
			{
				response.body.bufLen	= CCIS_MAXSIZE;
			}
			if (Write_Msg(ssl , (void*)&response , sizeof(BSNMsg)))
			{
				ccis_log_err("[%s]长字符串发送失败！" , __FUNCTION__);
				return 1;
			}
		}
	}
	return 0;
}

void Analyze_FlowProcess(pSearch_Log log_node , int* type , int* errcode)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (Get_FlowName_By_Index(log_node->cur_flow.node_index , log_node->cur_flow.FlowName))
	{
		ccis_log_alert("[%s]未知的流程索引号%d！" , log_node->querysn , log_node->cur_flow.node_index);
		*type	= CCIS_RECEIVE_ID_PHOTO;
		*errcode	= CCIS_PROCESS_INVALID;
		return ;
	}

	ccis_log_debug("[%s]当前流程：%s" , log_node->querysn , log_node->cur_flow.FlowName);
	ccis_log_debug("[%s]当前条件：%s" , log_node->querysn , log_node->cur_flow.Condition);

	*type	= Get_Number_By_Index(log_node->cur_flow.node_index);

	switch(*type)		//warning 日你奶奶的这里必须得写死，改了流程这里还要改，so流程控制的配置文件有个鸡儿用？
	{
	/*	case CCIS_RECEIVE_ID_INFO:{				//注释掉，只允许人脸比对之后的流程被维持
			if (strcmp(log_node->cur_flow.Condition , "verified") == 0)
			{
				*errcode	= CCIS_ID_CHECK_SUCCESS;
			}
			else
				*errcode	= CCIS_PROCESS_INVALID;
		}break;
		case CCIS_RECEIVE_ID_PHOTO:{
			if (strcmp(log_node->cur_flow.Condition , "done") == 0)
				*errcode	= CCIS_ID_PHOTO_SAVE_SUCCESS;
			else
				*errcode	= CCIS_PROCESS_INVALID;
		}break;
	*/
		case CCIS_RECEIVE_VIS_PHOTO:{
			if (strcmp(log_node->cur_flow.Condition , "matched") == 0)
				*errcode	= CCIS_FM_COMPARE_PASS;
			else
				*errcode	= CCIS_PROCESS_INVALID;
		}break;
		case CCIS_DOWNLOAD_REPORT:{
			if (strcmp(log_node->cur_flow.Condition , "unprint") == 0)
				*errcode	= CCIS_RP_UNPRINT_REPORT_EXIST;
			else if (strcmp(log_node->cur_flow.Condition , "charge") == 0)
				*errcode	= CCIS_RP_SHOULD_CHARGE;
			else
				*errcode	= CCIS_PROCESS_INVALID;
		}break;
		case CCIS_DOWNLOAD_REPORT_EXIST:{
			*errcode	= CCIS_PROCESS_INVALID;
		}break;
		case CCIS_DOWNLOAD_REPORT_NEW:{
			if (strcmp(log_node->cur_flow.Condition , "charge") == 0)
				*errcode	= CCIS_RP_SHOULD_CHARGE;
			else
				*errcode	= CCIS_PROCESS_INVALID;
		}break;
	/*	case CCIS_GET_CHARGE_RESULT:{
			*errcode	= CCIS_PROCESS_INVALID;
		}break;*/
		default:{
			*type	= CCIS_RECEIVE_ID_PHOTO;
			*errcode	= CCIS_PROCESS_INVALID;
		}
	}
}

int Make_User_Info_Struct(pSearch_Log log_node , struct UserInfoStruct* pstUserInfo)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (unlikely(!log_node || !pstUserInfo))
	{
		return 1;
	}
	memset(pstUserInfo , 0 , sizeof(struct UserInfoStruct));

	strcpy(pstUserInfo->acCertType , "0");
	strcpy(pstUserInfo->acCertNo , log_node->idnum);
	strcpy(pstUserInfo->acCertName , log_node->idname);
	strcpy(pstUserInfo->acQueryType , log_node->report_type);
	strcpy(pstUserInfo->acMobileNo , log_node->phonenum);
	//strcpy(pstUserInfo->acQuerySn , log_node->querysn);
	char* queryid = log_node->querysn;
    while (*queryid ++ == '0');
    queryid --;
    strcpy(pstUserInfo->acQuerySn, queryid);
    return 0;
}

int Get_Unprint_Report(char* idnum , char* buffer , char* old_report_path , char* old_repno , char* report_type , bool* unprint_up_flag)		//0成功，1失败，-1无结果
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv		= 0;
	Do_Connect();
	char* sql_command	= NULL;
	Query_Info* q_ret	= NULL;

	sql_command	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (unlikely(!sql_command))
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	q_ret	= (Query_Info*)malloc(sizeof(Query_Info));
	if (unlikely(!q_ret))
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));

	sprintf(sql_command , "idnum='%s' and prtsgn='0' and repno is not NULL and repno <> ''" , idnum);
	retv	= DB_Select_Data("biz01" , "querysn,repno,querydt,reptype" , sql_command , q_ret);
	if (retv == 0)
	{
#ifdef DEBUG
		ccis_log_debug("***************上次未打印报告****************");
		ccis_log_debug("querysn : %s" , q_ret->res_data[0][0]);
		ccis_log_debug("repno : %s" , q_ret->res_data[0][1]);
		ccis_log_debug("querydt : %s" , q_ret->res_data[0][2]);
#endif
		*unprint_up_flag	= true;
	}

	if (retv == 0 && buffer && q_ret->res_data[0][2])
	{
		strcpy(buffer , q_ret->res_data[0][2]);
	}

	if (unlikely(retv == 0 && old_report_path && old_repno))
	{
		if (q_ret->res_data[0][1])
			strcpy(old_repno , q_ret->res_data[0][1]);
		else
		{
			ccis_log_warning("[%s]未打印报告号丢失，报告文件可能存在错误！" , q_ret->res_data[0][0]);
			strcpy(old_repno , " ");
		}
		if (q_ret->res_data[0][3] && report_type)
			strcpy(report_type , q_ret->res_data[0][3]);

		memset(sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);

		if (q_ret->res_data[0][0])
			sprintf(sql_command , "querysn='%s'" , q_ret->res_data[0][0]);
		else
		{
			ccis_log_err("[%s:%d]DB Select Failed !" , __FUNCTION__ , __LINE__);
			retv	= 1;
			goto clean_up;
		}

		//释放上一次查询结果
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);

		memset(q_ret , 0 , sizeof(Query_Info));

		retv	= DB_Select_Data("biz02" , "reppath" , sql_command , q_ret);
		if (likely(retv == 0) && q_ret->res_data[0][0])
		{
			strcpy(old_report_path , q_ret->res_data[0][0]);
			ccis_log_debug("report : %s" , q_ret->res_data[0][0]);
		}
		else
		{
			ccis_log_err("[%s:%d]Database Select Failed , returned %d" , __FUNCTION__ , __LINE__ , retv);
			retv	= 1;
			goto clean_up;
		}
	}

clean_up:
#ifdef DEBUG
	if (retv == 0)
		ccis_log_debug("*********************************************");
#endif
	Do_Close();
	if (sql_command)
	{
		free(sql_command);
		sql_command	= NULL;
	}
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Update_Unprint_Sign(char* idnum , char* ignore_querysn , int sign , const char* old_report_path , bool* unprint_up_flag)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	char* sql_command	= NULL;
	Do_Connect();
	if (*unprint_up_flag)
	{
		sql_command	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
		if (!sql_command)
		{
			ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
			retv	= 1;
			goto clean_up;
		}
	
		sprintf(sql_command , "idnum='%s' and prtsgn='0' and repno is not NULL and repno <> '' and querysn <> '%s'" , idnum , ignore_querysn);
		if (sign == CCIS_DOWNLOAD_REPORT_EXIST)
			retv	= DB_Update_Data("biz01" , "prtsgn='2'" , sql_command);
		else if (sign == CCIS_DOWNLOAD_REPORT_NEW || sign == CCIS_DOWNLOAD_REPORT_CHARGE)
		{
			if (old_report_path)
			{
				remove(old_report_path);
				ccis_log_info("[%s]未打印报告文件(%s)由用户选择放弃，已删除" , ignore_querysn , old_report_path);
			}
			retv	= DB_Update_Data("biz01" , "prtsgn='3'" , sql_command);
		}
		*unprint_up_flag	= false;
	}

clean_up:
	Do_Close();
	if(sql_command)
	{
		free(sql_command);
		sql_command	= NULL;
	}
	return retv;
}

int Insert_Info_To_DB(pSearch_Log log_node , int type)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	Do_Connect();
	char* sql_command	= NULL;
	char* sql_condition	= NULL;
	Query_Info* q_ret	= NULL;
	char* cur_time		= NULL;
	
	sql_command	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_command)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	memset(sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);
	memset(q_ret , 0 , sizeof(Query_Info));

	sql_condition	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	memset(sql_condition , 0 , sizeof(char) * CCIS_SMALLSIZE);

	sprintf(sql_condition , "querysn='%s'" , log_node->querysn);

	cur_time	= Get_String_From_Time(&log_node->lastpackage);
	if (!cur_time)
	{
		retv	= 1;
		ccis_log_err("[%s]获取时间字符串失败！" , log_node->querysn);
		goto clean_up;
	}

	switch(type)
	{
		case CCIS_RECEIVE_ID_INFO:{
			sprintf(sql_command , "vfyret='%d'" , log_node->vfyret);
			retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
				retv	= 1;
				goto clean_up;
			}
		}break;
		case CCIS_RECEIVE_ID_PHOTO:{
			sprintf(sql_command , "authpath='%s',idpath='%s'" , log_node->authpic_path , log_node->idpic_path);
			retv	= DB_Update_Data("biz02" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
				retv	= 1;
				goto clean_up;
			}

			memset(sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);

			sprintf(sql_command , "falres='%d',rept='%s',flow='%d',condt='%s'" , log_node->falres , cur_time , log_node->cur_flow.node_index , log_node->cur_flow.Condition);
			retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
			}

			if (store_files)
			{
				int img_retv	= DB_Insert_Image("biz02" , "idpic" , log_node->idpic_path , sql_condition);
				if (img_retv)
				{
					ccis_log_err("[%s]身份证照片入库失败！SQL 错误码：%d" , log_node->querysn , img_retv);
				}
				img_retv	= DB_Insert_Image("biz02" , "authpic" , log_node->authpic_path , sql_condition);
				if (img_retv)
				{
					ccis_log_err("[%s]公安部照片入库失败！SQL错误码：%d" , log_node->querysn , img_retv);
				}
			}
		}break;
		case CCIS_RECEIVE_VIS_PHOTO:{
			sprintf(sql_command , "sppath='%s'" , log_node->sppic_path);
			retv	= DB_Update_Data("biz02" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
				retv	= 1;
				goto clean_up;
			}
			memset (sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);

			sprintf(sql_command , "rctrscr='%f',cptimes='%hd',falres='%d',rept='%s',flow='%d',condt='%s'" , log_node->rctrscr,log_node->comp_time , log_node->falres,cur_time , log_node->cur_flow.node_index,log_node->cur_flow.Condition);
			retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
			}
			if (store_files)
			{
				int img_retv	= DB_Insert_Image("biz02" , "sppic" , log_node->sppic_path , sql_condition);
				if (img_retv)
				{
					ccis_log_err("[%s]现场照片入库失败！SQL错误码：%d" , log_node->querysn , img_retv);
				}
			}
		}break;
		case CCIS_DOWNLOAD_REPORT:{
			sprintf(sql_command , "reppath='%s'" , log_node->report_path);
			retv	= DB_Update_Data("biz02" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
				retv	= 1;
				goto clean_up;
			}
			memset (sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);

			sprintf(sql_command , "repno='%s',phoneno='%s',chgnum='%d',querysgn='%s',reptype='%s',falres='%d',rept='%s',flow='%d',condt='%s'" , log_node->repno,log_node->phonenum,log_node->chgnum,log_node->querysgn,log_node->report_type,log_node->falres,cur_time , log_node->cur_flow.node_index,log_node->cur_flow.Condition);
			retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
			}
/*
			if (store_files)		// 假如此处不是免费报告下载好了的情况而是比如要收费或者未打印报告的话，那么会报出文件找不到的错误，以后修改
			{
				int text_retv	= DB_Insert_Text("biz02" , "reppaper" , log_node->report_path , sql_condition);
				if (text_retv)
				{
					ccis_log_err("[%s]报告文件%s入库失败！SQL返回值：%d" , log_node->querysn , log_node->report_path , text_retv);
				}
			}
*/
		}break;
		case CCIS_DOWNLOAD_REPORT_EXIST:{
			sprintf(sql_command , "reppath='%s'" , log_node->report_path);
			retv	= DB_Update_Data("biz02" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
				retv	= 1;
				goto clean_up;
			}
			memset (sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);

			sprintf(sql_command , "repno='%s',phoneno='%s',chgnum='%d',querysgn='%s',reptype='%s',falres='%d',rept='%s',flow='%d',condt='%s'" , log_node->repno,log_node->phonenum,log_node->chgnum,log_node->querysgn,log_node->report_type,log_node->falres,cur_time , log_node->cur_flow.node_index,log_node->cur_flow.Condition);
			retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
			}
/*
			if (store_files)
			{
				int text_retv	= DB_Insert_Text("biz02" , "reppaper" , log_node->report_path , sql_condition);
				if (text_retv)
				{
					ccis_log_err("[%s]报告文件%s入库失败！SQL返回值：%d" , log_node->querysn , log_node->report_path , text_retv);
				}
			}
*/
		}break;
		case CCIS_DOWNLOAD_REPORT_NEW:{
			sprintf(sql_command , "reppath='%s'" , log_node->report_path);
			retv	= DB_Update_Data("biz02" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
				retv	= 1;
				goto clean_up;
			}
			memset (sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);

			sprintf(sql_command , "repno='%s',phoneno='%s',chgnum='%d',querysgn='%s',falres='%d',rept='%s',flow='%d',condt='%s'" , log_node->repno,log_node->phonenum,log_node->chgnum,log_node->querysgn,log_node->falres,cur_time , log_node->cur_flow.node_index,log_node->cur_flow.Condition);
			retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
			}
/*
			if (store_files)
			{
				int text_retv	= DB_Insert_Text("biz02" , "reppaper" , log_node->report_path , sql_condition);
				if (text_retv)
				{
					ccis_log_err("[%s]报告文件%s入库失败！SQL返回值：%d" , log_node->querysn , log_node->report_path , text_retv);
				}
			}
*/
		}break;
		case CCIS_DOWNLOAD_REPORT_CHARGE:{
			sprintf(sql_command , "reppath='%s'" , log_node->report_path);
			retv	= DB_Update_Data("biz02" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
				retv	= 1;
				goto clean_up;
			}
			memset (sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);

			sprintf(sql_command , "repno='%s',phoneno='%s',chgno='%s',querysgn='%s',prtsgn='0',falres='%d',rept='%s',flow='%d',condt='%s'" , log_node->repno,log_node->phonenum,log_node->chgno,log_node->querysgn,log_node->falres,cur_time , log_node->cur_flow.node_index,log_node->cur_flow.Condition);
			retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
			if (retv)
			{
				ccis_log_err("[%s][%s] Database Update Failed , returned %d" , __FUNCTION__ , log_node->querysn , retv);
			}
/*
			if (store_files)
			{
				int text_retv	= DB_Insert_Text("biz02" , "reppaper" , log_node->report_path , sql_condition);
				if (text_retv)
				{
					ccis_log_err("[%s]报告文件%s入库失败！SQL返回值：%d" , log_node->querysn , log_node->report_path , text_retv);
				}
			}
*/
		}break;
		default:{
			ccis_log_err("[%s]未知类型0x%x无法插入数据库！" , log_node->querysn , type);
		}
	}

clean_up:
	Do_Close();
	if (cur_time)
		free(cur_time);
	if (sql_command)
		free(sql_command);
	if (sql_condition)
		free(sql_condition);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}

	return retv;
}

int Business_Done(pSearch_Log log_node)		//仅用于流程正常结束（非自检）模式
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	char* sql_command	= NULL;
	char* sql_condition	= NULL;
	char* cur_time		= NULL;

	Do_Connect();
	if (strcmp(log_node->querysgn , "1") && strcmp(log_node->querysgn , "2"))
	{
		if (interval_s > 0)				//当开启了流程维持的时候，允许在流程结束时仍然是查询中状态
			strcpy(log_node->querysgn , "0");
		else						//否则认为流程已结束
			strcpy(log_node->querysgn , "1");
	}


	if (log_node->falres != CCIS_PROC_ALL_DONE && (log_node->falres & 0xF00F) == 0)	//在流程未完成且没有其他错误的情况下
	{
		if (strcmp(log_node->prtsgn , "0") == 0 && strcmp(log_node->querysgn , "2") == 0 && log_node->falres == CCIS_PROC_REPORT_WORKING)	//若报告未打印，且无其他错误的情况下进入到了结束流程，可认为是报告打印超时
			log_node->falres	|= CCIS_ERR_REP_PRINT_TIMEOUT;
		else
			log_node->falres	|= USER_CHOICE;
	}

	sql_command	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_command)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	sql_condition	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}

	cur_time	= Get_String_From_Time(&log_node->lastpackage);
	if (!cur_time)
	{
		ccis_log_alert("[%s]获取时间字符串失败，流程继续..." , log_node->querysn);
	}

	memset(sql_command , 0 , sizeof(char) * CCIS_MIDSIZE);
	memset(sql_condition , 0 , sizeof(char) * CCIS_SMALLSIZE);

	sprintf(sql_condition , "querysn='%s'" , log_node->querysn);
	if (strcmp(log_node->prtsgn , "1") == 0)
		sprintf(sql_command , "querysgn='%s',prtsgn='%s',prtdttime='%s',rept='%s',falres='%d',chgnum='%d',flow='%d',condt='%s'" , log_node->querysgn,log_node->prtsgn,log_node->prtdttime,cur_time,log_node->falres,log_node->chgnum,log_node->cur_flow.node_index,log_node->cur_flow.Condition);
	else
		sprintf(sql_command , "querysgn='%s',prtsgn='%s',rept='%s',falres='%d',chgnum='%d',flow='%d',condt='%s'" , log_node->querysgn , log_node->prtsgn , cur_time , log_node->falres , log_node->chgnum , log_node->cur_flow.node_index , log_node->cur_flow.Condition);
	retv	= DB_Update_Data("biz01" , sql_command , sql_condition);

	remove(log_node->idpic_path);
	ccis_log_info("删除身份证照片：%s\n" , log_node->idpic_path);
	remove(log_node->authpic_path);
	ccis_log_info("删除高清照片：%s\n" , log_node->authpic_path);
	remove(log_node->sppic_path);
	ccis_log_info("删除现场照片：%s\n" , log_node->sppic_path);
	Free_Log_Node(log_node->querysn);

clean_up:
	Do_Close();
	if (sql_command)
		free(sql_command);
	if (sql_condition)
		free(sql_condition);
	if (cur_time)
		free(cur_time);
	return retv;
}

void Free_IDInfo(pID_Info pstID)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pstID)
		return;

	if (pstID->id)
		free(pstID->id);
	if (pstID->name)
		free(pstID->name);
	if (pstID->sex)
		free(pstID->sex);
	if (pstID->nation)
		free(pstID->nation);
	if (pstID->birthday)
		free(pstID->birthday);
	if (pstID->address)
		free(pstID->address);
	if (pstID->authority)
		free(pstID->authority);
	if (pstID->period)
		free(pstID->period);
	if (pstID->ctrscr)
		free(pstID->ctrscr);
	free(pstID);
}

int Check_Newer_Log(char* querysn , time_t lastpackage)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!querysn)
		return 1;

	int retv		= 0;
	char* sql_condition	= NULL;
	Query_Info* q_ret	= NULL;
	char* last_time_str	= NULL;
	Do_Connect();

	sql_condition	= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}

	q_ret		= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));
	last_time_str	= (char*)malloc(sizeof(char) * 20);
	if (!last_time_str)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}

	sprintf(sql_condition , "querysn='%s'" , querysn);
	retv	= DB_Select_Data("biz01" , "rept" , sql_condition , q_ret);
	if (retv)
	{
		ccis_log_err("[%s][%s]Database Select Error : %d" , __FUNCTION__ , querysn , retv);
		retv	= 1;
		goto clean_up;
	}
	if (q_ret->res_data[0][0])
		strncpy(last_time_str , q_ret->res_data[0][0] , 20);
	else
	{
		ccis_log_err("[%s]数据库流程时间错误，允许直接更新！" , querysn);
		retv	= 0;
		goto clean_up;
	}
	ccis_log_debug("[%s]上个报文时间：%s" , querysn , last_time_str);
	if (Compute_PassSecond(Get_Time_From_String(last_time_str) , lastpackage) < 0)
	{
		ccis_log_notice("[%s]流程数据库记录为最新记录，不予更新！" , querysn);
		retv	= 1;
		goto clean_up;
	}


clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	if (last_time_str)
		free(last_time_str);
	return retv;
}

int Upload_Log_Node(pSearch_Log log_node)	//仅用于流程异常结束（触发自检）模式
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	char* sql_command	= NULL;
	char* sql_condition	= NULL;
	char* time_str		= NULL;
	Do_Connect();
	sql_command		= (char*)malloc(sizeof(char) * CCIS_MAXSIZE);
	if (!sql_command)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	sql_condition		= (char*)malloc(sizeof(char) * CCIS_SMALLSIZE);
	if (!sql_condition)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	if (strcmp(log_node->querysgn , "1") && strcmp(log_node->querysgn , "2"))
	{
		if (interval_s > 0)				//当开启了流程维持的时候，允许在流程结束时仍然是查询中状态
			strcpy(log_node->querysgn , "0");
		else						//否则认为流程已结束
			strcpy(log_node->querysgn , "1");
	}

	if (log_node->falres != CCIS_PROC_ALL_DONE && (log_node->falres & 0xF00F) == 0)
	{
		if (strcmp(log_node->prtsgn , "0") == 0 && strcmp(log_node->querysgn , "2") == 0 && log_node->falres == CCIS_PROC_REPORT_WORKING)	//若报告未打印，且无其他错误的情况下进入到了结束流程，可认为是报告打印超时
			log_node->falres	|= CCIS_ERR_REP_PRINT_TIMEOUT;
		else
			log_node->falres	|= USER_CHOICE;
	}

	sprintf(sql_condition , "querysn='%s'" , log_node->querysn);

	time_str	= Get_String_From_Time(&log_node->lastpackage);
	if (!time_str)
	{
		ccis_log_err("[%s]获取时间字符串失败！" , log_node->querysn);
		retv	= 1;
		goto clean_up;
	}

	if (strlen(log_node->prtdttime) != 0)
	{
		sprintf(sql_command , "chkret='%s',phoneno='%s',disid='%s',chgno='%s',repno='%s',rctrscr='%lf',chgnum='%d',querysgn='%s',prtsgn='%s',prtdttime='%s',reptype='%s',falres='%u',flow='%d',condt='%s',rept='%s'" , log_node->chkret,log_node->phonenum,log_node->disid,log_node->chgno,log_node->repno,log_node->rctrscr,log_node->chgnum,"1",log_node->prtsgn,log_node->prtdttime,log_node->report_type,log_node->falres,log_node->cur_flow.node_index,log_node->cur_flow.Condition,time_str);
	}
	else
	{
		sprintf(sql_command , "chkret='%s',phoneno='%s',disid='%s',chgno='%s',repno='%s',rctrscr='%lf',chgnum='%d',querysgn='%s',prtsgn='%s',reptype='%s',falres='%u',flow='%d',condt='%s',rept='%s'" , log_node->chkret,log_node->phonenum,log_node->disid,log_node->chgno,log_node->repno,log_node->rctrscr,log_node->chgnum,"1",log_node->prtsgn,log_node->report_type,log_node->falres,log_node->cur_flow.node_index,log_node->cur_flow.Condition,time_str);
	}

	retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
	if (retv)
	{
		ccis_log_err("[%s]biz01表更新失败！" , log_node->querysn);
	}

	memset(sql_command , 0 , sizeof(char) * CCIS_MAXSIZE);
	sprintf(sql_command , "idpath='%s',sppath='%s',reppath='%s'" , log_node->idpic_path , log_node->sppic_path , log_node->report_path);
	retv	= DB_Update_Data("biz02" , sql_command , sql_condition);
	if (retv)
	{
		ccis_log_err("[%s]biz02表更新失败！" , log_node->querysn);
	}

clean_up:
	Do_Close();
	if (sql_command)
		free(sql_command);
	if (sql_condition)
		free(sql_condition);
	if (time_str)
		free(time_str);

	return retv;
}

int Get_OrgDevName(const char* orgid , const char* devsn , char* orgname , char* devname)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!orgid || !devsn || !orgname || !devname)
		return -1;

	int retv	= 0;
	char *sql_condition;
	Query_Info* q_ret;

	Do_Connect();
	sql_condition	= (char*)malloc(sizeof(char) * CCIS_MIDSIZE);
	if (!sql_condition)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	q_ret	= (Query_Info*)malloc(sizeof(Query_Info));
	if (!q_ret)
	{
		retv	= -1;
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	memset(q_ret , 0 , sizeof(Query_Info));

	sprintf(sql_condition , "orgid='%s'" , orgid);
	retv	= DB_Select_Data("org01" , "orgname" , sql_condition , q_ret);
	if (retv == -1)
	{
		ccis_log_err("无[%s]机构号信息！" , orgid);
		retv	= 1;
		goto clean_up;
	}
	else if (retv != 0)
	{
		ccis_log_err("[%s:%d]数据库查询未知错误！SQL返回值：%d" , __FUNCTION__ , __LINE__ , retv);
		retv	= 1;
		goto clean_up;
	}
	if (!(q_ret->res_data[0][0]))
	{
		ccis_log_err("机构号[%s]无对应机构名称！" , orgid);
		retv	= 1;
		goto clean_up;
	}
	else
	{
		strcpy(orgname , q_ret->res_data[0][0]);
		ccis_log_debug("机构号[%s]对应名称%s" , orgid , orgname);
	}

	memset (q_ret , 0 , sizeof(Query_Info));
	memset (sql_condition , 0 , sizeof(char) * CCIS_MIDSIZE);
	sprintf(sql_condition , "devsn='%s'" , devsn);
	retv	= DB_Select_Data("dev02" , "devname" , sql_condition , q_ret);
	if (retv == -1)
	{
		ccis_log_err("无[%s]设备号信息！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	else if (retv != 0)
	{
		ccis_log_err("[%s:%d]数据库查询未知错误！SQL返回值：%d" , __FUNCTION__ , __LINE__ , retv);
		retv	= 1;
		goto clean_up;
	}
	if (!(q_ret->res_data[0][0]))
	{
		ccis_log_err("设备号[%s]无对应设备名称！" , devsn);
		retv	= 1;
		goto clean_up;
	}
	else
	{
		strcpy(devname , q_ret->res_data[0][0]);
		ccis_log_debug("设备号[%s]对应名称%s" , devsn , devname);
	}

clean_up:
	Do_Close();
	if (sql_condition)
		free(sql_condition);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}

int Cleanup_ExpiredReport()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif

	int retv	= 0;
	Do_Connect();
	char* stop_date	= Compute_Days_Before(report_reserved_days);
	if (!stop_date)
	{
		ccis_log_err("过期报告调整失败：日期计算出错！");
		retv	= 1;
		goto clean_up;
	}
	Query_Info* q_ret	= (Query_Info*)calloc(1 , sizeof(Query_Info));
	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}

	char end_time[SECOND_TIME_LEN];
	char sql_condition[CCIS_MIDSIZE];
	char* select_result[MAXROW] = {NULL};		//保存待调整的记录的序列号
	int counts	= 0;

	strcpy(end_time , stop_date);
	strcat(end_time , " 23:59:59");

	ccis_log_debug("本次过期报告调整结束时间：%s" , end_time);

	sprintf(sql_condition , "querysgn='2' and prtsgn='0' and querydt < '%s'" , end_time);

	retv	= DB_Select_Data("biz01" , "querysn" , sql_condition , q_ret);
	if (retv > 0)
	{
		ccis_log_err("[%s:%d]数据库查询失败！SQL返回码：%d" , __FUNCTION__ , __LINE__ , retv);
		retv	= 1;
		goto clean_up;
	}
	else if (retv == -1)
	{
		ccis_log_info("无过期报告存在，调整结束！");
		retv	= 0;
		goto clean_up;
	}

	counts	= q_ret->num_rows;
	if (counts >= MAXROW)
		counts	= MAXROW - 1;		//每次最多仅调整MAXROW - 1条数据

	for (int i = 0 ; i < counts ; i ++)
	{
		select_result[i]	= (char*)malloc(sizeof(char) * QUERYSN_LEN);
		if (!select_result[i])
		{
			ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
			retv	= 1;
			goto clean_up;
		}
		if (!q_ret->res_data[i][0])
		{
			ccis_log_err("数据库查询未知错误：序列号丢失！");
			retv	= 1;
			goto clean_up;
		}
		strcpy(select_result[i] , q_ret->res_data[i][0]);
	}

	if (q_ret->ptr)
	{
		mysql_free_result(q_ret->ptr);
		q_ret->ptr	= NULL;
	}
	memset(q_ret , 0 , sizeof(Query_Info));
	ccis_log_info("本次自检将调整%d条查询记录" , counts);
	for (int i = 0 ; i < counts ; i ++)		//删除报告文件，更新prtsgn标志
	{
		sprintf(sql_condition , "querysn='%s'" , select_result[i]);
		retv	= DB_Select_Data("biz02" , "reppath" , sql_condition , q_ret);
		if (retv > 0)
		{
			ccis_log_err("[%s:%d]数据库查询失败！SQL返回码：%d" , __FUNCTION__ , __LINE__ , retv);
			continue;
		}
		else if (retv < 0)
		{
			ccis_log_err("查询记录(%s)相关信息丢失！" , select_result[i]);
			continue;
		}
		else
		{
			if (!q_ret->res_data[0][0])
				ccis_log_err("查询记录(%s)报告路径信息丢失！" , select_result[i]);
			else if (remove(q_ret->res_data[0][0]))
			{
				ccis_log_err("过期报告(%s)删除失败！失败原因：%s" , q_ret->res_data[0][0] , strerror(errno));
				if (errno != ENOENT)			//不是文件丢失引起的删除失败，需要留存等待下次调整
					continue;
			}
			else
				ccis_log_info("过期报告(%s)已删除！" , q_ret->res_data[0][0]);
		}

		sprintf(sql_condition , "querysn='%s'" , select_result[i]);
		retv	= DB_Update_Data("biz01" , "prtsgn='3'" , sql_condition);
		if (retv)
			ccis_log_err("查询记录(%s)报告打印标志调整失败！" , select_result[i]);
		else
			ccis_log_debug("查询记录(%s)报告打印标志调整完成！" , select_result[i]);

		if (q_ret->ptr)
		{
			mysql_free_result(q_ret->ptr);
			q_ret->ptr	= NULL;
		}
	}

clean_up:
	Do_Close();
	if (stop_date)
		free(stop_date);
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	for (int i = 0 ; i < MAXROW ; i ++)
	{
		if (select_result[i])
			free(select_result[i]);
	}

	return retv;
}

int Correct_DataBase()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	Do_Connect();
	Query_Info* q_ret	= (Query_Info*)calloc(1 , sizeof(Query_Info));
	char sql_condition[CCIS_MIDSIZE];
	char sql_command[CCIS_MIDSIZE];

	if (!q_ret)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	retv	= DB_Select_Data("biz01" , "querysn,falres" , "querysgn='0'" , q_ret);
	if (retv > 0)
	{
		ccis_log_err("[%s:%d]数据库查询错误！SQL返回码：%d" , __FUNCTION__ , __LINE__ , retv);
		retv	= 1;
		goto clean_up;
	}
	else if (retv <= -1)
	{
		ccis_log_info("暂不存在需要调整的查询记录！");
		retv	= 0;
		goto clean_up;
	}

	int counts	= q_ret->num_rows;
	int falres	= 0;
	for (int i = 0 ; i < counts ; i ++)
	{
		if (q_ret->res_data[i][0])
			sprintf(sql_condition , "querysn='%s'" , q_ret->res_data[i][0]);
		else
			continue;
		if (q_ret->res_data[i][1])
		{
			falres	= atoi(q_ret->res_data[i][1]);
			if ((falres & TYPECODE_MASK) == 0)
				if ((falres & ERRCODE_MASK) == 0)
					falres	|= CCIS_ERR_SELF_CHECK;
				else
					falres	|= SELF_CHECK_SYNC;
			sprintf(sql_command , "querysgn='1',falres='%d'" , falres);
		}
		else
		{
			ccis_log_err("[%s]falres错误！无法更新记录！" , q_ret->res_data[i][0]);
			continue;
		}

		retv	= DB_Update_Data("biz01" , sql_command , sql_condition);
		if (retv)
		{
			ccis_log_err("[%s]数据库更新错误！SQL返回码：%d" , q_ret->res_data[i][0] , retv);
			continue;
		}
		ccis_log_debug("[%s]异常查询记录已更新！" , q_ret->res_data[i][0]);
	}

clean_up:
	Do_Close();
	if (q_ret)
	{
		if (q_ret->ptr)
			mysql_free_result(q_ret->ptr);
		free(q_ret);
	}
	return retv;
}
