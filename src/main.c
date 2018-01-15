#include "ccis.h"
#include "type.h"
#include "log/ccis_log.h"
#include "network/network.h"
#include "system/resource.h"
#include "server/server.h"
#include "security/security.h"
#include "other/ccis_time.h"
#include "other/ccis_thread.h"
#include "other/ccis_system.h"
#include "schedule/epoll/ccis_epoll.h"
#include "database/sql_pool.h"
#include "camera/FaceMatcher.h"
#include <sys/resource.h>
#include <curl/curl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <stdbool.h>

#define MUL_PROC

int	iSockfd;
int	stop;
unsigned long	memused_kb;

char* local_dir;

int* shm_masterpid;

void Handler_Stop(int sig)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	ccis_log_notice("Process Received Single %d To Stop ..." , sig);
	stop	= 1;
}

void Handler_Self_Check(int sig)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	ccis_log_notice("Process Received Single %d To Self Checking..." , sig);

	bool overflow_sign	= false;
	ccis_log_debug("开始清理业务链表...");
	pSearch_Log log_node	= Search_List->log_node;
	while(log_node)
	{
		if (Check_Newer_Log(log_node->querysn , log_node->lastpackage))
		{
			if ((log_node->falres & TYPECODE_MASK) == 0)
				if ((log_node->falres & ERRCODE_MASK) == 0)
					log_node->falres	|= CCIS_ERR_SELF_CHECK;
				else
					log_node->falres	|= SELF_CHECK_SYNC;
			Upload_Log_Node(log_node);
		}
		Free_Log_Node(log_node->querysn);
		log_node	= Search_List->log_node;
	}
	ccis_log_debug("业务链表清理结束！");

	pRing ring	= Ring_List->ring;
	ccis_log_debug("开始清理令牌环...");
	while(ring)
	{
		Free_Ring_Node(ring->devsn);
		ring	= Ring_List->ring;
	}
	ccis_log_debug("令牌环清理结束！");

	if (getpid() == *shm_masterpid)
	{
		ccis_log_info("开始清理照片目录...");
		if (unlikely(!local_dir))
		{
			ccis_log_err("文件存储目录指针无效！");
		}
		else
		{
			printf("当日文件路径：%s\n" , local_dir);
			char vis_dir[CCIS_PATHLEN];
			char id_dir[CCIS_PATHLEN];
			char pol_dir[CCIS_PATHLEN];
			strcpy(vis_dir , local_dir);
			strcpy(id_dir , local_dir);
			strcpy(pol_dir , local_dir);
			strcat(vis_dir , "/vis_photo");
			strcat(id_dir , "/id_photo");
			strcat(pol_dir , "/police_photo");
			char command[CCIS_MIDSIZE];
			memset(command , 0 , sizeof(char) * CCIS_MIDSIZE);
			sprintf(command , "rm -r %s" , vis_dir);
			if (system(command) == 0)
			{
				ccis_log_info("%s已删除" , vis_dir);
			}
			memset(command , 0 , sizeof(char) * CCIS_MIDSIZE);
			sprintf(command , "rm -r %s" , id_dir);
			if (system(command) == 0)
			{
				ccis_log_info("%s已删除" , id_dir);
			}
			memset(command , 0 , sizeof(char) * CCIS_MIDSIZE);
			sprintf(command , "rm -r %s" , pol_dir);
			if (system(command) == 0)
			{
				ccis_log_info("%s已删除" , pol_dir);
			}
			free(local_dir);
			local_dir	= NULL;
		}
		ccis_log_info("开始清理过期未打印报告...");
		Cleanup_ExpiredReport();

		ccis_log_info("开始矫正当日流程概况...");
		Correct_DataBase();
	}

	ccis_log_notice("Process Self Check Done...");
	unsigned long cur_mem	= 0;
	if ((cur_mem = GetMemUsed_KB()) == 0)
	{
		ccis_log_err("无法获取进程运行状态，进程将自动重启！");
		overflow_sign	= true;
	}
	else
	{
		if ((double)(cur_mem - memused_kb) / memused_kb > 0.30)
		{
			ccis_log_warning("进程内存消耗过大，将忽略重启配置项自动重启！");
			overflow_sign	= true;
		}
		else
			ccis_log_debug("进程内存初始值：%lukB，当前值：%lukB，增长率：%f" , memused_kb , cur_mem , (double)(cur_mem - memused_kb) / memused_kb);
	}
	if (auto_restart || overflow_sign)
	{
		ccis_log_notice("进程即将重启...");
		exit(0);
	}
	else
	{
		Set_Alarm();
		local_dir	= (char*)malloc(CCIS_PATHLEN * sizeof(char));
		if (unlikely(!local_dir))
		{
			ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
			exit(0);
		}
		else
			if (unlikely(Get_Filepath(5 , local_dir , NULL , NULL)))
			{
				ccis_log_err("文件存储目录获取失败！");
				exit (0);
			}
	}
}

/*
	调试模式：
		接收信号，中断当前流程，执行以下操作：
		1、在文件/tmp/pid-ccis-online.info中输出所有在线的客户端及其相关信息；
		2、在文件/tmp/pid-ccis-flow.info中输出所有未完成的业务及其相关信息；
*/
void Handler_Debugger(int sig)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	ccis_log_notice("[NOTICE]Process Received %d To Debugger Mode" , sig);

	char devfile[CCIS_PATHLEN];
	char flowfile[CCIS_PATHLEN];
	int pid	= getpid();
	sprintf(devfile , "/tmp/%d-ccis-online.info" , pid);
	sprintf(flowfile , "/tmp/%d-ccis-flow.info" , pid);
	FILE* devfp	= fopen(devfile , "wt");
	FILE* flowfp	= fopen(flowfile , "wt");
	if (!devfp || !flowfp)
	{
		ccis_log_err("调试模式启动失败：输出文件无法打开！失败原因：%s" , strerror(errno));
		goto clean_up;
	}

	char buffer[CCIS_MAXSIZE];
	if (Ring_List)
	{
		if (Ring_List->node_num > 0)
		{
			pRing ring	= Ring_List->ring;
			int counts	= 1;
			while (ring)
			{
				sprintf(buffer , "-----------设备%d---------\n" , counts ++);
				fwrite(buffer , sizeof(char) , strlen(buffer) , devfp);
				sprintf(buffer , "来源IP：%s\n" , ring->ip);
				fwrite(buffer , sizeof(char) , strlen(buffer) , devfp);
				sprintf(buffer , "本地描述符句柄：%d\n" , ring->fd);
				fwrite(buffer , sizeof(char) , strlen(buffer) , devfp);
				sprintf(buffer , "设备号：%s\n" , ring->devsn);
				fwrite(buffer , sizeof(char) , strlen(buffer) , devfp);
				sprintf(buffer , "TPM序列号：%s\n" , ring->tpmsn);
				fwrite(buffer , sizeof(char) , strlen(buffer) , devfp);
				sprintf(buffer , "Ukey序列号：%s\n" , ring->ukeysn);
				fwrite(buffer , sizeof(char) , strlen(buffer) , devfp);
				sprintf(buffer , "代理模式：%s\n" , ring->agent ? "是":"否");
				fwrite(buffer , sizeof(char) , strlen(buffer) , devfp);
				sprintf(buffer , "认证级别：");
				if (ring->verified == CCIS_CLIENT_HASH_CHECKED)
					strcat(buffer , "Hash认证通过\n");
				else if (ring->verified == (CCIS_CLIENT_HASH_CHECKED | CCIS_CLIENT_UKEY_CERT_VERIFIED))
					strcat(buffer , "Ukey认证通过\n");
				else if (ring->verified == CCIS_CLIENT_VERIFIED)
					strcat(buffer , "允许使用\n");
				else
				{
					sprintf(buffer , "认证级别：未知状态%#06x\n" , ring->verified);
				}
				fwrite(buffer , sizeof(char) , strlen(buffer) , devfp);
				sprintf(buffer , "--------------------------\n\n");
				fwrite(buffer , sizeof(char) , strlen(buffer) , devfp);

				ring	= ring->next;
			}
		}
		else
			fputs("暂无在线的客户端\n" , devfp);
	}
	else
	{
		fputs("令牌环链表异常\n" , devfp);
	}

	if (Search_List)
	{
		if (Search_List->node_num > 0)
		{
			int counts	= 1;
			pSearch_Log log_node	= Search_List->log_node;
			while(log_node)
			{
				sprintf(buffer , "-------------查询%d------------\n" , counts ++);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "查询序列号：%s\n" , log_node->querysn);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "来源设备号：%s\n" , log_node->devsn);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "身份证照片路径：%s\n" , log_node->idpic_path);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "公安部照片路径：%s\n" , log_node->authpic_path);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "现场照片路径：%s\n" , log_node->sppic_path);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "征信报告路径：%s\n" , log_node->report_path);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "未打印报告路径：%s\n" , log_node->old_report_path);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "人脸比对次数：%d\n" , log_node->comp_time);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "查询状态：");
				if (!strcmp(log_node->querysgn , "0"))
					strcat(buffer , "查询中\n");
				else if (!strcmp(log_node->querysgn , "1"))
					strcat(buffer , "未下载报告\n");
				else if (!strcmp(log_node->querysgn , "2"))
					strcat(buffer , "报告已下载\n");
				else
					sprintf(buffer , "查询状态：未知状态%s\n" , log_node->querysgn);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "打印状态：%s\n" , strcmp(log_node->prtsgn , "0") ? "已打印":"未打印");
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "错误码：%#06x\n" , log_node->falres);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				char *timestr	= Get_String_From_Time(&log_node->lastpackage);
				if (!timestr)
					sprintf(buffer , "最后一个报文时间：获取失败\n");
				else
				{
					sprintf(buffer , "最后一个报文时间：%s\n" , timestr);
					free(timestr);
					timestr	= NULL;
				}
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "当前流程：%d\n" , log_node->cur_flow.node_index);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "当前满足条件：%s\n" , log_node->cur_flow.Condition);
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);
				sprintf(buffer , "-------------------------------\n\n");
				fwrite(buffer , sizeof(char) , strlen(buffer) , flowfp);

				log_node	= log_node->next;
			}
		}
		else
		{
			fputs("暂无进行中的查询\n" , flowfp);
		}
	}
	else
	{
		fputs("查询链表异常\n" , flowfp);
	}

clean_up:
	if (devfp)
	{
		fflush(devfp);
		fclose(devfp);
	}
	if (flowfp)
	{
		fflush(flowfp);
		fclose(flowfp);
	}

	return;
}

/*
	重载模式：
		接收到信号后，重新载入配置文件
		仅支持部分的配置项重载
*/
void Handler_Reload(int sig)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (Reload_Configure())
		ccis_log_err("配置文件重载失败！");
	else
		ccis_log_notice("配置文件已重载！");
	if (getpid() == *shm_masterpid)
		Display_Configure();
}

void Handler_Ignore()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	return;
}

int main()
{
	if (geteuid() != 0)
	{
		fprintf(stderr , "错误：程序必须以管理员权限运行！\n");
		return -1;
	}
	signal(SIGINT , Handler_Stop);
	signal(SIGTERM , Handler_Stop);
	signal(SIGPIPE , Handler_Stop);
	signal(SIGALRM , Handler_Self_Check);
	signal(SIGVTALRM , Handler_Ignore);
	signal(SIGUSR1 , Handler_Debugger);
	signal(SIGUSR2 , Handler_Reload);

	int retv	= 0;
	log_level	= CCIS_LOG_DEBUG;
	openlog("CCISServer" , LOG_PID , LOG_LOCAL3);

#ifdef CALLTRACE
	ccis_log_info("CALLTRACE ：函数调用追踪已开启");
#endif
	retv	= Init_Resource();

	if (retv)
	{
		ccis_log_emerg("资源初始化失败，程序即将退出！");
		return -1;
	}
	ccis_log_info("服务端程序已启动，当前版本号：%s" , version);
	ccis_log_info("启动资源已初始化完成！");

	while((iSockfd = Create_Socket(serverip , serverport , AF_INET , SOCK_STREAM | SOCK_CLOEXEC , IPPROTO_TCP , max_socket_connection , 1)) < 0)
	{
		if (stop)
			return -1;
		ccis_log_alert("无法在[%s:%d]上创建套接字：%s，5秒后将自动重试" , serverip , serverport , strerror(errno));
		sleep(5);
	}
	ccis_log_info("套接字已监听，监听端口：%d" , serverport);

	if (Init_SSL())
	{
		ccis_log_emerg("SSL初始化失败，程序即将退出！");
		return -1;
	}
	ccis_log_info("SSL初始化完成！");

	if (auto_timesync)
	{
		ccis_log_info("时间同步已开启，时间服务器：%s" , timesync_server);
		if (Create_ASync_Thread((void*)Get_Remotetime , (void*)timesync_server , NULL))
		{
			ccis_log_alert("时间同步线程开启失败！无法执行时间同步！");
		}
	}

	int f_pid		= getpid();

	int shmid		= shmget((key_t)1 , sizeof(int) , 0644 | IPC_CREAT);
	if (shmid == -1)
	{
		ccis_log_emerg("无法创建共享内存，程序即将退出！失败原因：%s" , strerror(errno));
		exit (-1);
	}
	shm_masterpid		= (int*)shmat(shmid , 0 , 0);
	if ((void*)shm_masterpid == (void*)-1)
	{
		ccis_log_emerg("共享内存挂载失败，程序即将退出！失败原因：%s" , strerror(errno));
		exit(-1);
	}
	*shm_masterpid		= 65536;

	ccis_log_info("父进程%d已就绪" , f_pid);

#ifdef MUL_PROC
	int process_num		= 0;
	pid_t	procid		= -1;

	while (process_num ++ < process_limits)
	{
		procid		= fork();
		if (procid < 0)
		{
			ccis_log_emerg("无法创建进程，程序即将退出！失败原因：%s" , strerror(errno));
			retv	= -1;
			goto clean_up;
		}
		else if (procid > 0)
		{
			if (procid < *shm_masterpid)
				*shm_masterpid	= procid;
			continue;
		}
		else
		{
			ccis_log_info("子进程%d已创建" , getpid());
			Set_Alarm();
			break;
		}
	}

	int status	= 0;
	if (procid > 0)
	{
		while(!stop)
		{
			pid_t ret	= wait(&status);
			if (ret < 0)
			{
				ccis_log_emerg("父进程监听异常 , 程序将终止运行！异常原因：%s" , strerror(errno));
				retv	= EXIT_FAILURE;
				goto clean_up;
			}
			if ((status >> 8) == RESOURCE_INIT_ERR)
			{
				ccis_log_alert("子进程 %d 资源初始化失败，该子进程将不会自动重启，请检查系统资源！" , ret);
				continue;
			}
			else if (WIFEXITED(status))
			{
				ccis_log_notice("子进程 %d 正常退出 , 退出码 = %d" , ret , WEXITSTATUS(status));
			}
			else if (WIFSIGNALED(status))
			{
				ccis_log_err("子进程 %d 异常结束 , 退出码 = %d" , ret , WTERMSIG(status));
			}
			else if (WIFSTOPPED(status))
			{
				ccis_log_err("子进程 %d 被终止运行 , 退出码 = %d" , ret , WSTOPSIG(status));
			}
			else
			{
				ccis_log_err("子进程 %d 由于未知原因，已停止运行！" , ret);
			}

			if (ret == *shm_masterpid)
				*shm_masterpid	= 65536;

			if (!stop)
			{
				procid	= fork();
				if (procid < 0)
				{
					ccis_log_emerg("无法创建进程，程序即将退出！errno %d" , errno);
					continue;
				}
				else if(procid > 0)
				{
					if (procid < *shm_masterpid)
						*shm_masterpid	= procid;
					ccis_log_notice("新进程%d已创建" , procid);
				}
				else
				{
					Set_Alarm();
					break;
				}
			}
			else
				goto clean_up;
		}
		if (procid > 0)
			goto clean_up;
	}
#endif
	if (prctl(PR_SET_PDEATHSIG , SIGTERM))
	{
		ccis_log_err("子进程%d无法挂载信号关联！错误原因：%s" , getpid() , strerror(errno));
	}
	else
	{
		ccis_log_info("子进程%d信号关联已挂载" , getpid());
	}
	stop	= 0;
	if (Create_SQLpool(POOL_NUMBER))
	{
		ccis_log_err("无法连接到数据库，程序即将结束！");
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	curl_global_init(CURL_GLOBAL_ALL);

	struct rlimit rt;
	rt.rlim_max = rt.rlim_cur = rlimit_number;
	if (setrlimit(RLIMIT_NOFILE , &rt) == -1)
	{
		ccis_log_err("无法设置file_limits，进程即将退出！错误原因：%s" , strerror(errno));
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	ccis_log_info("文件句柄限制已设置成功，当前允许最大句柄数：%d" , rlimit_number);

	if (Create_Events_Pool())
	{
		ccis_log_emerg("无法创建epoll连接池！");
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	ccis_log_info("事件池已创建！");

	Channel* core	= Channel_New();
	if (!core)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！" , __FUNCTION__ , __LINE__);
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	Set_ChannelSock(core , iSockfd , EPOLLIN);

	if (Register_Events(core))
	{
		ccis_log_emerg("无法注册监听事件！");
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	ccis_log_info("核心事件已监听！");	

	if (Create_Log_List())
	{
		ccis_log_emerg("业务链表创建失败！");
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	ccis_log_info("业务链表已创建！");

	if (Create_Ring_List())
	{
		ccis_log_emerg("安全令牌链表创建失败！");
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	ccis_log_info("令牌环链表已创建！");

	if (Create_FlowMap(flow_control_conf_file))
	{
		ccis_log_emerg("流程控制图创建失败！");
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	ccis_log_info("流程控制图已创建！");
	if (Pre_Process_Image())
	{
		ccis_log_emerg("人脸识别模型预建立失败！");
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	ccis_log_info("人脸识别模型预建立成功！");

	if ((memused_kb	= GetMemUsed_KB()) == 0)
	{
		ccis_log_emerg("无法获取进程状态！");
		retv	= RESOURCE_INIT_ERR;
		goto clean_up;
	}
	ccis_log_info("进程已加载，初始内存大小：%lukB" , memused_kb);
	ccis_log_info("进程%d已初始化完成！" , getpid());
	
	if (local_dir)
	{
		free(local_dir);
	}
		
	local_dir	= (char*)malloc(CCIS_PATHLEN * sizeof(char));

	if (unlikely(!local_dir))
	{
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
	}
	else
	{
		if (unlikely(Get_Filepath(5 , local_dir , NULL , NULL)))
		{
			ccis_log_err("文件存储目录获取失败！");
		}
	}

	while(!stop)
	{
		Accept_Events(100);
	}

clean_up:
	ccis_log_info("Process is stopping...");
	curl_global_cleanup();
	Close_SSL();
	ccis_log_info("正在清理查询链表...");
	Destroy_Log_List();
	ccis_log_info("正在清理令牌环链表...");
	Destroy_Ring_List();
	ccis_log_info("正在销毁数据库连接池...");
	Destroy_SQLpool();
	ccis_log_info("正在销毁流程控制图...");
	Destroy_FlowMap();
	ccis_log_info("正在销毁事件池...");
	Destroy_Events_Pool();					//同时会关闭所有活跃的socket连接
	ccis_log_info("正在回收系统资源...");
	Recycle_Resource();
	ccis_log_info("Process Exited With %d" , retv);

	closelog();
	return retv;
}
