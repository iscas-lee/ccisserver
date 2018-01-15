#ifndef __CCIS_STSVR_H__
#define __CCIS_STSVR_H__

#include "../../ccis.h"
#include "../../schedule/flow_control.h"
#include "../../other/ccis_thread.h"
#include <time.h>
#include <stdbool.h>

/*****************************************/
struct Search_Log{
	char	querysn[QUERYSN_LEN];
	char	devsn[DEVSN_LEN];

	char	idnum[19];
	char	qyear[5];
	char	querydt[21];
	int	qnum;
	char	idtype[5];
	char	idname[33];
	char	idsex[5];
	char	nation[33];
	char	birthdt[20];
	char	addr[300];
	char	idstartdt[11];
	char	idenddt[11];
	char	issauth[65];
	char	chkret[2];
	char	phonenum[12];
	short	vfyret;				//公安部核查结果
	char	idpic_path[CCIS_PATHLEN];
	char	authpic_path[CCIS_PATHLEN];
	char	sppic_path[CCIS_PATHLEN];
	char	infpic_path[CCIS_PATHLEN];
	bool	unprint_up_flag;
	char	report_path[CCIS_PATHLEN];
	char	old_report_path[CCIS_PATHLEN];

	char	orgid[19];
	char	orgname[50];
	char	devname[50];
	float	rctrscr;
	float	ctrscr;
	short	comp_time;			//比对次数，在比对成功的情况下，奇数表示最终成功在身份证比对上，偶数表示最终成功在公安部照片上
	char	querysgn[2];			//0表示未查询结束，1表示未下载报告，但是用户选择了结束，2表示报告已经下载成功
	char	prtsgn[2];			//0表示未打印成功，1表示打印成功
	char	disid[55];			//异议查询编号
	char	chgno[25];			//收费查询编号
	int	chgtype;
	unsigned long long	olchg_seq;			//移动支付编号
	int	olchg_status;			//移动支付错误码
	int	chgnum;
	int	lastchgnum;
	char	orderid[CHG_ORDERID_LEN];
	char	report_type[3];
	char	repno[25];
	char	old_repno[25];
	char	prtdttime[20];

	unsigned int falres;
	unsigned int retry_time;
	time_t	lastpackage;
	
	struct Flow cur_flow;
	Thread_Info *t_list;

	struct Search_Log* next;
};
typedef struct Search_Log* pSearch_Log;
/*******************************************/

/*****************业务链表头****************/
struct Server_List_Head{
	int node_num;
	pSearch_Log log_node;
};
typedef struct Server_List_Head* pSLH;

pSLH Search_List;
/*******************************************/

extern int	Create_Log_List();
extern int	Init_Log_Node(pSearch_Log* plog_node);
extern pSearch_Log	Find_Log_Node(char* querysn);
extern pSearch_Log	Find_Log_Node_By_Dev(const char* devsn);
extern pSearch_Log	Add_Log_Node(pSearch_Log log_node);
extern void	Free_Log_Node(char* querysn);
extern void	Destroy_Log_List();
extern pSearch_Log	Dump_Log_Node(pSearch_Log log_node);

#endif
