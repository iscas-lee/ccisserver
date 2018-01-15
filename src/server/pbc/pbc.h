#ifndef __CCIS_PBC_H__
#define __CCIS_PBC_H__
#include <stdio.h>
#include <sys/socket.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include "../../ccis.h"
#include "../../type.h"
#include <curl/curl.h>
#include "../struct/server_struct.h"

#ifndef BUFSIZE
#define BUFSIZE 1024
#endif
#ifndef DIR_SEPARATOR
#define DIR_SEPARATOR "/"
#endif
#define MINSIZE 16
#define	SMALLSIZE	64
#define MIDSIZE 128
#define MAXSIZE 1024
#define CERTNOLEN 18
#ifndef PWD_LEN
#define PWD_LEN 8
#endif

#define REPNOLEN	22
#define CHGNOLEN	23

#define ZX_LOGIN_DO "logon.do"
#define ZX_LOGIN_PARA "isDissentLogin=null&userid=%s&password=%s"
#define ZX_LOGIN_AGENT_PARA "isDissentLogin=null&method=login&name=%s&pws=%s&time=%lld"
#define ZX_LOGOUT_DO "logon.do"
#define ZX_LOGOUT_PARA "method=logout&_dc=%lld"
#define ZX_CHANGE_PWD_DO "forceChangePasswordAction.do"
#define ZX_CHANGE_PWD_PARA "userid=%s&password=%s&confirmpwd=%s&oldpassword=%s"
#define ZX_CHANGE_PWD_AGENT_DO "PsOuteruser.do"
#define ZX_CHANGE_PWD_AGENT_PARA "method=changepwd&psOuteruservo.userid=%s&psOuteruservo.oldpwd=%s&psOuteruservo.userpwd=%s&psOuteruservo.userpwd2=%s"
#define ZX_ALREADY_LOGIN_DO "menu.do"
#define ZX_ALREADY_LOGIN_PARA "method=menujs&_dc=%lld"
#define ZX_INNER_QUERY_DO "innerQueryChargeAction.do"
#define ZX_VERIFY_FEE_PARA "forwardtype=4&nexttype=1&querytype=%s&user=%s&ctype=%s&idno=%s&reltel=%s&relname=&relcerttype=&relcertno="
#define ZX_VERIFY_FEE_AGENT_PARA "user=%s&ctype=0&idno=%s&querytype=%s&reltel=%s&relname=&relcerttype=&relcertno=&forwardtype=1"
#define ZX_CHARGE_NO_PARA "user=%s&ctype=%s&idno=%s&querytype=%s&reltel=%s&relname=&relcerttype=&relcertno=&forwardtype=1&xlhc=%lld"
#define ZX_CHARGE_NO_AGENT_PARA "user=%s&ctype=%s&idno=%s&querytype=%s&reltel=%s&relname=&relcerttype=&relcertno=&forwardtype=1"
#define ZX_BRANCH_QUERY_DO "branchQueryCreditReportAction.do"
#define ZX_DISSENT_ID_PARA "t=1&name=%s&certno=%s&certtype=%s&queryreason=04&querylog=yes&querytype=%s&reltel=%s&relname=&relcerttype=&relcertno=&dissentid=null&backbutton=%s&chargeNOHidden=%s&chargestathidden=%c&querytypehidden=%s&querynumber=0&historychargestat=%c&automark=%s"
#define ZX_DISSENT_ID_BACK_BUTTON "/branchquery/newdissent/creditReport/branchPersonalCreditReportIndex.jsp"
#define ZX_INQUIRE_REPORT_DO "dissentInnerQueryActionV2.do"
#define ZX_INQUIRE_REPORT_PARA "name=%s&certno=%s&certtype=%s&queryreason=04&vertype=%s&dissentid=%s&chargeNO=%s"
#define ZX_INQUIRE_REPORT_AGENT_PARA "name=%s&certno=%s&certtype=%s&queryreason=04&vertype=%s&dissentid=%s&chargeNO=%s&fromSelfMachine=-%d"
#define ZX_POLICE_VERIFY_DO "checkquery.do"
#define ZX_POLICE_VERIFY_PARA "username=%s&certcode=%s&queryreason=04&policetype=0"
#define ZX_POLICE_DOWN_SERVLET "photoservlet"
#define ZX_POLICE_DOWN_PARA "Index=0"
#define ZX_POLICE_DOWN_AGENT_PARA "Index=0&t_xlhc_daniel=%lld"

#define ZX_COOKIE "/tmp/cookie.txt"

#define CHARGE_NUM	10			//收费时应收金额

//定义用户信息结构
struct UserInfoStruct
{
    char acCertType[MINSIZE];    //证件类型    
    char acCertNo[MIDSIZE];	   //证件编号
    char acCertName[SMALLSIZE];    //证件姓名
    char acQueryType[MINSIZE];    //查询类型（21，简版；24，简版+明细版）
    char acMobileNo[MINSIZE];    //手机号码
    char acQuerySn[MIDSIZE];    //查询日志ID
};

//定义获取异议ID的参数结构
struct DissentParaStruct
{
    char acChargeNo[MIDSIZE];	   //收费编码
    char acBackButton[MIDSIZE];    //回退按钮URL
    char cChargeStat;    //收费状态
    char cHistoryChargeStat;    //历史收费状态
};

//发送消息结构体
typedef struct
{
    int type;    //消息类型
    char *str;    //消息体，字符串
}msg_ci;

typedef struct{		//新增，存放征信相关信息，被包含于安全令牌中。
	char Orgid[19];
	char User[CCIS_SMALLSIZE];
	char Pwd[CCIS_SMALLSIZE];
}PBC;

struct MemoryStruct {	
    char *pcBuf;		//需要分配空间和free
    size_t uiSize;		//pcBuf的长度
};

CURL* curl;


//以下说明：未知错误表示所有系统原因导致的错误，比如内存分配失败，curl初始化失败等各种不应该被用户知道的错误

/*	Connection_To_PBC()
	参数：
	1、征信账号名
	2、征信密码
	3、是否需要代理
	4、新密码（这个参数我现在不知道怎么用也不知道怎么传入，也不知道有什么用，即是不是应该允许服务器去修改征信密码，因为现在服务器已经不存放客户端的征信信息在数据库中了，只会存放在内存中，因此感觉是不是应该取消这个功能）
	返回值：
	0、登陆成功
	1、征信账号或密码错误
	2、无法连接到征信服务器
	3、未知错误
*/
extern int	Connection_To_PBC(char *pcUserId, char *pcUserPwd, bool bAgtSign, char **ppNewPwd);

/*
	Download_Police_Photo()
	参数：
	1、征信账号名
	2、征信密码
	3、新密码，如果可以取消的话就取消
	4、用户信息结构体
	5、存放高清照片路径的指针
	6、是否需要代理（2.0允许同时支持需要代理和无需代理的客户端，因此所有需要代理的地方在源码中已经修改成了动态分配地址，详见.c中判断代理的部分）
	返回值：
	0、身份证验证通过并且照片下载成功
	1、无登记的高清照片
	2、身份证号码与姓名不匹配
	3、身份证号码无效
	4、身份证验证不通过
	5、无法下载高清照片
	6、公安部服务器连接失败
	7、未知错误
	
*/
extern int	Download_Police_Photo(char *pcUserId, char *pcUserPwd,char **new_pwd,struct UserInfoStruct *pstUserInfo, char *pcPolicePhoto, bool bAgtSign);

/*
	Download_Report_Free()
	参数：
	1、征信账号名
	2、征信密码（应该需要，因为与征信的连接是短链接，登陆后用完随即登出，下次登陆应该还是需要密码）
	3、用户信息结构体
	4、存放报告号的指针
	5、存放报告文件路径的指针
	6、如果需要收费的话，存放历史查询记录的指针，组合成可以直接发送的字符串格式；如果不需要收费，则不需对其进行任何操作
	7、是否需要代理
	返回值：
	0、报告下载成功
	1、初始查询系统错误:征信系统服务器连接失败
	2、初始查询系统错误:征信系统用户名或密码错误
	3、初始查询系统错误:征信系统查询错误
	4、初始查询其他错误
	5、需要收费（此时需要赋值history参数）
	6、未知错误
	
*/
extern int Download_Report_Free(const char* querysn , char *pcUserId, char* pcUserPwd, char **new_pwd, struct UserInfoStruct *pstUserInfo,
                                char *pcReportNo,char *pcReportFile, char **history, bool bAgtSign);

//extern int	Get_Charge_Information(char *pcUserId, char *(*apcFeeRet)[4], struct UserInfoStruct *pstUserInfo, bool bAgtSign);取消，由上一个函数完成功能

/*
	暂时不知道参数也不知道返回值，待定
*/
extern int Download_Report_Charge(const char* querysn , char *pcUserId, char* pcUserPwd, char **new_pwd, struct UserInfoStruct *pstUserInfo,
								  char *pcReportNo, char* pcChargeNo , char *pcReportFile,  bool bAgtSign);
/*
	Make_User_Info_Struct
	该函数我在另一个文件中实现了，使用的结构体是这个头文件定义的结构体，因此无需理会实现方式，只要直接使用即可
*/

extern int	Init_Curl();
extern int	Clean_Curl();

/*
#include "../../security/struct/security_struct.h"

extern int	Store_New_Password(pRing ring);	//status=1表示服务端已获取新密码，未更新至客户端。reason=1表示由于过期自动触发
*/
#endif
