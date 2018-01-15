#ifndef __CCIS_SVR_H__
#define __CCIS_SVR_H__
#include "../schedule/flow_control.h"
#include "../ccis.h"
#include "../network/network.h"
#include "struct/server_struct.h"
#include "pbc/pbc.h"
#include "pbc/agent/upload_agent.h"
#include "../other/ccis_time.h"
#include "../other/ccis_common.h"
#include "../other/ccis_string.h"
#include "../security/struct/security_struct.h"
#include "online_charge.h"

struct ID_Info{
	char* id;
	char* name;
	char* sex;
	char* nation;
	char* birthday;
	char* address;
	char* authority;
	char* period;
	char* ctrscr;
};
typedef struct ID_Info* pID_Info;

extern void	Print_Log_Struct(pSearch_Log log_node);
extern int	Analyze_ID_Info(char* idinfo , pID_Info pstID);
extern pSearch_Log Find_LastBusiness(const char* idnum , const char* devsn);
extern void	Analyze_FlowProcess(pSearch_Log log_node , int* type , int* errcode);
extern int	Check_ID_Info(pSearch_Log log_node , pRing ring , pID_Info pstID , char* devsn);
extern int	Receive_ID_Photo(pSearch_Log log_node , char* photobuf , int bufLen , int status);
extern int	Receive_Vis_Photo(pSearch_Log log_node , char* photobuf , int bufLen , int status);
extern int	Receive_Inf_Photo(pSearch_Log log_node , char* photobuf , int bufLen , int status);
extern int	Receive_PhoneNumber(pSearch_Log log_node , pRing ring , char* buffer , char* phonenumber , SSL* ssl);
extern int	Download_New_Report(pSearch_Log log_node , pRing ring , SSL *ssl);
extern int	Get_Last_ChargeNum(pSearch_Log log_node);
extern int	Get_Charge_Result(pSearch_Log log_node , char* chargebuf);
extern int	Retreat_Charge_Log(pSearch_Log log_node);
extern int	Download_Charge_Report(pSearch_Log log_node , pRing ring , SSL* ssl);
extern int	Send_Old_Report(pSearch_Log log_node , pRing ring , SSL *ssl);
extern int	Resend_Report(pSearch_Log log_node , pRing ring , SSL *ssl);
extern int	Resend_Report_NoEN(pSearch_Log log_node , pRing ring , SSL *ssl);
extern int	Get_Print_Result(pSearch_Log log_node , int p_result);
extern int	Get_Unprint_Report(char* idnum , char* buffer , char* old_report_path , char* old_repno , char* report_type , bool* unprint_up_flag);
extern int	Compress_Encrypt_Send_Report(pSearch_Log log_node , pRing ring , SSL* ssl , int type , char* en_md5);
extern int	Update_Unprint_Sign(char* idnum , char* ignore_querysn , int sign , const char* old_report_path , bool* unprint_up_flag);
extern int	Insert_Info_To_DB(pSearch_Log log_node , int type);
extern int	Business_Done(pSearch_Log log_node);
extern void	Free_IDInfo(pID_Info pstID);
extern int	Check_Newer_Log(char* querysn , time_t lastpackage);
extern int	Upload_Log_Node(pSearch_Log log_node);
extern int	Get_OrgDevName(const char* orgid , const char* devsn ,  char* orgname , char* devname);
extern int	Send_File(SSL* ssl , char* filepath , int type , int errcode , char* querysn);
extern int	Send_Report_To_Client(SSL* ssl , pSearch_Log log_node , pRing ring , int type , int errcode);
extern int	Cleanup_ExpiredReport();
extern int	Correct_DataBase();



#endif
