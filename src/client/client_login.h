#ifndef __CCIS_CLIENT_H__
#define __CCIS_CLIENT_H__

#include <openssl/rsa.h>
#include <stdbool.h>

typedef struct{
	char *hardmodelhash;
	char *softhash;
} HashInfo;
typedef HashInfo* pHashInfo;

typedef struct{
	char* ukeysn;
	char *tpmsn;
	char* prtsn;
	char* idrsn;
	char* tssn;
	char* chgsn;
	char* camsn01;
	char* camsn02;
	char* vedsn;
} HardSN;
typedef HardSN* pHardSN;

typedef struct{
	char* tpmsn;
	char* ukeysn;
} UkeyBind;
typedef UkeyBind* pUkeyBind;

typedef struct{
	char* pbcid;
	char* username;
	char* password;
	char* agt;
} PBCInfo;
typedef PBCInfo* pPBCInfo;

typedef struct{
	char* ip;
	char* netmask;
	char* gateway;
	char* dns;
} SystemInfo;
typedef SystemInfo* pSystemInfo;

extern int	Compare_Client_Hash(char* devsn , pHashInfo pstHash);			//对比软硬件hash值，匹配返回0
extern int	Insert_HardSN(char* devsn , pHardSN pstHard);				//插入硬件SN号
extern int	Modify_HardSN(char* devsn , pHardSN pstHard);				//更改硬件SN号
extern int	Get_UkeyPIN(char* devsn , char* tpmsn , char* ukeysn , char* result , int chkbind);	//获取Ukey PIN码
extern int	Try_NewPIN(char* ukeysn , char* newpin);				//查找是否存在未同步成功的新pin码，有则1，没有返回0
extern int	Bind_Ukey_TPM(char* devsn , char* tpmsn , char* ukeysn);		//绑定Ukey与TPM
extern int	Unbind_Ukey_TPM(char* devsn , char* tpmsn , char* ukeysn);		//删除Ukey绑定记录
extern int	Check_Ukey_TPM(char* devsn , char* tpmsn , char* ukeysn);		//检测Ukey与TPM绑定关系
extern int	Check_Ukey_Bind_Status(char* ukeysn);					//检测Ukey绑定状态
extern int	Insert_SystemInfo(char* devsn , pSystemInfo pstSystem);			//插入系统信息
extern int	Modify_SystemInfo(char* devsn , pSystemInfo pstSystem);			//更新系统信息
extern int	Receive_Ukey_Cert(char* filepath , char* buffer , int bufLen , int status);	//接收Ukey证书
extern int	Rollback_SystemInfo(char* devsn);						//回滚系统信息记录
extern int	Rollback_HardSN(char* devsn);						//回滚硬件信息记录
extern int	Check_Cert_In_CA(char* certfile);
extern int	Check_Orgid(const char* devsn , const char* orgid);			//验证Orgid有效性
extern int	Check_Pwd_Status(const char* pbcuser , char* newinfo , int* pwdlen , RSA* pubkey);//检验是否有密码需要更新，返回0表示无需修改，返回1表示需要修改，-1表示异常
extern int	Check_Account_Status(const char* devsn , const char* ukeysn , char* newinfo , int* pwdlen , RSA* pubkey);	//检验是否有帐密需要更新
extern int	Update_Account_Status(const char* devsn , const char* ukeysn , const char* pbcuser , int status);			//更新密码状态
extern int	Query_PBC_Account(const char* devsn , const char* ukeysn , const char* orgid , char* result);		//申请征信帐号密码
extern int	Check_PBCInfo_Change(const char* devsn , const char* ukeysn , PBCInfo* pstPBC);		//检测帐号更新状态
extern int	Record_PBCInfo_Change(const char* devsn , const char* ukeysn , PBCInfo* pstPBC , int status , int reason , const char* opera); //记录密码更新日志
extern int	Check_Register_Status(const char* devsn , const char* ukeysn , bool* tpmsign , bool* ukeysign);	//检测TPM与Ukey的注册状态
extern int	Version_Check(const char* client_ver , const char* lowlimit_ver , const char* uplimit_ver);	//检测客户端版本号，通过返回0,过低返回负值，过高返回正值
extern int	Compare_Version(const char* client_ver , const char* limit_ver , int sign);		//比较版本号
extern int	Check_LoginStatus(const char* devsn);					//检测登陆状态，0表示允许登陆，1表示禁止登陆

extern void	Free_Hash(pHashInfo pstHash);
extern void	Free_HardSN(pHardSN pstHard);
extern void	Free_UkeyBind(pUkeyBind pstUkeyBind);
extern void	Free_PBCInfo(pPBCInfo pstPBC);
extern void	Free_SystemInfo(pSystemInfo pstSystem);
#endif
