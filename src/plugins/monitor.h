/*
将客户端的操作记录登记到数据库中，以便管理网站能够显示
*/
#ifndef __CCIS_MONITOR_H__
#define __CCIS_MONITOR_H__

/*******************************level********************************/
#define	MONITOR_NORMAL		0
#define	MONITOR_WARNING		1
#define	MONITOR_ERROR		2
#define	MONITOR_UNKNOW		4

/*******************************type*********************************/
#define	CCIS_MONITOR_LOGIN	0x0001			//客户端登陆
#define	CCIS_MONITOR_LOGOUT	0x0002			//客户端登出



/*******************************value********************************/
#define	CCIS_MONITOR_LOGIN_SUCCESS			0x0001		//客户端登陆成功
#define CCIS_MONITOR_LOGIN_UNKNOW_ERROR			0x0002		//客户端登陆未知错误
#define CCIS_MONITOR_LOGIN_NO_PRE_RING			0x0003		//客户端信息节点丢失
#define CCIS_MONITOR_LOGIN_DECRYPT_FAILED		0x0004		//客户端信息解密失败
#define CCIS_MONITOR_LOGIN_ENCRYPT_FAILED		0x0005		//客户端信息加密失败
#define CCIS_MONITOR_LOGIN_HASH_INVALID			0x0006		//客户端hash验证不通过
#define CCIS_MONITOR_LOGIN_RECORD_HARDSN_FAILED		0x0007		//客户端硬件信息记录失败
#define	CCIS_MONITOR_LOGIN_MODIFY_HARDSN_FAILED		0x0008		//客户端硬件信息变更失败
#define CCIS_MONITOR_LOGIN_NO_UKEY_PIN			0x0009		//客户端PIN码获取失败
#define	CCIS_MONITOR_LOGIN_UKEY_NOT_MATCHED		0x000A		//客户端UKEY与TPM绑定关系不匹配
#define	CCIS_MONITOR_LOGIN_UKEY_BIND_FAILED		0x000B		//客户端Ukey与TPM绑定失败
#define	CCIS_MONITOR_LOGIN_UKEY_CERT_INVALID		0x000C		//客户端Ukey证书验证不通过
#define	CCIS_MONITOR_LOGIN_PBC_PASSWORD_ERROR		0x000D		//客户端征信密码错误
#define	CCIS_MONITOR_LOGIN_PBC_NO_SUCH_USER		0x000E		//客户端征信账号不存在
#define	CCIS_MONITOR_LOGIN_PBC_INVALIAD_PBCID		0x000F		//客户端征信机构号尚未登记
#define	CCIS_MONITOR_LOGIN_PBC_LOGIN_FAILED		0x0010		//客户端登陆征信中心失败（未知错误）
#define	CCIS_MONITOR_LOGIN_RECORD_SYSINFO_FAILED	0x0011		//客户端系统信息记录失败
#define	CCIS_MONITOR_LOGIN_MODIFY_SYSINFO_FAILED	0x0012		//客户端系统信息变更失败
#define	CCIS_MONITOR_LOGIN_TPM_CERT_UNREACHABLE		0x0013		//客户端TPM证书无法获取
#define	CCIS_MONITOR_LOGIN_TPM_PUBKEY_UNREACHABLE	0x0014		//客户端TPM公钥无法获取
#define	CCIS_MONITOR_LOGIN_FLOW_INVALID			0x0015		//客户端登陆流程非法
#define	CCIS_MONITOR_LOGIN_PBC_LOCKED			0x0016		//客户端账号已被锁定
#define CCIS_MONITOR_LOGIN_PBC_CANNOT_EMPTY		0x0017		//客户端账号或密码为空
#define	CCIS_MONITOR_LOGIN_PBC_REMOTE_SYSTEM_ERROR	0x0018		//征信中心系统异常
#define	CCIS_MONITOR_LOGIN_PBC_LOCAL_SYSTEM_ERROR	0x0019		//服务器系统异常


extern int	Client_Login_Status(int level , const char* devsn , int value , const char* comment);
extern int	Client_Logout_Status(int level , const char* devsn , int value , const char* comment);

#endif
