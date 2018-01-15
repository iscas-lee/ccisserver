#ifndef __CCIS_TYPE_H__
#define __CCIS_TYPE_H__

/*********************MSG Type****************/
/*
字段说明：
	0x0001~0x000F		业务无关消息字段
	0x0010~0x001F		客户端登陆流程字段
	0x0020~0x003F		业务相关字段
	0x0040~0x004F		消息重发相关字段
*/

#define CCIS_PING				0x0001		//开机连接测试

#define CCIS_GET_TIME				0x0002		//获取对时报文
/*
#define	CCIS_SUCCESS				0x0001
#define CCIS_UNKNOW_ERROR			0x0002
*/

#define CCIS_UKEY_REGISTER			0x0003		//Ukey自助注册
/*
#define	CCIS_SUCCESS				0x0001
#define CCIS_UNKNOW_ERROR			0x0002
#define	CCIS_UR_NO_SUCH_UKEY			0x0101		//当前申请注册的Ukey未在数据库中登记
#define	CCIS_UR_SEND_CERT			0x0102		//正在发送Ukey证书文件
#define	CCIS_UR_SENDCERT_ERROR			0x0103		//证书发送失败
#define CCIS_UR_CERT_NOT_FOUND			0x0104		//证书文件丢失
#define CCIS_UR_REGISTER_SUCCESS		0x0105		//客户端保存Ukey证书与PIN码成功
#define CCIS_UR_REGISTER_FAILED			0x0106		//客户端保存Ukey证书与PIN码失败
#define CCIS_UR_ALREADY_REGISTED		0x0107		//客户端Ukey已经注册过
*/

#define CCIS_UKEY_RESEND_RESULT			0x0004		//重新发送注册好的Ukey证书与Ukey PIN码
/*
#define	CCIS_SUCCESS				0x0001
#define CCIS_UNKNOW_ERROR			0x0002
#define CCIS_UR_CERT_NOT_FOUND			0x0104		//证书文件丢失
*/

#define CCIS_TPM_REGISTER			0x0005		//TPM或软证书注册
/*
#define	CCIS_SUCCESS				0x0001
#define CCIS_UNKNOW_ERROR			0x0002
#define CCIS_TPM_NO_SUCH_DEV			0x0111		//当前申请注册的TPM或设备未登记
#define CCIS_TPM_SEND_CERT			0x0112		//正在发送TPM证书文件
#define CCIS_TPM_SENDCERT_ERROR			0x0113		//证书文件发送失败
#define CCIS_TPM_CERT_NOT_FOUND			0x0114		//证书文件丢失
#define CCIS_TPM_REGISTER_SUCCESS		0x0115		//客户端保存TPM证书成功
#define CCIS_TPM_REGISTER_FAILED		0x0116		//客户端保存TPM证书失败
#define CCIS_TPM_ALREADY_REGISTED		0x0117		//客户端TPM已经注册过
*/

#define CCIS_TPM_RESEND_RESULT			0x0006		//重新发送注册好的TPM证书
/*
#define	CCIS_SUCCESS				0x0001
#define CCIS_UNKNOW_ERROR			0x0002
#define CCIS_TPM_CERT_NOT_FOUND			0x0114		//证书文件丢失
*/

#define	CCIS_KEEPALIVE				0x0007		//保活心跳报文

#define CCIS_CLIENT_CHECK_HASH			0x0010		//验证客户端hash值
/*
#define CCIS_CLIENT_DECRYPT_FAILED		0x0060		//客户端数据解密失败
#define CCIS_CLIENT_CHECK_HASH_INVALID		0x0060		//客户端hash验证不通过
#define CCIS_CLIENT_CHECK_HASH_VALID		0x0061		//客户端hash验证通过
#define CCIS_LOW_VERSION			0x0006		//客户端版本过低，需要更新
#define CCIS_HIGH_VERSION			0x0007		//客户端版本过高，无法提供服务
#define CCIS_UNKNOW_VERSION			0x0008		//客户端版本未知，根据配置文件决定是否提供服务
#define	CCIS_CLIENT_DUPLICATE_LOGIN		0x006F		//客户端重复登陆
#define	CCIS_CLIENT_CERT_ERROR			0x0084		//客户端证书错误
*/

#define CCIS_CLIENT_UPLOAD_SN			0x0011		//接受所有的硬件SN号	返回值携带ukey PIN码 仅在首次开机时出现该type
/*
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_CLIENT_UKEY_ALREADY_USED		0x0075		//用户Ukey已被绑定
#define CCIS_CLIENT_RECORD_HARDSN_FAILED	0x0064		//客户端硬件SN记录失败
#define CCIS_CLIENT_RECORD_HARDSN_SUCCESS	0x0065		//客户端硬件SN记录成功
#define CCIS_CLIENT_NO_UKEY_PIN			0x0068		//获取UKEY PIN码失败
#define CCIS_CLIENT_ENCRYPT_FAILED		0x0061		//客户端信息加密失败
*/

#define CCIS_CLIENT_MODIFY_SN			0x0012		//更换硬件设备时接受SN号 返回携带ukey PIN码
/*
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_CLIENT_MODIFY_HARDSN_FAILED	0x0066		//客户端硬件SN变更失败
#define CCIS_CLIENT_MODIFY_HARDSN_SUCCESS	0x0067		//客户端硬件SN变更成功
#define CCIS_CLIENT_NO_UKEY_PIN			0x0068		//获取UKEY PIN码失败
#define CCIS_CLIENT_ENCRYPT_FAILED		0x0061		//客户端信息加密失败
#define CCIS_CLIENT_UKEY_NOT_MATCHED		0x0076		//当前使用的Ukey与TPM不匹配
*/

#define CCIS_CLIENT_GET_UKEY_PIN		0x0013		//返回UKEY的PIN码
/*
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_CLIENT_UKEY_PIN_MATCHED		0x0069		//获取UKEY PIN码成功
#define CCIS_CLIENT_NO_UKEY_PIN			0x0068		//获取UKEY PIN码失败
#define CCIS_CLIENT_ENCRYPT_FAILED		0x0061		//客户端信息加密失败
#define CCIS_CLIENT_UKEY_NOT_MATCHED		0x0076		//当前使用的Ukey与TPM不匹配
*/

#define CCIS_CLIENT_CHECK_UKEY_CERT		0x0014		//接收Ukey证书并验证
/*
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_CLIENT_CHECK_UKEY_CERT_INVALID	0x006A		//客户端Ukey证书验证不通过
#define CCIS_CLIENT_CHECK_UKEY_CERT_VALID	0x006B		//客户端Ukey证书验证通过
*/

#define CCIS_CLIENT_LOGIN_PBC_FIRST		0x0015		//客户端首次开机登陆	此处接受征信信息，验证通过后在数据库中绑定TPM与UKey
/*
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_CLIENT_DECRYPT_FAILED		0x0060		//客户端数据解密失败
#define CCIS_CLIENT_PBC_PASSWORD_ERROR		0x0070		//客户端征信密码错误
#define CCIS_CLIENT_PBC_NO_SUCH_USER		0x0071		//无此征信账号
#define CCIS_CLIENT_PBC_INVALIAD_PBCID		0x0072		//征信机构号无效
#define CCIS_CLIENT_PBC_LOGIN_FAILED		0x0072		//征信中心登陆失败（原因未知）
#define CCIS_CLIENT_PBC_LOGIN_SUCCESS		0x0073		//客户端登陆征信中心成功
#define CCIS_CLIENT_UKEY_BIND_FAILED		0x0075		//用户Ukey与TPM绑定失败
#define CCIS_CLIENT_UKEY_ALREADY_USED		0x0075		//用户Ukey已被绑定
#define	CCIS_CLIENT_PBC_PWD_CHANGE		0x0078		//征信密码应该更新
#define	CCIS_CLIENT_PBC_LOCKED			0x0080		//征信账号已被锁定
#define	CCIS_CLIENT_PBC_CANNOT_EMPTY		0x0081		//征信账号密码不可为空
#define	CCIS_CLIENT_PBC_REMOTE_SYSTEM_ERROR	0x0082		//征信中心系统异常
#define	CCIS_CLIENT_PBC_LOCAL_SYSTEM_ERROR	0x0083		//服务端系统异常
*/

#define CCIS_CLIENT_LOGIN_PBC_NORMAL		0x0016		//客户端开机登陆	此处接受征信信息
/*
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_CLIENT_DECRYPT_FAILED		0x0060		//客户端数据解密失败
#define CCIS_CLIENT_PBC_PASSWORD_ERROR		0x0070		//客户端征信密码错误
#define CCIS_CLIENT_PBC_NO_SUCH_USER		0x0071		//无此征信账号
#define CCIS_CLIENT_PBC_INVALIAD_PBCID		0x0072		//征信机构号无效
#define CCIS_CLIENT_PBC_LOGIN_FAILED		0x0072		//征信中心登陆失败（原因未知）
#define CCIS_CLIENT_PBC_LOGIN_SUCCESS		0x0073		//客户端登陆征信中心成功
#define CCIS_CLIENT_UKEY_NOT_MATCHED		0x0076		//当前使用的Ukey与TPM不匹配
#define	CCIS_CLIENT_PBC_PWD_CHANGE		0x0078		//征信密码应该更新
#define	CCIS_CLIENT_PBC_LOCKED			0x0080		//征信账号已被锁定
#define	CCIS_CLIENT_PBC_CANNOT_EMPTY		0x0081		//征信账号密码不可为空
#define	CCIS_CLIENT_PBC_REMOTE_SYSTEM_ERROR	0x0082		//征信中心系统异常
#define	CCIS_CLIENT_PBC_LOCAL_SYSTEM_ERROR	0x0083		//服务端系统异常
*/

#define CCIS_CLIENT_UPLOAD_SYSTEM_INFO		0x0017		//上传系统信息
/*
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_CLIENT_RECORD_SYSTEM_INFO_FAILED	0x006C		//客户端系统信息记录失败
#define CCIS_CLIENT_RECORD_SYSTEM_INFO_SUCCESS	0x006D		//客户端系统信息记录成功
#define CCIS_CLIENT_RECORD_HARDSN_FAILED	0x0064		//客户端硬件SN记录失败
*/

#define CCIS_CLIENT_MODIFY_SYSTEM_INFO		0x0018		//修改系统信息
/*
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_CLIENT_MODIFY_SYSTEM_INFO_FAILED	0x006E		//客户端系统信息变更失败
#define CCIS_CLIENT_MODIFY_SYSTEM_INFO_SUCCESS	0x006F		//客户端系统信息变更成功
#define CCIS_CLIENT_MODIFY_HARDSN_FAILED	0x0066		//客户端硬件SN变更失败
*/

#define	CCIS_CLIENT_PWD_CHANGE			0x0019		//征信密码修改
/*
#define	CCIS_CLIENT_PWD_CHANGE_SUCCESS
#define	CCIS_CLIENT_PWD_CHANGE_FAILED
*/

#define CCIS_CLIENT_PBC_QUERY			0x001A		//征信信息自动获取
/*
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_CLIENT_PBC_INVALIAD_PBCID		0x0072		//征信机构号无效
#define CCIS_CLIENT_PBC_QUERY_SUCCESS		0x007B		//征信帐号申请成功
#define CCIS_CLIENT_PBC_DOUBLE_QUERY		0x007C		//征信帐号申请操作重复
#define CCIS_CLIENT_PBC_ALREADY_EXIST		0x007D		//征信帐号已存在，不允许重新申请
#define CCIS_CLIENT_PBC_QUERY_FAILED		0x007E		//征信帐号申请出错
#define CCIS_CLIENT_PBC_ISSUED_SUCCESS		0x007F		//征信帐号颁发成功
*/



#define	CCIS_RECEIVE_ID_INFO			0x0020		//接收身份证信息
/*
#define CCIS_ID_INIT_NODE_FAILED		0x0020		//流程节点初始化错误
#define CCIS_ID_DECRYPT_FAILED			0x0021		//解密失败
#define CCIS_ID_DATA_INVALID			0x0022		//身份证不在有效期内
#define CCIS_ID_INCOMPLETE_INFO			0x0023		//身份证信息不完整
#define CCIS_ID_INVALID_NUMBER			0x0024		//身份证号码无效
#define CCIS_ID_INFO_NOT_MATCH			0x0025		//身份证信息不匹配
#define CCIS_ID_NO_POLICE_PHOTO			0x0027		//无高清照片
#define CCIS_ID_POLICE_PHOTO_DOWNLOAD_FAILED	0x0028		//下载高清照片失败
#define CCIS_ID_POLICE_CHECK_ERROR		0x0029		//联网核查失败
#define CCIS_ID_LINK_SERVER_FAILED		0x002A		//无法连接公安部服务器
#define CCIS_ID_LINK_SERVER_PWD_ERROR		0x002B		//征信网站账号密码错误
#define CCIS_ID_CHECK_SUCCESS			0x002F		//身份证验证通过
*/

#define CCIS_RECEIVE_ID_PHOTO			0x0021		//接收身份证照片
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_ID_PHOTO_SAVE_FAILED		0x0026		//身份证照片保存失败
#define CCIS_ID_PHOTO_SAVE_SUCCESS		0x002E		//身份证照片接收成功
*/

#define CCIS_RECEIVE_VIS_PHOTO			0x0022		//接收现场照片并开始人脸比对 最后一个报文接受后执行比对并发送结果
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_FM_VIS_PHOTO_RECV_FAILED		0x0030		//现场照片接收失败
#define CCIS_FM_VIS_PHOTO_NOT_FOUND		0x0031		//无法找到现场照片文件
#define CCIS_FM_ID_PHOTO_NOT_FOUND		0x0032		//无法找到身份证照片文件
#define CCIS_FM_POLICE_PHOTO_NOT_FOUND		0x0033		//无法找到高清照片文件
#define CCIS_FM_RETRY_DENY			0x0034		//重试次数超限
#define CCIS_FM_COMPARE_NOT_MATCH		0x003E		//人脸比对不通过
#define CCIS_FM_COMPARE_PASS			0x003F		//人脸比对成功
*/

#define CCIS_DOWNLOAD_REPORT			0x0023		//接收手机号并开始连接征信下载报告
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_RP_REPORT_SENDING			0x0045		//正在发送报告
#define CCIS_RP_PHONE_NUMBER_ERROR		0x0040		//手机号插入失败
#define CCIS_RP_UNPRINT_REPORT_EXIST		0x0041		//存在未打印报告
#define CCIS_RP_SHOULD_CHARGE			0x0042		//应该收费
#define CCIS_RP_QUERY_SYSTEM_ERROR		0x0047		//征信系统查询错误
#define CCIS_RP_QUERY_LINK_SERVER_FAILED	0x0048		//征信系统连接失败
#define CCIS_RP_QUERY_OTHER_ERROR		0x0049		//征信系统其他错误
#define CCIS_RP_QUERY_UNKNOW_ERROR		0x004A		//征信系统未知错误
#define CCIS_RP_DOWNLOAD_SUCCESS		0x004E		//报告发送成功
#define CCIS_RP_DOWNLOAD_FAILED			0x004F		//报告发送失败
#define CCIS_RP_TYPE_INVALID			0x0055		//报告类型不被支持
#define	CCIS_RP_CHARGEINFO_ERROR		0x0056		//获取收费信息失败
#define	CCIS_RP_REPNO_ERROR			0x0057		//获取报告号失败
#define	CCIS_RP_DISNO_ERROR			0x0058		//获取查询异议号失败
*/

#define CCIS_DOWNLOAD_REPORT_EXIST		0x0024		//发送已存在的未打印报告
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_RP_REPORT_SENDING			0x0045		//正在发送报告
#define CCIS_RP_UNPRINT_NOT_FOUND		0x0043		//未打印报告文件丢失
#define CCIS_RP_DOWNLOAD_SUCCESS		0x004E		//报告发送成功
#define CCIS_RP_DOWNLOAD_FAILED			0x004F		//报告发送失败
*/

#define CCIS_DOWNLOAD_REPORT_NEW		0x0025		//下载新报告
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_RP_REPORT_SENDING			0x0045		//正在发送报告
#define CCIS_RP_DOWNLOAD_SUCCESS		0x004E		//报告发送成功
#define CCIS_RP_DOWNLOAD_FAILED			0x004F		//报告发送失败
#define CCIS_RP_SHOULD_CHARGE			0x0042		//应该收费
#define CCIS_RP_QUERY_SYSTEM_ERROR		0x0047		//征信系统查询错误
#define CCIS_RP_QUERY_LINK_SERVER_FAILED	0x0048		//征信系统连接失败
#define CCIS_RP_QUERY_OTHER_ERROR		0x0049		//征信系统其他错误
#define CCIS_RP_QUERY_UNKNOW_ERROR		0x004A		//征信系统未知错误
#define	CCIS_RP_CHARGEINFO_ERROR		0x0056		//获取收费信息失败
#define	CCIS_RP_REPNO_ERROR			0x0057		//获取报告号失败
#define	CCIS_RP_DISNO_ERROR			0x0058		//获取查询异议号失败
*/

#define CCIS_GET_CHARGE_RESULT			0x0026		//获取收费信息
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_CHARGE_CONFIRM_SUCCESS		0x0045		//收费入库确认
#define CCIS_CHARGE_CONFIRM_FAILED		0x0046		//收费信息入库失败
*/

#define CCIS_RETREAT_CHARGE			0x0027		//退币请求
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_CHARGE_RETREAT_SUCCESS		0x0048		//退币确认
#define CCIS_CHARGE_RETREAT_FAILED		0x0049		//退币数据库操作失败
*/

#define CCIS_DOWNLOAD_REPORT_CHARGE		0x0028		//下载收费报告
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define	CCIS_CHARGE_NOT_ENOUGH			0x0044		//收费金额不足
#define CCIS_RP_REPORT_SENDING			0x0045		//正在发送报告
#define CCIS_RP_QUERY_SYSTEM_ERROR		0x0047		//征信系统查询错误
#define CCIS_RP_QUERY_LINK_SERVER_FAILED	0x0048		//征信系统连接失败
#define CCIS_RP_QUERY_OTHER_ERROR		0x0049		//征信系统其他错误
#define CCIS_RP_QUERY_UNKNOW_ERROR		0x004A		//征信系统未知错误
#define	CCIS_RP_CHARGEINFO_ERROR		0x0056		//获取收费信息失败
#define	CCIS_RP_REPNO_ERROR			0x0057		//获取报告号失败
#define	CCIS_RP_DISNO_ERROR			0x0058		//获取查询异议号失败
*/

#define	CCIS_GET_PRINT_RESULT			0x0029		//获取报告打印结果
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_RP_PRINT_SUCCESS			0x004B		//报告打印成功
#define CCIS_RP_PRINT_FAILED			0x004C		//报告打印失败
*/

#define	CCIS_OLCHG_REQUEST			0x002A		//移动支付
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define	CCIS_OLCHG_NOTSUPPORT			0x0090		//不支持在线支付
#define	CCIS_OLCHG_CONNECT_FAILED		0x0091		//收费服务器连接失败
#define	CCIS_OLCHG_TIMEOUT			0x0092		//收费服务器响应超时（包括获取二维码和收费结果）
#define	CCIS_OLCHG_SUCCESS			0x0093		//在线收费成功
#define	CCIS_OLCHG_FAILED			0x0094		//在线收费失败
#define	CCIS_OLCHG_QRCODE			0x0095		//发送二维码
#define	CCIS_OLCHG_CHARGE_WAITING		0x009A		//等待支付
*/

#define	CCIS_OLCHG_RECONFIRM			0x002B		//移动支付重新确认结果
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define	CCIS_OLCHG_NOTSUPPORT			0x0090		//不支持在线支付
#define	CCIS_OLCHG_CONNECT_FAILED		0x0091		//收费服务器连接失败
#define	CCIS_OLCHG_TIMEOUT			0x0092		//收费服务器响应超时（包括获取二维码和收费结果）
#define	CCIS_OLCHG_SUCCESS			0x0093		//在线收费成功
#define	CCIS_OLCHG_FAILED			0x0094		//在线收费失败
#define	CCIS_OLCHG_CHARGE_WAITING		0x009A		//等待支付
*/

#define	CCIS_OLCHG_REFUNDS			0x002C		//移动支付退款
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define	CCIS_OLCHG_REFUNDS_SUCCESS		0x0096		//退款请求提交成功
#define	CCIS_OLCHG_REFUNDS_FAILED		0x0097		//退款请求提交失败
*/

#define	CCIS_WORK_DONE				0x002F		//流程结束
/*
#define	CCIS_SUCCESS				0x0001
*/

#define CCIS_RESEND_REPORT			0x0040		//重新发送报告
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_RP_REPORT_SENDING			0x0045		//正在发送报告
#define CCIS_RP_DOWNLOAD_SUCCESS		0x004E		//报告发送成功
#define CCIS_RP_DOWNLOAD_FAILED			0x004F		//报告发送失败
#define CCIS_RP_RETRY_DENY			0x004D		//报告重发次数超限
*/

#define	CCIS_RESEND_REPORT_NOEN			0x0041		//重新发送报告（非加密格式）
/*
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define CCIS_PROCESS_INVALID			0x0004		//流程非法
#define CCIS_RP_REPORT_SENDING			0x0045		//正在发送报告
#define CCIS_RP_DOWNLOAD_SUCCESS		0x004E		//报告发送成功
#define CCIS_RP_DOWNLOAD_FAILED			0x004F		//报告发送失败
#define CCIS_RP_RETRY_DENY			0x004D		//报告重发次数超限
*/

/********************MSG Errcode**************/
/*
字段说明：
	0x0001~0x001F		Global
	0x0020~0x002F		身份证信息相关
	0x0030~0x003F		人脸比对相关
	0x0040~0x005F		征信报告相关
	0x0060~0x008F		客户端登陆相关
	0x0090~0x00AF		移动支付相关
	0x0100~0x010F		Ukey注册相关
	0x0110~0x011F		TPM注册相关
	0x0200~0x021F		自检程序相关
*/
#define	CCIS_SUCCESS				0x0001
#define CCIS_UNKNOW_ERROR			0x0002
#define CCIS_NO_PRE_LOG_NODE			0x0003		//未找到前置节点
#define	CCIS_NO_PRE_RING_NODE			0x0004		//未找到前置安全令牌
#define CCIS_PROCESS_INVALID			0x0005		//流程非法
#define CCIS_LOW_VERSION			0x0006		//客户端版本过低，需要更新
#define CCIS_HIGH_VERSION			0x0007		//客户端版本过高，无法提供服务
#define CCIS_UNKNOW_VERSION			0x0008		//客户端版本未知，根据配置文件决定是否提供服务

#define CCIS_ID_INIT_NODE_FAILED		0x0020		//流程节点初始化错误
#define CCIS_ID_DECRYPT_FAILED			0x0021		//解密失败
#define CCIS_ID_DATA_INVALID			0x0022		//身份证不在有效期内
#define CCIS_ID_INCOMPLETE_INFO			0x0023		//身份证信息不完整
#define CCIS_ID_INVALID_NUMBER			0x0024		//身份证号码无效
#define CCIS_ID_INFO_NOT_MATCH			0x0025		//身份证信息不匹配
#define CCIS_ID_PHOTO_SAVE_FAILED		0x0026		//身份证照片保存失败
#define CCIS_ID_NO_POLICE_PHOTO			0x0027		//无高清照片
#define CCIS_ID_POLICE_PHOTO_DOWNLOAD_FAILED	0x0028		//下载高清照片失败
#define CCIS_ID_POLICE_CHECK_ERROR		0x0029		//联网核查失败
#define CCIS_ID_LINK_SERVER_FAILED		0x002A		//无法连接公安部服务器
#define CCIS_ID_LINK_SERVER_PWD_ERROR		0x002B		//征信网站账号密码错误
#define CCIS_ID_PHOTO_SAVE_SUCCESS		0x002E		//身份证照片接收成功
#define CCIS_ID_CHECK_SUCCESS			0x002F		//身份证验证通过

#define CCIS_FM_VIS_PHOTO_RECV_FAILED		0x0030		//现场照片接收失败
#define CCIS_FM_VIS_PHOTO_NOT_FOUND		0x0031		//无法找到现场照片文件
#define CCIS_FM_ID_PHOTO_NOT_FOUND		0x0032		//无法找到身份证照片文件
#define CCIS_FM_POLICE_PHOTO_NOT_FOUND		0x0033		//无法找到高清照片文件
#define CCIS_FM_RETRY_DENY			0x0034		//重试次数超限
#define CCIS_FM_COMPARE_NOT_MATCH		0x003E		//人脸比对不通过
#define CCIS_FM_COMPARE_PASS			0x003F		//人脸比对成功

#define CCIS_RP_PHONE_NUMBER_ERROR		0x0040		//手机号插入失败
#define CCIS_RP_UNPRINT_REPORT_EXIST		0x0041		//存在未打印报告
#define CCIS_RP_SHOULD_CHARGE			0x0042		//应该收费
#define CCIS_RP_UNPRINT_NOT_FOUND		0x0043		//未打印报告文件丢失
#define	CCIS_CHARGE_NOT_ENOUGH			0x0044		//收费金额不足
#define CCIS_CHARGE_CONFIRM_SUCCESS		0x0045		//收费入库确认
#define CCIS_CHARGE_CONFIRM_FAILED		0x0046		//收费信息入库失败
#define CCIS_CHARGE_RETREAT_SUCCESS		0x0048		//退币确认
#define CCIS_CHARGE_RETREAT_FAILED		0x0049		//退币数据库操作失败
#define CCIS_RP_REPORT_SENDING			0x004A		//正在发送报告
#define CCIS_RP_QUERY_UP_ERROR			0x004B		//征信系统账号密码错误
#define CCIS_RP_QUERY_SYSTEM_ERROR		0x004C		//征信系统查询错误
#define CCIS_RP_QUERY_LINK_SERVER_FAILED	0x004D		//征信系统连接失败
#define CCIS_RP_QUERY_OTHER_ERROR		0x004E		//征信系统其他错误
#define CCIS_RP_QUERY_UNKNOW_ERROR		0x004F		//征信系统未知错误
#define CCIS_RP_RETRY_DENY			0x0050		//报告重发次数超限
#define CCIS_RP_DOWNLOAD_SUCCESS		0x0051		//报告发送成功
#define CCIS_RP_DOWNLOAD_FAILED			0x0052		//报告发送失败
#define CCIS_RP_PRINT_SUCCESS			0x0053		//报告打印成功
#define CCIS_RP_PRINT_FAILED			0x0054		//报告打印失败
#define CCIS_RP_TYPE_INVALID			0x0055		//报告类型不被支持
#define	CCIS_RP_CHARGEINFO_ERROR		0x0056		//获取收费信息失败
#define	CCIS_RP_REPNO_ERROR			0x0057		//获取报告号失败
#define	CCIS_RP_DISNO_ERROR			0x0058		//获取查询异议号失败

//客户端登陆相关
#define CCIS_CLIENT_DECRYPT_FAILED		0x0060		//客户端数据解密失败
#define CCIS_CLIENT_ENCRYPT_FAILED		0x0061		//客户端信息加密失败
#define CCIS_CLIENT_CHECK_HASH_INVALID		0x0061		//客户端hash验证不通过
#define CCIS_CLIENT_CHECK_HASH_VALID		0x0062		//客户端hash验证通过
#define CCIS_CLIENT_RECORD_HARDSN_FAILED	0x0063		//客户端硬件SN记录失败
#define CCIS_CLIENT_RECORD_HARDSN_SUCCESS	0x0064		//客户端硬件SN记录成功
#define CCIS_CLIENT_MODIFY_HARDSN_FAILED	0x0065		//客户端硬件SN变更失败
#define CCIS_CLIENT_MODIFY_HARDSN_SUCCESS	0x0066		//客户端硬件SN变更成功
#define CCIS_CLIENT_NO_UKEY_PIN			0x0067		//获取UKEY PIN码失败
#define CCIS_CLIENT_UKEY_PIN_MATCHED		0x0068		//获取UKEY PIN码成功
#define CCIS_CLIENT_CHECK_UKEY_CERT_INVALID	0x0069		//客户端Ukey证书验证不通过
#define CCIS_CLIENT_CHECK_UKEY_CERT_VALID	0x006A		//客户端Ukey证书验证通过
#define CCIS_CLIENT_RECORD_SYSTEM_INFO_FAILED	0x006B		//客户端系统信息记录失败
#define CCIS_CLIENT_RECORD_SYSTEM_INFO_SUCCESS	0x006C		//客户端系统信息记录成功
#define CCIS_CLIENT_MODIFY_SYSTEM_INFO_FAILED	0x006D		//客户端系统信息变更失败
#define CCIS_CLIENT_MODIFY_SYSTEM_INFO_SUCCESS	0x006E		//客户端系统信息变更成功
#define	CCIS_CLIENT_DUPLICATE_LOGIN		0x006F		//客户端重复登陆

#define CCIS_CLIENT_PBC_PASSWORD_ERROR		0x0070		//客户端征信密码错误
#define CCIS_CLIENT_PBC_NO_SUCH_USER		0x0071		//无此征信账号
#define CCIS_CLIENT_PBC_INVALIAD_PBCID		0x0072		//征信机构号无效
#define CCIS_CLIENT_PBC_LOGIN_FAILED		0x0073		//征信中心登陆失败（原因未知）
#define CCIS_CLIENT_PBC_LOGIN_SUCCESS		0x0074		//客户端登陆征信中心成功
#define CCIS_CLIENT_UKEY_BIND_FAILED		0x0075		//用户Ukey与TPM绑定失败
#define CCIS_CLIENT_UKEY_ALREADY_USED		0x0076		//用户Ukey已被绑定
#define CCIS_CLIENT_UKEY_NOT_MATCHED		0x0077		//当前使用的Ukey与TPM不匹配
#define	CCIS_CLIENT_PBC_PWD_CHANGE		0x0078		//征信密码应该更新
#define	CCIS_CLIENT_PWD_CHANGE_SUCCESS		0x0079		//征信密码修改成功
#define	CCIS_CLIENT_PWD_CHANGE_FAILED		0x007A		//征信密码修改失败
#define CCIS_CLIENT_PBC_QUERY_SUCCESS		0x007B		//征信帐号申请成功
#define CCIS_CLIENT_PBC_DOUBLE_QUERY		0x007C		//征信帐号申请操作重复
#define CCIS_CLIENT_PBC_ALREADY_EXIST		0x007D		//征信帐号已存在，不允许重新申请
#define CCIS_CLIENT_PBC_QUERY_FAILED		0x007E		//征信帐号申请出错
#define CCIS_CLIENT_PBC_ISSUED_SUCCESS		0x007F		//征信帐号颁发成功

#define	CCIS_CLIENT_PBC_LOCKED			0x0080		//征信账号已被锁定
#define	CCIS_CLIENT_PBC_CANNOT_EMPTY		0x0081		//征信账号密码不可为空
#define	CCIS_CLIENT_PBC_REMOTE_SYSTEM_ERROR	0x0082		//征信中心系统异常
#define	CCIS_CLIENT_PBC_LOCAL_SYSTEM_ERROR	0x0083		//服务端系统异常
#define	CCIS_CLIENT_CERT_ERROR			0x0084		//客户端证书错误

//移动支付相关
#define	CCIS_OLCHG_NOTSUPPORT			0x0090		//不支持在线支付
#define	CCIS_OLCHG_CONNECT_FAILED		0x0091		//收费服务器连接失败
#define	CCIS_OLCHG_TIMEOUT			0x0092		//收费服务器响应超时（包括获取二维码和收费结果）
#define	CCIS_OLCHG_SUCCESS			0x0093		//在线收费成功
#define	CCIS_OLCHG_FAILED			0x0094		//在线收费失败
#define	CCIS_OLCHG_QRCODE			0x0095		//发送二维码
#define	CCIS_OLCHG_REFUNDS_SUCCESS		0x0096		//退款请求提交成功
#define	CCIS_OLCHG_REFUNDS_FAILED		0x0097		//退款请求提交失败
#define	CCIS_OLCHG_CHARGE_TIMEOUT		0x0098		//交易超时
#define	CCIS_OLCHG_CHARGE_CLOSE			0x0099		//交易关闭
#define	CCIS_OLCHG_CHARGE_WAITING		0x009A		//等待支付

#define	CCIS_UR_NO_SUCH_UKEY			0x0101		//当前申请注册的Ukey未在数据库中登记
#define	CCIS_UR_SEND_CERT			0x0102		//正在发送Ukey证书文件
#define	CCIS_UR_SENDCERT_ERROR			0x0103		//证书发送失败
#define CCIS_UR_CERT_NOT_FOUND			0x0104		//证书文件丢失
#define CCIS_UR_REGISTER_SUCCESS		0x0105		//客户端保存Ukey证书与PIN码成功
#define CCIS_UR_REGISTER_FAILED			0x0106		//客户端保存Ukey证书与PIN码失败
#define CCIS_UR_ALREADY_REGISTED		0x0107		//客户端Ukey已经注册过

#define CCIS_TPM_NO_SUCH_DEV			0x0111		//当前申请注册的TPM或设备未登记
#define CCIS_TPM_SEND_CERT			0x0112		//正在发送TPM证书文件
#define CCIS_TPM_SENDCERT_ERROR			0x0113		//证书文件发送失败
#define CCIS_TPM_CERT_NOT_FOUND			0x0114		//证书文件丢失
#define CCIS_TPM_REGISTER_SUCCESS		0x0115		//客户端保存TPM证书成功
#define CCIS_TPM_REGISTER_FAILED		0x0116		//客户端保存TPM证书失败
#define CCIS_TPM_ALREADY_REGISTED		0x0117		//客户端TPM已经注册过

#define CCIS_SCHK_PROCESS_INIT			0x0200		//客户端自检入库流程启动
#define	CCIS_SCHK_DEVSN_NOT_REGISTERED		0x0201		//客户端设备序列号不在自检表中
#define CCIS_SCHK_DB_ERROR			0x0202		//客户端自检时系统数据库错误
#define CCIS_SCHK_ENCRYPT_FAILED		0x0203		//数据加密失败

/********************MSG Status***************/
#define CCIS_PACKAGE_FIRST			0x0001
#define CCIS_PACKAGE_UNFINISHED			0x0002
#define CCIS_PACKAGE_FINISHED			0x0003


/********************Falres*******************/
#define	ERRCODE_MASK				(0x000F)	//错误掩码位，用于提取最后的错误码
#define	PROCCODE_MASK				(0x00F0)	//流程掩码位，用于提取业务流程
#define	TYPECODE_MASK				(0xF000)	//错误类型掩码位，用于提取错误类型

#define	RESET_ERRCODE(x)			(x &= ~ERRCODE_MASK)	//重置错误位
#define	RESET_PROCCODE(x)			(x &= ~PROCCODE_MASK)	//重置流程位
#define	RESET_TYPECODE(x)			(x &= ~TYPECODE_MASK)	//重置类型位

#define	SET_ERRCODE(x , code)			\
		do{				\
			RESET_ERRCODE(x);	\
			x	|= code;	\
		}while(0)

#define	SET_PROCCODE(x , code)			\
		do{				\
			RESET_PROCCODE(x);	\
			x	|= code;	\
		}while(0)

#define	SET_TYPECODE(x , code)			\
		do{				\
			RESET_TYPECODE(x);	\
			x	|= code;	\
		}while(0)

#define USER_CHOICE                     	0x1000  //用户取消
#define BASE_ERROR                      	0x2000  //基本错误
#define SYSTEM_ERROR_LOCAL              	0x3000  //系统错误,本地原因
#define SYSTEM_ERROR_NETWORK            	0x4000  //系统错误，网络原因
#define SELF_CHECK_SYNC                 	0x5000  //流程未正常结束，触发系统自检
#define OTHER_ERROR                     	0x6000  //其他错误

#define CCIS_PROC_IDCARD_CHECK          	0x0010  //正在检测身份证信息
#define CCIS_PROC_FACE_MATCH            	0x0020  //正在进行人脸比对
#define	CCIS_PROC_CHARGE			0x0030	//收费流程
#define CCIS_PROC_REPORT_WORKING        	0x0040  //正在下载&发送征信报告
#define	CCIS_PROC_OLCHG				0x0050	//移动支付
#define CCIS_PROC_ALL_DONE              	0x0100  //流程全部结束,并且报告打印成功

#define CCIS_ERR_UNKNOW_ERROR           	(0x000F | OTHER_ERROR)          //未知错误
#define	CCIS_ERR_SELF_CHECK			(0x000E | SELF_CHECK_SYNC)	//流程未结束，系统自检更新

//身份证部分
#define CCIS_ERR_ID_INVALID_INFO        	(0x0001 | BASE_ERROR)           //无效的密文，解密失败
#define CCIS_ERR_ID_INCOMPLITE_INFO     	(0x0002 | BASE_ERROR)           //身份证信息不完整
#define CCIS_ERR_ID_SQL_ERROR           	(0x0003 | SYSTEM_ERROR_LOCAL)   //数据库错误
#define CCIS_ERR_ID_NO_POLICE_PHOTO     	(0x0004 | BASE_ERROR)           //无公安部照片
#define CCIS_ERR_ID_NAME_NOT_MATCH      	(0x0005 | BASE_ERROR)           //身份证号和姓名不匹配
#define CCIS_ERR_ID_INVALID_IDNUM       	(0x0006 | BASE_ERROR)           //无效身份证号
#define CCIS_ERR_ID_CHECK_FAILED        	(0x0007 | BASE_ERROR)           //身份证验证不通过
#define CCIS_ERR_ID_POLICE_LINK_ERROR  		(0x0008 | SYSTEM_ERROR_NETWORK) //公安部连接失败
#define CCIS_ERR_ID_DOWNLOAD_PHOTO_ERR  	(0x0009 | SYSTEM_ERROR_NETWORK) //无法下载公安部照片
#define CCIS_ERR_ID_IDPHOTO_RECV_FAILED 	(0x000A | SYSTEM_ERROR_NETWORK) //身份证照接收失败
#define CCIS_ERR_ID_GET_PATH_FAILED     	(0x000B | SYSTEM_ERROR_LOCAL)   //无法获取身份证照存储路径
#define	CCIS_ERR_ID_PASSWD_ERROR		(0x000C | BASE_ERROR)		//征信账号或密码错误

//人脸比对
#define CCIS_ERR_FM_GET_PATH_FAILED     	(0x0001 | SYSTEM_ERROR_LOCAL)   //无法获取现场照片存储路径
#define CCIS_ERR_FM_VIS_PHOTO_RECV_ERR  	(0x0002 | SYSTEM_ERROR_NETWORK) //现场照片接收失败
#define CCIS_ERR_FM_NO_PHOTO_EXIST      	(0x0003 | SYSTEM_ERROR_LOCAL)   //没有找到身份证照或公安部照
#define CCIS_ERR_FM_PREPROC_FAILED      	(0x0004 | SYSTEM_ERROR_LOCAL)   //照片预处理失败
#define CCIS_ERR_FM_GET_FEATURE_FAILED  	(0x0005 | SYSTEM_ERROR_LOCAL)   //无法提取特征值
#define CCIS_ERR_FM_COMPARE_NOT_PASS    	(0x0006 | BASE_ERROR)           //比对不通过

//收费流程
#define	CCIS_ERR_CHG_RETREATED			(0x0001 | BASE_ERROR)		//已退费
#define	CCIS_ERR_CHG_GETINFO_FAILED		(0x0002 | SYSTEM_ERROR_LOCAL)	//获取收费情况失败
#define	CCIS_ERR_CHG_RETREAT_FAILED		(0x0003 | SYSTEM_ERROR_LOCAL)	//退费失败

//收费报告相关
#define CCIS_ERR_REP_UNPRINT_NO_REPORT  	(0x0001 | SYSTEM_ERROR_LOCAL)   //有未打印记录但没有报告文件
#define CCIS_ERR_REP_FREE_SYSTEM_ERROR  	(0x0002 | OTHER_ERROR)          //查询系统错误
#define CCIS_ERR_REP_USER_PWD_ERROR     	(0x0003 | OTHER_ERROR)          //用户名或密码错误
#define CCIS_ERR_REP_QUERY_WRONG        	(0x0004 | OTHER_ERROR)          //征信系统查询错误
#define CCIS_ERR_REP_OTHER_ERROR        	(0x0005 | OTHER_ERROR)          //查询系统其他错误
#define CCIS_ERR_REP_REPORT_SEND_FAILED 	(0x0006 | SYSTEM_ERROR_NETWORK) //报告发送失败
#define	CCIS_ERR_REP_INDEXNO_ERROR		(0x0007 | OTHER_ERROR)		//征信报告凭证号错误
#define	CCIS_ERR_REP_PRINT_TIMEOUT		(0x0008 | BASE_ERROR)		//报告打印超时
#define CCIS_ERR_REP_PRINT_FAILED       	(0x0009 | BASE_ERROR)           //报告打印失败
#define CCIS_ERR_REP_GET_TIME_FAILED    	(0x000A | SYSTEM_ERROR_LOCAL)   //获取报告打印时间失败
#define CCIS_ERR_REP_LINK_FAILED		(0x000B | SYSTEM_ERROR_NETWORK)	//征信系统连接错误

#define CCIS_ERR_GLOBAL_PROCESS_INVALID		(0x000D | OTHER_ERROR)		//流程非法

/*******************************客户端登陆认证流程**********************************/
//客户端登陆相关
#define CCIS_CLIENT_HASH_CHECKED		0x0001				//客户端有效性验证已通过
#define CCIS_CLIENT_UKEY_CERT_VERIFIED		0x0002				//客户端UKEY证书验证已通过
#define CCIS_CLIENT_VERIFIED			0x0010				//客户端已被允许使用

#endif
