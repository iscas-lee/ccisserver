#include "resource.h"
#include "unistd.h"
#include "stdlib.h"
#include "stdio.h"
#include "sys/stat.h"
#include "../configure/configure.h"
#include "../camera/FaceMatcher.h"
#include "../log/ccis_log.h"
#include "../security/security.h"

int	Init_Resource();
void	Recycle_Resource();
int	Init_Configure();
int	Reload_Configure();
void	Display_Configure();
int	Init_FaceMatcher();
int	Init_Dir();
int	Check_File_Exist();

int Init_Resource()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;

	retv	= Init_Configure();
	if (unlikely(retv != 0))
		goto clean_up;
	Display_Configure();

	retv	= Init_FaceMatcher();
	if (unlikely(retv != 0))
		goto clean_up;

	retv	= Init_Dir();
	if (unlikely(retv != 0))
		goto clean_up;

/*	retv	= Check_File_Exist();
	if (unlikely(retv != 0))
		goto clean_up;*/

clean_up:
	return retv;
}

void Recycle_Resource()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	FM_DestroyIns(&fm_instance_2);
	int nRet = FD_DestroyIns(&fm_instance_1);
	if ((nRet != FME_OK) || (fm_instance_1 != 0))
	{
		ccis_log_warning("人脸识别库实例句柄回收失败！错误码：%d" , nRet);
	}
}

int Init_Configure()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	keyFile	= g_key_file_new();
	FILE* verfp	= fopen("/etc/CCIS/version" , "r");
	if (!g_file_test(CONF_FILE_PATH , G_FILE_TEST_EXISTS))
	{
		printf("配置文件不存在！\n");
		ccis_log_emerg("配置文件丢失！");
		retv	= 1;
		goto clean_up;
	}

	char*	tmp_username;
	char* 	tmp_passwd;

	if (!verfp)
	{
		retv	= 1;
		ccis_log_emerg("服务器版本未知，无法启动！");
		goto clean_up;
	}
	version		= calloc(CCIS_SMALLSIZE + 1 , sizeof(char));
	if (!version)
	{
		retv	= 1;
		ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	if (fread(version , sizeof(char) , CCIS_SMALLSIZE , verfp) <= 0)
	{
		retv	= 1;
		ccis_log_emerg("服务器版本未知，无法启动！");
		goto clean_up;
	}
	char* tmppos	= version;
	while (*tmppos != '\0')
	{
		if (*tmppos == '\r' || *tmppos == '\n')
		{
			*tmppos = '\0';
			break;
		}
		tmppos ++;
	}

	process_limits		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SYSTEM" , "PROCESS");
	if (process_limits <= 0)
		process_limits	= 1;

	max_socket_connection	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SYSTEM" , "MAX_SOCKET_CONN");
	if (max_socket_connection < 0)
		max_socket_connection	= 20;

	rlimit_number		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SYSTEM" , "PRO_LIMITS");
	if (rlimit_number < 0)
		rlimit_number	= 100000;
		
	data_path		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "SYSTEM" , "DATA_PATH");
	if (!data_path || strlen(data_path) > 80)
	{
		ccis_log_emerg("配置文件加载失败：DATA_PATH项参数不正确或路径超长！");
		retv	= 1;
		goto clean_up;
	}
	struct stat dirstat;
	while (stat(data_path , &dirstat) < 0)
	{
		if (errno == 2)
		{
			char command[CCIS_PATHLEN];
			sprintf(command , "mkdir -p %s" , data_path);
			if (system(command))
			{
				ccis_log_emerg("%s 存储路径不存在，且自动创建失败！失败原因：%s" , data_path , strerror(errno));
				retv	= 1;
				goto clean_up;
			}
			ccis_log_notice("%s 存储路径不存在，已自动创建" , data_path);
		}
		else
		{
			ccis_log_emerg("存储路径%s权限获取失败！失败原因：%s" , data_path , strerror(errno));
			retv	= 1;
			goto clean_up;
		}
	}
	if (!S_ISDIR(dirstat.st_mode))
	{
		ccis_log_emerg("配置文件加载失败：%s 不是一个目录或者该路径不存在！" , data_path);
		retv	= 1;
		goto clean_up;
	}

	auto_restart		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SYSTEM" , "AUTO_RESTART");

	link_timeout_s		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SYSTEM" , "LINK_TIMEOUT_S");
	if (link_timeout_s < 1)
	{
		ccis_log_emerg("配置文件加载失败：超时时间设置错误！");
		retv	= 1;
		goto clean_up;
	}

	version_lowerlimit	= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "CLIENT" , "VER_LOWERLIMIT");
	if (!version_lowerlimit)
	{
		ccis_log_emerg("客户端版本下限设置错误！");
		retv	= 1;
		goto clean_up;
	}

	version_upperlimit	= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "CLIENT" , "VER_UPPERLIMIT");
	if (!version_upperlimit)
	{
		ccis_log_emerg("客户端版本上限设置错误！");
		retv	= 1;
		goto clean_up;
	}

	serverip		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "NETWORK" , "SERVERIP");
	if (!serverip)
	{
		ccis_log_emerg("配置文件加载失败：SERVERIP项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	serverport		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "NETWORK" , "SERVERPORT");
	if (serverport <=0 || serverport > 65535)
		serverport	= 80;

	db_ip			= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "MYSQL_IP");
	if (!db_ip)
	{
		ccis_log_emerg("配置文件加载失败：MYSQL_IP项参数不正确！");
		retv	= 1;
		goto clean_up;
	}
	
	db_port			= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "MYSQL_PORT");
	if (db_port <= 0 || db_port > 65535)
	{
		db_port	= 3012;
	}

	tmp_username		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "MYSQL_USER");
	if (!tmp_username)
	{
		ccis_log_emerg("配置文件加载失败：MYSQL_USER项参数不正确！");
		retv	= 1;
		goto clean_up;
	}
	db_username	= malloc(128);
	if (!db_username)
	{
		ccis_log_emerg("配置文件加载失败：内存分配失败！");
		retv	= 1;
		goto clean_up;
	}
	if (Base64_Decode(tmp_username, strlen(tmp_username), db_username , 128))
	{
		ccis_log_emerg("配置文件加载失败：数据库用户名解密失败！");
		retv	= 1;
		goto clean_up;
	}

	tmp_passwd		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "MYSQL_PASSWD");
	if (!tmp_passwd)
	{
		ccis_log_emerg("配置文件加载失败：MYSQL_PASSWD项参数不正确！");
		retv	= 1;
		goto clean_up;
	}
	db_passwd	= malloc(128);
	if (!db_passwd)
	{
		ccis_log_emerg("配置文件加载失败：内存分配失败！");
		retv	= 1;
		goto clean_up;
	}
	if (Base64_Decode(tmp_passwd , strlen(tmp_passwd) , db_passwd , 128))
	{
		ccis_log_emerg("配置文件加载失败：数据库密码解密失败！");
		retv	= 1;
		goto clean_up;
	}

	db_tablename		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "MYSQL_DATABASE");
	if (!db_tablename)
	{
		ccis_log_emerg("配置文件加载失败：MYSQL_DATABASE项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	ssl_connect		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "SSL_CONNECT");
	if (ssl_connect)
		ssl_connect	= 1;
	//store_files		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "STORE_FILES");
	store_files		= 1;	//强制入库

	cacert			= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "CACERT");
	if (!cacert)
	{
		ccis_log_emerg("配置文件加载失败：CACERT项参数不正确！");
		retv	= 1;
		goto clean_up;
	}


	server_private_key	= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "SERVER_PRIVATE_KEY");
	if (!server_private_key)
	{
		ccis_log_emerg("配置文件加载失败：SERVER_PRIVATE_KEY项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	server_cert		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "SERVER_CERT");
	if (!server_cert)
	{
		ccis_log_emerg("配置文件加载失败：SERVER_CERT项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	client_private_key	= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "CLIENT_PRIVATE_KEY");

	client_cert		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "CLIENT_CERT");

	ca_enable		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "CA_ENABLE");
	if (ca_enable)
		ca_enable	= 1;

	cahost			= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "CAHOST");
	if (ca_enable && !cahost)
	{
		ccis_log_emerg("配置文件加载失败：CAHOST项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	duplicate_login_action	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "DUPLICATE_LOGIN_ACTION");
	if (duplicate_login_action < -1 || duplicate_login_action > 1)
	{
		ccis_log_emerg("配置文件加载失败：DUPLICATE_LOGIN_ACTION项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	zx_normal_url		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "ZX_NORMAL_URL");
	zx_agent_url		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "ZX_AGENT_URL");
	if (!zx_normal_url && !zx_agent_url)
	{
		ccis_log_emerg("配置文件加载失败：征信地址不可为空！");
		retv	= 1;
		goto clean_up;
	}

	zx_agent_sign		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "ZX_AGENT_SIGN");
	if (!zx_agent_sign)
	{
		ccis_log_emerg("配置文件加载失败：ZX_AGENT_SIGN项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	auto_upload		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "AUTO_UPLOAD");
	if (auto_upload)
		auto_upload	= 1;

	pic_upload_url		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "PIC_UPLOAD_URL");
	if (auto_upload && !pic_upload_url)
	{
		ccis_log_emerg("配置文件加载失败：PIC_UPLOAD_URL项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	log_upload_url		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "LOG_UPLOAD_URL");
	if (auto_upload && !log_upload_url)
	{
		ccis_log_emerg("配置文件加载失败：LOG_UPLOAD_URL项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	report_limit		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "REPORT_LIMIT");
	if (report_limit > 3 || report_limit < 1)
	{
		ccis_log_emerg("配置文件加载失败：REPORT_LIMIT项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	constrain_verify	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "CONSTRAIN_VERIFY");
	if (constrain_verify >> 1)
	{
		ccis_log_emerg("配置文件加载失败：CONSTRAIN_VERIFY项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	report_reserved_days	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "REPORT_RESERVED_DAYS");
	if (report_reserved_days < 0)
	{
		ccis_log_emerg("配置文件加载失败：REPORT_RESERVED_DAYS项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	charge_type		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "CHARGE_TYPE");
	if (charge_type & ~3)
	{
		ccis_log_emerg("配置文件加载失败：CHARGE_TYPE项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	if (charge_type & 2)
	{
		zoneid		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "ZONEID");
		if (!zoneid)
		{
			ccis_log_emerg("配置文件加载失败：ZONEID项参数不正确！");
			retv	= 1;
			goto clean_up;
		}

		olchg_server		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "OLCHG_SERVER");
		if (!olchg_server)
		{
			ccis_log_emerg("配置文件加载失败：OLCHG_SERVER项参数不正确！");
			retv	= 1;
			goto clean_up;
		}

		olchg_port		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "OLCHG_PORT");
		if (olchg_port < 0)
		{
			ccis_log_emerg("配置文件加载失败：OLCHG_PORT项参数不正确！");
			retv	= 1;
			goto clean_up;
		}

		olchg_timeout		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "OLCHG_TIMEOUT");
		if (olchg_timeout < 1)
		{
			ccis_log_emerg("配置文件加载失败：OLCHG_TIMEOUT项参数不正确！");
			retv	= 1;
			goto clean_up;
		}

		olchg_polling_interval	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "OLCHG_POLLING_INTERVAL");
		if (olchg_polling_interval < 1)
		{
			ccis_log_emerg("配置文件加载失败：OLCHG_POLLING_INTERVAL项参数值过低！");
			retv	= 1;
			goto clean_up;
		}
	}

	cross_dev		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "CROSS_DEV");
	if (cross_dev > 1 || cross_dev < 0)
	{
		ccis_log_emerg("配置文件加载失败：CROSS_DEV项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	cross_website		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "CROSS_WEBSITE");
	if (cross_website > 1 || cross_website < 0)
	{
		ccis_log_emerg("配置文件加载失败：CROSS_WEBSITE项参数不正确！");
		retv	= 1;
		goto clean_up;
	}
	if (cross_website == 1 && cross_dev == 0)
	{
		ccis_log_warning("自动矫正：由于配置项CROSS_WEBSITE项参数与CROSS_DEV有冲突，CROSS_WEBSITE配置项已被自动矫正为0！");
		cross_website	= 0;
	}

	self_check_time		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "ALARM" , "HOUR");
	if (self_check_time > 24 || self_check_time <= 0)
		self_check_time	= 24;

	auto_timesync		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "ALARM" , "AUTO_TIMESYNC");
	if (auto_timesync)
		auto_timesync	= 1;

	timesync_server		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "ALARM" , "TIMESYNC_SERVER");
	if (auto_timesync && !timesync_server)
	{
		ccis_log_emerg("配置文件加载失败：TIMESYNC_SERVER项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	flow_control_conf_file	= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "FLOW" , "CONFPATH");
	if (!flow_control_conf_file)
	{
		ccis_log_emerg("配置文件加载失败：CONFPATH项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	interval_s		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "FLOW" , "INTERVAL_S");
	if (interval_s < 0)
		interval_s	= 0;

	log_level		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "LOG" , "LEVEL");
	if (log_level < 0)
		log_level	= 0;
	else if (log_level > 7)
		log_level	= 7;

clean_up:
	if (verfp)
		fclose(verfp);
/*
	if (keyFile)
	{
		g_key_file_free(keyFile);
		keyFile	= NULL;
	}
*/
	if (tmp_username)
		free(tmp_username);
	if (tmp_passwd)
		free(tmp_passwd);
	return retv;
}

int Reload_Configure()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	if (!keyFile)
	{
		keyFile	= g_key_file_new();
		if (!keyFile)
		{
			ccis_log_err("配置文件句柄创建失败！");
			retv	= 1;
			goto clean_up;
		}
	}

	if (!g_file_test(CONF_FILE_PATH , G_FILE_TEST_EXISTS))
	{
		printf("配置文件不存在！\n");
		ccis_log_emerg("配置文件丢失！");
		retv	= 1;
		goto clean_up;
	}

	data_path		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "SYSTEM" , "DATA_PATH");
	if (!data_path || strlen(data_path) > 80)
	{
		ccis_log_emerg("配置文件加载失败：DATA_PATH项参数不正确或路径超长！");
		retv	= 1;
		goto clean_up;
	}
	struct stat dirstat;
	while (stat(data_path , &dirstat) < 0)
	{
		if (errno == 2)
		{
			char command[CCIS_PATHLEN];
			sprintf(command , "mkdir -p %s" , data_path);
			if (system(command))
			{
				ccis_log_emerg("%s 存储路径不存在，且自动创建失败！失败原因：%s" , data_path , strerror(errno));
				retv	= 1;
				goto clean_up;
			}
			ccis_log_notice("%s 存储路径不存在，已自动创建" , data_path);
		}
		else
		{
			ccis_log_emerg("存储路径%s权限获取失败！失败原因：%s" , data_path , strerror(errno));
			retv	= 1;
			goto clean_up;
		}
	}
	if (!S_ISDIR(dirstat.st_mode))
	{
		ccis_log_emerg("配置文件加载失败：%s 不是一个目录或者该路径不存在！" , data_path);
		retv	= 1;
		goto clean_up;
	}

	auto_restart		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SYSTEM" , "AUTO_RESTART");

	link_timeout_s		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SYSTEM" , "LINK_TIMEOUT_S");
	if (link_timeout_s < 1)
	{
		ccis_log_emerg("配置文件加载失败：超时时间设置错误！");
		retv	= 1;
		goto clean_up;
	}

	ca_enable		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "CA_ENABLE");
	if (ca_enable)
		ca_enable	= 1;

	duplicate_login_action	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "SECURITY" , "DUPLICATE_LOGIN_ACTION");
	if (duplicate_login_action < -1 || duplicate_login_action > 1)
	{
		ccis_log_emerg("配置文件加载失败：DUPLICATE_LOGIN_ACTION项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	auto_upload		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "AUTO_UPLOAD");
	if (auto_upload)
		auto_upload	= 1;

	pic_upload_url		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "PIC_UPLOAD_URL");
	if (auto_upload && !pic_upload_url)
	{
		ccis_log_emerg("配置文件加载失败：PIC_UPLOAD_URL项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	log_upload_url		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "LOG_UPLOAD_URL");
	if (auto_upload && !log_upload_url)
	{
		ccis_log_emerg("配置文件加载失败：LOG_UPLOAD_URL项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	report_limit		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "REPORT_LIMIT");
	if (report_limit > 3 || report_limit < 1)
	{
		ccis_log_emerg("配置文件加载失败：REPORT_LIMIT项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	constrain_verify	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "CONSTRAIN_VERIFY");
	if (constrain_verify >> 1)
	{
		ccis_log_emerg("配置文件加载失败：CONSTRAIN_VERIFY项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	report_reserved_days	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "REPORT_RESERVED_DAYS");
	if (report_reserved_days < 0)
	{
		ccis_log_emerg("配置文件加载失败：REPORT_RESERVED_DAYS项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	charge_type		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "CHARGE_TYPE");
	if (charge_type & ~3)
	{
		ccis_log_emerg("配置文件加载失败：CHARGE_TYPE项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	if (charge_type & 2)
	{
		olchg_server		= get_string_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "OLCHG_SERVER");
		if (!olchg_server)
		{
			ccis_log_emerg("配置文件加载失败：OLCHG_SERVER项参数不正确！");
			retv	= 1;
			goto clean_up;
		}
	
		olchg_port		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "OLCHG_PORT");
		if (olchg_port < 0)
		{
			ccis_log_emerg("配置文件加载失败：OLCHG_PORT项参数不正确！");
			retv	= 1;
			goto clean_up;
		}

		olchg_timeout		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "OLCHG_TIMEOUT");
		if (olchg_timeout < 1)
		{
			ccis_log_emerg("配置文件加载失败：OLCHG_TIMEOUT项参数不正确！");
			retv	= 1;
			goto clean_up;
		}

		olchg_polling_interval	= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "OLCHG_POLLING_INTERVAL");
		if (olchg_polling_interval < 1)
		{
			ccis_log_emerg("配置文件加载失败：OLCHG_POLLING_INTERVAL项参数值过低！");
			retv	= 1;
			goto clean_up;
		}
	}

	cross_dev		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "CROSS_DEV");
	if (cross_dev > 1 || cross_dev < 0)
	{
		ccis_log_emerg("配置文件重载失败：CROSS_DEV项参数不正确！");
		retv	= 1;
		goto clean_up;
	}

	cross_website		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "PBC" , "CROSS_WEBSITE");
	if (cross_website > 1 || cross_website < 0)
	{
		ccis_log_emerg("配置文件重载失败：CROSS_WEBSITE项参数不正确！");
		retv	= 1;
		goto clean_up;
	}
	if (cross_website == 1 && cross_dev == 0)
	{
		ccis_log_warning("自动矫正：由于配置项CROSS_WEBSITE项参数与CROSS_DEV有冲突，CROSS_WEBSITE配置项已被自动矫正为0！");
		cross_website	= 0;
	}

	log_level		= get_int_accord_group_key(keyFile , CONF_FILE_PATH , "LOG" , "LEVEL");
	if (log_level < 0)
		log_level	= 0;
	else if (log_level > 7)
		log_level	= 7;

clean_up:
/*
	if (keyFile)
	{
		g_key_file_free(keyFile);
		keyFile	= NULL;
	}
*/
	return retv;
}

int Init_FaceMatcher()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	char *face_matcher_model1	= "/root/CCISServer/res/FaceMatcherSDK2.8/models/fms-1.0/5";
	char *face_matcher_model2	= "/root/CCISServer/res/FaceMatcherSDK2.8/models/fms-1.0";
	char *face_matcher_log		= "/root/CCISServer/log/face_matcher.log";

	int retv			= 0;
	retv	= FD_CreateIns(&fm_instance_1 , face_matcher_model1 , face_matcher_log);
	if ((retv != FME_OK) || (fm_instance_1 <= 0))
	{
		ccis_log_emerg("人脸识别库句柄创建失败，返回值%d , fm_instance_1 = %lld" , retv , fm_instance_1);
		retv	= -1;
		goto clean_up;
	}

	retv	= FM_CreateIns(&fm_instance_2 , face_matcher_model2 , face_matcher_log);
	if (retv != FME_OK)
	{
		ccis_log_emerg("人脸识别库句柄创建失败，返回值%d , fm_instance_2 = %lld" , retv , fm_instance_2);
		retv	= -1;
		goto clean_up;
	}
clean_up:
	return retv;
}

int Init_Dir()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	DIR* pdir	= NULL;
	int retv	= 0;
	if (unlikely((pdir = opendir("/tmp/css")) == NULL))
	{
		if (unlikely(mkdir("/tmp/css" , 0755) != 0))
		{
			retv	= -1;
			goto clean_up;
		}
	}
	else
	{
		closedir(pdir);
		pdir	= NULL;
	}

	if (unlikely((pdir = opendir("/tmp/images")) == NULL))
	{
		if (unlikely(mkdir("/tmp/images" , 0755) != 0))
		{
			retv	= -1;
			goto clean_up;
		}
	}
	else
	{
		closedir(pdir);
		pdir	= NULL;
	}

	if (unlikely((pdir = opendir("/var/log/CCIS")) == NULL))
	{
		if (unlikely(mkdir("/var/log/CCIS" , 0755) != 0))
		{
			retv	= -1;
			goto clean_up;
		}
	}
	else
	{
		closedir(pdir);
		pdir	= NULL;
	}

clean_up:
	if (pdir)
	{
		closedir(pdir);
		pdir	= NULL;
	}
	return retv;
}

int Check_File_Exist()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	char* command	= NULL;
	int attr	= F_OK | R_OK;

	if (access("/tmp/css/grmxprint.css" , attr))
	{
		if (!access("/usr/share/ccis-server/css/grmxprint.css" , attr))
		{
			if (system("cp /usr/share/ccis-server/css/grmxprint.css /tmp/css/grmxprint.css"))
			{
				printf("css not exist!\n");
				retv	= 1;
				goto clean_up;
			}
		}
		else
		{
			printf("css not exist!\n");
			retv	= 1;
			goto clean_up;
		}
	}

	if (access("/tmp/images/pbccrc_watermark.gif" , attr))
	{
		if (!access("/usr/share/ccis-server/images/pbccrc_watermark.gif" , attr))
		{
			if (system("cp /usr/share/ccis-server/images/pbccrc_watermark.gif /tmp/images/"))
			{
				printf("watermark file not exist\n");
				retv	= 1;
				goto clean_up;
			}
		}
		else
		{
			printf("watermark file not exist\n");
			retv	= 1;
			goto clean_up;
		}
	}

	if (access("/tmp/images/qlogo.gif" , attr))
	{
		if (!access("/usr/share/ccis-server/images/qlogo.gif" , attr))
		{
			if (system("cp /usr/share/ccis-server/images/qlogo.gif /tmp/images/"))
			{
				printf("logo file not exist\n");
				retv	= 1;
				goto clean_up;
			}
		}
		else
		{
			printf("logo file not exist\n");
			retv	= 1;
			goto clean_up;
			
		}
	}

	if (access("/tmp/images/yz.gif" , attr))
	{
		if (!access("/usr/share/ccis-server/images/yz.gif" , attr))
		{
			if (system("cp /usr/share/ccis-server/images/yz.gif /tmp/images/"))
			{
				printf("yz file not exist\n");
				retv	= 1;
				goto clean_up;
			}
		}
		else
		{
			printf("yz file not exist\n");
			retv	= 1;
			goto clean_up;
		}
	}

clean_up:
	if (command)
		free(command);
	return retv;
}

void Display_Configure()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	ccis_log_info("-----------------系统设置--------------------");
	ccis_log_info("服务器版本号：%s" , version);
	ccis_log_info("业务进程数量：%d" , process_limits);
	ccis_log_info("TCP Backlog限制：%d" , max_socket_connection);
	ccis_log_info("文件句柄数限制：%d" , rlimit_number);
	ccis_log_info("本地文件存储路径：%s" , data_path);
	ccis_log_info("服务监听端口：%d" , serverport);
	ccis_log_info("自检时重启进程：%s" , auto_restart ? "是":"否");
	ccis_log_info("外部连接超时时间：%d秒" , link_timeout_s);
	ccis_log_info("-----------------客户端设置------------------");
	ccis_log_info("可兼容最低客户端版本：%s" , version_lowerlimit);
	ccis_log_info("可兼容最高客户端版本：%s" , version_upperlimit);
	ccis_log_info("-----------------数据库设置------------------");
	ccis_log_info("数据库IP：%s" , db_ip);
	ccis_log_info("数据库端口：%d" , db_port);
	ccis_log_info("启用安全链接：%s" , ssl_connect?"是":"否");
	ccis_log_info("启用文件内容入库：%s" , store_files?"是":"否");
	ccis_log_info("-----------------CA中心设置------------------");
	ccis_log_info("根证书路径：%s" , cacert);
	ccis_log_info("服务器私钥路径：%s" , server_private_key);
	ccis_log_info("服务器证书路径：%s" , server_cert);
	ccis_log_info("启用CA认证：%s" , ca_enable?"是":"否");
	if (ca_enable)
		ccis_log_info("CA服务器地址：%s" , cahost);
	ccis_log_info("设备重复登陆时动作：%s" , duplicate_login_action > 0 ? "强制登陆" : (duplicate_login_action < 0 ? "无操作（该选项仅应出现与调试环境中）" : "禁止登陆"));
	ccis_log_info("-----------------征信业务设置----------------");
	ccis_log_info("征信中心地址：%s", zx_normal_url);
	ccis_log_info("代理服务器地址：%s" , zx_agent_url);
	ccis_log_info("代理标志后缀：%s" , zx_agent_sign);
	ccis_log_info("数据自动上传（仅代理有效）：%s" , auto_upload?"是":"否");
	if (auto_upload)
	{
		ccis_log_info("照片上传路径（仅代理有效）：%s" , pic_upload_url);
		ccis_log_info("记录上传路径（仅代理有效）：%s" , log_upload_url);
	}
	ccis_log_info("报告查询类型限制：%s" , report_limit == 1 ? "仅简版" : report_limit == 2 ? "仅详版" : "无限制");
	ccis_log_info("启用公安部强制认证：%s" , constrain_verify == 0 ? "否" : "是");
	ccis_log_info("未打印报告保留时间：%d天" , report_reserved_days);
	ccis_log_info("是否允许跨设备收费：%s" , cross_dev ? "允许":"禁止");
	ccis_log_info("是否允许跨网点收费：%s" , cross_website ? "允许":"禁止");
	ccis_log_info("收费类型支持：%s" , charge_type == 0 ? "不支持" : charge_type == 1 ? "仅现金" : charge_type == 2 ? "仅移动支付" : "无限制");
	if (charge_type > 1)
	{
		ccis_log_info("区域代号：%s" , zoneid);
		ccis_log_info("移动支付收费服务器地址：%s" , olchg_server);
		ccis_log_info("移动支付收费服务器端口：%d" , olchg_port);
		ccis_log_info("移动支付轮询超时时间：%ds" , olchg_timeout);
		ccis_log_info("移动支付轮询间隔时间：%ds" , olchg_polling_interval);
	}
	ccis_log_info("-----------------时钟参数设置----------------");
	ccis_log_info("每日自检时间：%d:00:00" , self_check_time);
	ccis_log_info("启用时钟同步：%s" , auto_timesync?"是":"否");
	if (auto_timesync)
		ccis_log_info("时钟同步服务器地址：%s" , timesync_server);
	ccis_log_info("-----------------流程控制设置-----------------");
	ccis_log_info("流程控制配置文件路径：%s" , flow_control_conf_file);
	ccis_log_info("业务维持间隔时间：%ds" , interval_s);
	ccis_log_info("-----------------日志文件设置-----------------");
	ccis_log_info("日志记录等级（0-7）：%d" , log_level);
	ccis_log_info("----------------------------------------------");
}
