#ifndef __CCIS_H__
#define __CCIS_H__

#define CCIS_MAXSIZE	1024
#define CCIS_MIDSIZE	256
#define CCIS_SMALLSIZE	64
#define CCIS_MINSIZE	16

#define	CCIS_THREADLIMITS	256

#define	CCIS_PATHLEN	128

#define QUERYSN_LEN	17
#define DEVSN_LEN	12
#define	UKEYSN_LEN	33
#define	TPMSN_LEN	33
#define UKEYPIN_LEN	7

#define	CHG_ORDERID_LEN	33

#define SUCCESS		0
#define FAILED		1

#define REPORT_SIMPLE	"21"
#define	REPORT_NORMAL	"24"

#define RESOURCE_INIT_ERR	233

#ifndef likely
#define likely(x)	__builtin_expect(!!(x) , 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x) , 0)
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/********************配置文件项，全局变量******************/
char*	version;
int	process_limits;
int	max_socket_connection;
int	rlimit_number;
char*	data_path;
int	auto_restart;
int	link_timeout_s;

char*	version_lowerlimit;
char*	version_upperlimit;

char*	serverip;
int	serverport;

char*	db_ip;
int	db_port;
char*	db_username;
char*	db_passwd;
char*	db_tablename;
int	ssl_connect;
int	store_files;

char*	cacert;
char*	server_private_key;
char*	server_cert;
char*	client_private_key;
char*	client_cert;
int	ca_enable;
char*	cahost;
int	duplicate_login_action;		//-1无操作，0禁止登陆，1强制登陆

char*	zx_normal_url;
char*	zx_agent_url;
char*	zx_agent_sign;
int	auto_upload;
char*	pic_upload_url;
char*	log_upload_url;
int	report_limit;
int	constrain_verify;
int	report_reserved_days;
int	charge_type;
int	cross_dev;
int	cross_website;
char*	zoneid;
char*	olchg_server;
int	olchg_port;
int	olchg_timeout;
int	olchg_polling_interval;

int	self_check_time;
int	auto_timesync;
char*	timesync_server;

char*	flow_control_conf_file;
int	interval_s;

int	log_level;
/**********************************************************/


#endif
