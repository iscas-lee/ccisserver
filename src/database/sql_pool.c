#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include "sql_pool.h"
#include "../security/security.h"
#include "../log/ccis_log.h"

static SQLsock_Pool sql_sock_pool;
/***********************************************************
Function:       create_connect
Description:   
Calls:
Called By:
Input:
Output:
Return:		return 0: connect success, 1 connect error, -1: init error, -2:base64 decode error
Others:
 ************************************************************/
static int create_connect(SQLsock_Node *node)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int ret = 0;
	int opt = 1;
		if (NULL == mysql_init(&node->fd))
		{
			printf("mysql_init error!.\n");
			ret = -1;
		}
		else
		{
                       /* if(pthread_mutex_init(&node->sql_lock, NULL))
                        {
                                printf("Couldn't pthread_mutex_init to engine!.\n");
                        }
			*/
			if (ssl_connect)
				mysql_ssl_set(&node->fd , server_private_key , server_cert , cacert , NULL , NULL);
			if(!(node->mysql_sock = mysql_real_connect(&node->fd, db_ip, db_username, db_passwd, db_tablename, db_port , NULL, 0)))
			{
				ccis_log_err("数据库连接失败:IP = %s , 用户名 = %s , 密码 = %s , 数据库表名 = %s" , db_ip , db_username , db_passwd , db_tablename);
				node->sql_state = DB_DISCONN;
				ret = 1;
				printf("[%s:%d]connect error\n" , __FUNCTION__ , __LINE__);
			}
			else
			{
				node->used = 0;
				node->sql_state = DB_CONN;
				mysql_query(&node->fd, "set names utf8mb4");
				mysql_options(&node->fd, MYSQL_OPT_RECONNECT, &opt);
				opt = 3; //3S
				mysql_options(&node->fd, MYSQL_OPT_CONNECT_TIMEOUT, &opt);
				ret = 0;
			}
		}
	return ret;
}
/***********************************************************
Function:       Create_SQLpoll
Description:   	use this funcion to create the pool
Calls:
Called By:
Input:		the number of connections
Output:
Return:         return 0: success, 1 error,-1 init error
Others:
 ************************************************************/
int Create_SQLpool(int connect_pool_number)//creat pool
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int index = 0;
    MYSQL fd_temp;

    // init
    memset((SQLsock_Pool *)&sql_sock_pool, 0, sizeof(SQLsock_Pool));
    // set db info
    sprintf(sql_sock_pool.ip, "%s", db_ip);
   // sql_sock_pool.port = config->mysql_server_port;
    sprintf(sql_sock_pool.dbname, "%s",db_tablename);
    sprintf(sql_sock_pool.user, "%s", db_username);
    sprintf(sql_sock_pool.passwd, "%s", db_passwd);

    mysql_init(&fd_temp);

    // create connect
    for(index = 0; index < connect_pool_number; index ++)
    {
		if(create_connect(&(sql_sock_pool.sql_pool[index])))
		{
			goto POOL_CREATE_FAILED;
		}
		//printf("create db pool success\n");
		sql_sock_pool.sql_pool[index].index = index;
        sql_sock_pool.pool_number++;
    }
    return 0;
POOL_CREATE_FAILED:
	Destroy_SQLpool();
    return -1;
}
/***********************************************************
Function:       Destroy_SQLpool
Description:   	use this function to destory the pool
Calls:
Called By:
Input:
Output:
Return:       NULL 
Others:
 ************************************************************/
void Destroy_SQLpool()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int index;
	for (index = 0; index < sql_sock_pool.pool_number; index ++)
	{
		if (NULL != sql_sock_pool.sql_pool[index].mysql_sock) // close the mysql
		{
			mysql_close(sql_sock_pool.sql_pool[index].mysql_sock); // close
			sql_sock_pool.sql_pool[index].mysql_sock = NULL;
		}
		sql_sock_pool.sql_pool[index].sql_state = DB_DISCONN;
	}
	mysql_library_end();
}

/***********************************************************
Function:       get_db_connect_from_pool
Description:   	get a connection which is not being used
Calls:
Called By:
Input:
Output:
Return:         return SQLsock_Node success,NULL error
Others:
 ************************************************************/
SQLsock_Node *get_db_connect_from_pool()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int start_index = 0, loop_index = 0, index = 0, ping_ret = 0;

	srand((int) time(0));
	start_index = rand() % sql_sock_pool.pool_number;

	for (loop_index = 0; loop_index < sql_sock_pool.pool_number; loop_index++)
	{
		index = (start_index + loop_index) % sql_sock_pool.pool_number;
            //    if (0 == pthread_mutex_trylock(&(sql_sock_pool.sql_pool[index].sql_lock)))
	//	{	
			if (DB_DISCONN == sql_sock_pool.sql_pool[index].sql_state)
			{
				// try reconnect
				if (0 != create_connect(&(sql_sock_pool.sql_pool[index])))
        		{
					// also can not connect to the database
        			release_sock_to_sql_pool(&(sql_sock_pool.sql_pool[index]));
        			continue;
        		}
			}
			ping_ret = mysql_ping(sql_sock_pool.sql_pool[index].mysql_sock);
			if (0 != ping_ret)
			{
				printf("mysql_ping error!\n");
				sql_sock_pool.sql_pool[index].sql_state = DB_DISCONN; // ping error then next time reconnect
				release_sock_to_sql_pool(&(sql_sock_pool.sql_pool[index]));
			}
			else
			{
				sql_sock_pool.sql_pool[index].used = 1;
				break;
			}
	//	}
	}
	if (loop_index == sql_sock_pool.pool_number)
	{
		return NULL;
	}
	else
	{
		return &(sql_sock_pool.sql_pool[index]);
	}

}
/***********************************************************
Function:       release_sock_to_sql_pool
Description:   	put the connection to pool
Calls:
Called By:
Input:
Output:
Return:         return 0: success, 1 error
Others:
 ************************************************************/
int release_sock_to_sql_pool(SQLsock_Node * n)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	n->used = 0;
//	if(pthread_mutex_unlock(&n->sql_lock))
//		return 1;
	return 0;
}
