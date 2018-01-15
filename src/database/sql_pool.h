#ifndef SQL_POOL_H_
#define SQL_POOL_H_

#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include "../configure/configure.h"
#include "../ccis.h"

/**********mysql info*************/
#define MYSQLDEBUG 0
#define MYSQL_IP 	get_string_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "MYSQL_IP")
#define MYSQL_USER 	get_string_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "MYSQL_USER")
#define MYSQL_PASSWD 	get_string_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "MYSQL_PASSWD")
#define MYSQL_DATABASE  get_string_accord_group_key(keyFile , CONF_FILE_PATH , "MYSQL" , "MYSQL_DATABASE")	

/*************DB Type*******************/
#define DB_LEN_IP		15
#define DB_LEN_PORT		8
#define DB_LEN_DBNAME		64
#define DB_LEN_DBUSER		64
#define DB_LEN_PASSWD		64

#define POOL_NUMBER		10	//number of connections

/******************sql pool**********************/
typedef struct _SQLsock_Node{
	MYSQL	fd;
	MYSQL 	*mysql_sock;
	char	used;
	int 	index; 
	enum {DB_DISCONN, DB_CONN} 	sql_state;
}SQLsock_Node;

typedef struct _SQLsock_Pool{
	SQLsock_Node sql_pool[POOL_NUMBER];

	char ip[DB_LEN_IP + 1];
	int  port;
	char dbname[DB_LEN_DBNAME + 1];
	char user[DB_LEN_DBUSER + 1];
	char passwd[DB_LEN_PASSWD + 1];

	int pool_number;
}SQLsock_Pool;

void	Destroy_SQLpool();//destory the pool
SQLsock_Node *get_db_connect_from_pool();
int 	release_sock_to_sql_pool(SQLsock_Node *n);
int 	Create_SQLpool(int connect_pool_number);//create the pool



#endif /* SQL_POOL_H_ */
