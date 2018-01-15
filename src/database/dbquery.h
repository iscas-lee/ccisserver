#ifndef DBQUERY_H
#define DBQUERY_H

#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>
#include "sql_pool.h"

#define DB_MAXSIZE	4096		//SQL语句最大长度
#define MAXROW		1000		//查询结果最大行数
#define MAXCOL		40		//查询结果最大列数
#define MAX_IMAGESIZE	1024*1000	//数据库中存储图片的大小上限
#define MAX_TEXTSIZE	1024*500	//数据库中存储文本文件的大小上限
/**********查询结果************/
typedef struct query_index_info{
	int num_columns;		//列数
	int num_rows;		//行数
	int cur_row;		
	char *res_data[MAXROW][MAXCOL];	//结果指针数组
	MYSQL_RES* ptr;		//指向MYSQL_RES查询结果的指针，需要先于该结构体使用mysql_free_result()来释放
}Query_Info;

extern int Do_Connect();	//从连接池拿来连接
extern int Do_Close();		//将连接放回连接池
extern int DB_Select_Data(char *table_name, char *fields, char *values,Query_Info* query_data);	//查询接口 
//select fields from table_name where values
extern int DB_Insert_Data(char *table_name, char *fields, char *values);					//增加接口
//insert into table_name (fields)values(values)
extern int DB_Update_Data(char *table_name, char *values, char *condition);	//更新接口
//update  table_name set values where condition
//eg. values="field1='value1',field2='value2''"
extern int DB_Delete_Data(char *table_name, char *condition);					//删除接口
//delete from table name where fields = 'values'
extern int DB_Insert_Image(char *table_name, char *fields,char *pFileName , char* condition);				//图片存入接口
extern int DB_Insert_Text(char *table_name, char *fields, char *pFileName , char* condition);
extern int mysql_fetch_image_ex(char *pImageTableName,char *fields,char *value,char *pFileName);		//图片取出接口
extern int select_data(char *table_name, char *fields, char *values,int(*call_back)(Query_Info*,MYSQL_RES*,int,int) , Query_Info* result);
extern int call_back_select_data(Query_Info* arg,MYSQL_RES* resultSet,int num_fields,int num_rows);

#endif
