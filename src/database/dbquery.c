#include "math.h"
#include "dbquery.h"
#include "sql_pool.h"
#include "../ccis.h"
#include "../security/security.h"
#include "../log/ccis_log.h"

static SQLsock_Node *socket_node = NULL;

/***********************************************************
Function:       Do_Connect
Description:   从连接池“拿”的操作，如果连接池已满，创建新的连接 
Calls:
Called By:
Input:
Output:
Return:0为成功,1为失败
Others:
 ************************************************************/
int Do_Connect() {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif

    socket_node = get_db_connect_from_pool();    //从连接池拿来一个连接
    if (NULL == socket_node) {
        printf("sql_pool if full.create new connect\n");
        int ret = 0;
        socket_node = (SQLsock_Node *) malloc(sizeof(SQLsock_Node));
        mysql_init(&socket_node->fd);

	if (ssl_connect)
		mysql_ssl_set(&socket_node->fd , server_private_key , server_cert , cacert , NULL , NULL);
        if (!mysql_real_connect(&socket_node->fd, db_ip, db_username, db_passwd, db_tablename, db_port, NULL,
                                0))
        {
            printf("mysql connect error!\n");
            return FAILED;
        }
        else {
#ifdef DEBUG
            printf("connect success!\n");
#endif
        }
        ret = mysql_query(&socket_node->fd, "set names utf8mb4");
        if (ret) {
            printf("set names utf8 failed!\n");
            mysql_close(&socket_node->fd);
            return FAILED;
        }
    }
    return SUCCESS;
}

/***********************************************************
Function:       Do_Close
Description:   连接池的“放回”操作 
Calls:
Called By:
Input:
Output:
Return:
Others:
 ************************************************************/
int Do_Close() {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    if (release_sock_to_sql_pool(socket_node)) {
        mysql_close(&socket_node->fd);
        free(socket_node);
    }
    return SUCCESS;

}

/***********************************************************
Function:       call_back_select_data
Description:    select data的回调函数
Calls:
Called By:	select_data
Input:		param:arg,对应的返回类型，是函数的输出变量；
		param:resultSet,对应查询表的结果集；
		param:num_fields,对应查询表的字段数；
		param:num_rows,查询结果的数据库记录行数
Output:
Return:		0为成功，-1为查无结果，1为失败,其他为errno
Others:
 ************************************************************/
int call_back_select_data(Query_Info *arg, MYSQL_RES *resultSet, int num_fields, int num_rows) {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    MYSQL_ROW row;
    if (arg == NULL) {
        printf("%s function %d line bad input parameter.\n", __func__, __LINE__);
        return FAILED;
    }

    arg->num_columns = num_fields;
    arg->num_rows = num_rows;
    arg->cur_row = 0;
    int arr_row = 0;
    if (arg->cur_row < arg->num_rows) {
        while ((row = mysql_fetch_row(resultSet)) != NULL) {
            unsigned int field_count;
            field_count = 0;
            if (arg->cur_row >= (num_rows - MAXROW)) {
                while (field_count < num_fields) {
                    arg->res_data[arr_row][field_count] = row[field_count];
                    field_count++;
                }
                arr_row++;
            }
            arg->cur_row++;
        }
        return SUCCESS;
    }
    return FAILED;
}


/***********************************************************
Function:       DB_Insert_Data
Description:    向数据库中插入数据
Calls:
Called By:
Input:
Output:
Return:		0为成功，-1为查无结果，1为失败,其他为errno
Others:
 ************************************************************/
int DB_Insert_Data(char *table_name, char *fields, char *values) {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    char mysqlbuf[DB_MAXSIZE];
    memset(mysqlbuf, '\0', DB_MAXSIZE);

    sprintf(mysqlbuf, "insert into %s(%s) values(%s)", table_name, fields, values);

    int ret = mysql_query(&(socket_node->fd), mysqlbuf);
    if (!ret) {
        printf("Inserted %lu rows\n", (unsigned long) mysql_affected_rows(&(socket_node->fd)));
    }
    else {
        fprintf(stderr, "Insert error %d: %s\n", mysql_errno(&(socket_node->fd)), mysql_error(&(socket_node->fd)));
	ccis_log_err("SQL Insert Error : %s" , mysqlbuf);
	//LOGGER(0 , "sql" , "Insert error %d: %s" , mysql_errno(&(socket_node->fd)), mysql_error(&(socket_node->fd)));
        return mysql_errno(&(socket_node->fd));
    }

    return SUCCESS;
}

/***********************************************************
Function:       DB_Select_Data
Description:    用户实际调用的select入口
Calls:		select_data
Called By:
Input:		query_data,类型为结构体Query_Info，输出对应的结果集
Output:
Return:		0为成功，-1为查无结果，1为失败,其他为errno
Others:
 ************************************************************/
int DB_Select_Data(char *table_name, char *fields, char *values, Query_Info *query_data) {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int ret = 0;
    if (query_data == NULL) {
        printf("input error\n");
    }
    ret = select_data(table_name, fields, values, call_back_select_data, query_data);
	ccis_log_debug("SQL Select Command : select %s from %s where %s" , fields , table_name , values);
    if (ret == -1) {
        printf("no such result\n");
        return -1;
    } else
        return ret;
}

/**********************************************************
Function:       DB_Update_Data
Description:    更新数据库中数据
Calls:
Called By:
Input:
Output:
Return:		0为成功，-1为查无结果，1为失败,其他为errno
Others:
 ************************************************************/
int DB_Update_Data(char *table_name, char *values, char* condition)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    char query[DB_MAXSIZE];
    sprintf(query, "update %s set %s where %s", table_name, values , condition);
	ccis_log_debug("SQL Update Command : %s" , query);
    int ret = mysql_query(&(socket_node->fd), query);
    if (ret) {
        printf("err making query\n");
	ccis_log_err("SQL Update Error : %s" , query);
        return mysql_errno(&(socket_node->fd));
    }

    return SUCCESS;
}

/***********************************************************
Function:       DB_Delete_Data
Description:    删除数据库中数据
Calls:
Called By:
Input:
Output:
Return:	0为成功，-1为查无结果，1为失败,其他为errno
Others:
 ************************************************************/
int DB_Delete_Data(char *table_name, char *condition) {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    char query[DB_MAXSIZE];
    sprintf(query, "delete from %s where %s", table_name, condition);
    int ret = mysql_query(&(socket_node->fd), query);
    if (ret) {
	ccis_log_err("SQL Delete Error : %s , return values %d" , query , ret);
        printf("err making query\n");
        return mysql_errno(&(socket_node->fd));
    }
    return SUCCESS;
}

/***********************************************************
Function:       select_data
Description:    查找数据库中数据
Calls:		call_back_selecct_data
Called By:	DB_Select_Data
Input:
Output:
Return:		0为成功，-1为查无结果，1为失败,其他为errno
Others:
 ************************************************************/
int select_data(char *table_name, char *fields, char *values, int(*call_back)(Query_Info *, MYSQL_RES *, int, int),
                Query_Info *result) {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    if (result == NULL) {
        printf("%s function %d line bad input parameter.\n", __func__, __LINE__);
    }

    char query[DB_MAXSIZE];
    MYSQL_RES *res_ptr;
    int ret;
    sprintf(query, "select %s from %s where %s ", fields, table_name, values);
    ret = mysql_query(&(socket_node->fd), query);		//执行一条mysql语句
    if (ret) {
        printf("err making query\n");
        return mysql_errno(&(socket_node->fd));
    }
    else {
        res_ptr = mysql_store_result(&(socket_node->fd));
        if (res_ptr) {
            int num_fields = mysql_num_fields(res_ptr);
            int num_rows = mysql_num_rows(res_ptr);
            if (num_rows == 0) {
			result->ptr	= res_ptr;
     //           mysql_free_result(res_ptr);
                return -1;
            }
            if (call_back) {
                call_back(result, res_ptr, num_fields, num_rows);
            }
		result->ptr	= res_ptr;
            //mysql_free_result(res_ptr);
        }
    }
    return SUCCESS;
}

/***********************************************************
Function:       DB_Insert_Image
Description:    向MySQL数据库中存储图片
Calls:
Called By:
Input:
Output:
Return:0	为成功，-1为查无结果，1为失败,其他为errno
Others:
 ************************************************************/

int DB_Insert_Image(char *table_name, char *fields, char *pFileName , char* condition) {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    FILE *fp;
    char szImageData[MAX_IMAGESIZE];//图片大小最大不超过1M
    char szStoreImageData[2 * MAX_IMAGESIZE + 1];
    char szSql[2 * MAX_IMAGESIZE + 1];
    unsigned long ulReadLength = 0, ulStoreLength = 0, ulStoredLength = 0;
    int iRetCode = -1;

    fp = fopen(pFileName, "rb");
    if (NULL == fp) {
	ccis_log_err("[%s:%d]文件%s打开失败！失败原因：%s" , __FUNCTION__ , __LINE__ , pFileName , strerror(errno));
        return FAILED;
    }

    memset(szImageData, 0, MAX_IMAGESIZE);
    ulReadLength = fread(szImageData, 1, MAX_IMAGESIZE , fp);
    fclose(fp);

    if (!ulReadLength) {
	ccis_log_err("[%s:%d]文件%s读取失败！失败原因：%s" , __FUNCTION__ , __LINE__ , pFileName , strerror(errno));
        return FAILED;
    }

    printf("ulReadLength = %ld \n", ulReadLength);
	ccis_log_debug("读取到文件大小：%ld" , ulReadLength);

    memset(szStoreImageData, 0, 2 * MAX_IMAGESIZE + 1);
    ulStoreLength = mysql_real_escape_string(&(socket_node->fd), szStoreImageData, szImageData, ulReadLength);
    //二进制数据可能包含一些特殊字符,这些字符在sql语句中可能会引起一些问题, 所以必须转义,理论上每个字符都可能是特殊字符,所以szStoreImageData数组>大小是szImageData数组大小的两倍, 该函数还会在szStoreImageData数组最后加上结尾符

    printf("ulStoreLength = %ld \n", ulStoreLength);

    memset(szSql, 0, 2 * MAX_IMAGESIZE + 1);
    sprintf(szSql, "update %s set %s='%s' where %s", table_name, fields, szStoreImageData , condition);

    ulStoredLength = strlen(szSql);
    iRetCode = mysql_real_query(&(socket_node->fd), szSql, ulStoredLength);
    printf("ulStoredLength = %ld \n", ulStoredLength);
    if (iRetCode) {
        fprintf(stderr, "insert error ,sqlcode=[%d] : %s !\n", mysql_errno(&(socket_node->fd)),
                mysql_error(&(socket_node->fd)));
        return mysql_errno(&(socket_node->fd));
    }
    return SUCCESS;

}

/***********************************************************
Function:       mysql_fetch_image_ex
Description:    从MySQL数据库提取存储的图片
Calls:
Called By:
Input:
Output:
Return:		0为成功，-1为查无结果，1为失败,其他为errno
Others:
 ************************************************************/
int mysql_fetch_image_ex(char *pImageTableName, char *fields, char *value, char *pFileName) {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    FILE *fp;
    MYSQL_RES *res_ptr = NULL;
    MYSQL_ROW sqlrow;
    int iRetCode = -1, iTableRow = 0;
    char szSql[256];
    unsigned long *ulLength = NULL;
    unsigned long ulWriteLength = 0;


    memset(szSql, 0, sizeof(szSql));

    sprintf(szSql, "select data from %s where %s = '%s'", pImageTableName, fields, value);

    iRetCode = mysql_query(&(socket_node->fd), szSql); //执行SQL语句
    if (iRetCode) {
        fprintf(stderr, "Select error %d: %s !\n", mysql_errno(&(socket_node->fd)),
                mysql_error(&(socket_node->fd)));  //打印错误处理具体信息
//	LOGGER(0 , "sql" , "Select Error %d: %s" , mysql_errno(&(socket_node->fd)), mysql_error(&(socket_node->fd)));
        return mysql_errno(&(socket_node->fd));
    }
    res_ptr = mysql_store_result(&(socket_node->fd)); //集合
    if (res_ptr) {
        iTableRow = mysql_num_rows(res_ptr);//行

        if (iTableRow == 0)//表示查询没有结果
        {
            //		fclose(fp);		//0725 patch	: 未打开任何文件
            mysql_free_result(res_ptr); //0725 patch
            printf(" result is null  !\n");
            return FAILED;
        }

        sqlrow = mysql_fetch_row(res_ptr);
        ulLength = mysql_fetch_lengths(res_ptr);
        sscanf(sqlrow[1], "%s", pFileName);//从数据库中取文件名

        printf("ulFetchedLength: %ld\n", ulLength[0]);

        mysql_free_result(res_ptr); //完成对数据的所有操作后,调用此函数来让MySQL库清理它分配的对象

        fp = fopen(pFileName, "wb");
        if (NULL == fp) {
            fprintf(stderr, "This file: [ %s ] isn't exsit !\n", pFileName);
            return FAILED;
        }

        ulWriteLength = fwrite(sqlrow[0], 1, ulLength[0], fp);
        if (ulWriteLength == 0) {
            fclose(fp);
            fprintf(stderr, "Write file found error !\n");
            return FAILED;
        }
        printf("ulWriteLength = %ld \n", ulWriteLength);

    }
    else {
        //fclose(fp);		//0725 patch	： 该流程分支不会打开任何文件
        fprintf(stderr, "Select result is null  !\n");
        return FAILED;
    }

    if (fp)            //0725 patch
        fclose(fp);
    return SUCCESS;
}


int DB_Insert_Text(char *table_name, char *fields, char *pFileName , char* condition) {
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    FILE *fp;
    char szTextData[MAX_TEXTSIZE];//图片大小最大不超过1M
    char szStoreTextData[2 * MAX_TEXTSIZE + 1];
    char szSql[2 * MAX_TEXTSIZE + 1];
    unsigned long ulReadLength = 0, ulStoreLength = 0, ulStoredLength = 0;
    int iRetCode = -1;

    fp = fopen(pFileName, "rb");
    if (NULL == fp) {
	ccis_log_err("[%s:%d]文件%s打开失败！失败原因：%s" , __FUNCTION__ , __LINE__ , pFileName , strerror(errno));
        return FAILED;
    }

    memset(szTextData, 0, MAX_TEXTSIZE);
    ulReadLength = fread(szTextData, 1, MAX_TEXTSIZE , fp);
    fclose(fp);

    if (!ulReadLength) {
        fprintf(stderr, "Read file found error !\n");
	ccis_log_err("[%s:%d]文件%s读取失败！失败原因：%s" , __FUNCTION__ , __LINE__ , pFileName , strerror(errno));
        return FAILED;
    }

    printf("ulReadLength = %ld \n", ulReadLength);
	ccis_log_debug("读取到文件大小：%ld" , ulReadLength);

    memset(szStoreTextData, 0, 2 * MAX_TEXTSIZE + 1);
    ulStoreLength = mysql_real_escape_string(&(socket_node->fd), szStoreTextData, szTextData, ulReadLength);
    //二进制数据可能包含一些特殊字符,这些字符在sql语句中可能会引起一些问题, 所以必须转义,理论上每个字符都可能是特殊字符,所以szStoreTextData数组>大小是szTextData数组大小的两倍, 该函数还会在szStoreTextData数组最后加上结尾符

    printf("ulStoreLength = %ld \n", ulStoreLength);

    memset(szSql, 0, 2 * MAX_TEXTSIZE + 1);
    sprintf(szSql, "update %s set %s='%s' where %s", table_name, fields, szStoreTextData , condition);

    ulStoredLength = strlen(szSql);
    iRetCode = mysql_real_query(&(socket_node->fd), szSql, ulStoredLength);
    printf("ulStoredLength = %ld \n", ulStoredLength);
    if (iRetCode) {
        fprintf(stderr, "insert error ,sqlcode=[%d] : %s !\n", mysql_errno(&(socket_node->fd)),
                mysql_error(&(socket_node->fd)));
        return mysql_errno(&(socket_node->fd));
    }
    return SUCCESS;

}
