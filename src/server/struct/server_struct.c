#include "server_struct.h"
#include "../../database/dbquery.h"
#include "stdlib.h"
#include "../../other/ccis_time.h"
#include "../../log/ccis_log.h"
#include <errno.h>

int	Create_Log_List();
int	Init_Log_Node(pSearch_Log* plog_node);
pSearch_Log	Find_Log_Node(char* querysn);
pSearch_Log	Find_Log_Node_By_Dev(const char* devsn);
pSearch_Log	Add_Log_Node(pSearch_Log log_node);
void	Free_Log_Node(char* querysn);
void	Destroy_Log_List();
pSearch_Log	Dump_Log_Node(pSearch_Log log_node);

int Create_Log_List()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	Search_List	= (pSLH)malloc(sizeof(struct Server_List_Head));
	if (!Search_List)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		retv	= 1;
		goto clean_up;
	}
	Search_List->node_num	= 0;
	Search_List->log_node	= NULL;

clean_up:
	return retv;
}

int Init_Log_Node(pSearch_Log* plog_node)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	char* cur_time	= NULL;
	if (!(*plog_node))
	{
		*plog_node	= (pSearch_Log)malloc(sizeof(struct Search_Log));
		if (!(*plog_node))
		{
			ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
			retv	= 1;
			goto clean_up;
		}
	}

	memset(*plog_node , 0 , sizeof(struct Search_Log));

	(*plog_node)->next	= NULL;

	cur_time	= Get_Localtime();
	if (!cur_time)
	{
		printf("Cannot Get Current Time\n");
		retv	= 2;
		goto clean_up;
	}
	int qyear	= Get_Localyear();
	sprintf((*plog_node)->qyear , "%d" , qyear);

	strncpy((*plog_node)->querydt , cur_time , sizeof((*plog_node)->querydt));
	(*plog_node)->lastpackage	= Get_Time_From_String(cur_time);
	strcpy((*plog_node)->prtsgn , "0");
	strcpy((*plog_node)->querysgn , "0");
	strcpy((*plog_node)->idtype , "0");

	(*plog_node)->falres	= 0;
	(*plog_node)->retry_time	= 0;
	(*plog_node)->unprint_up_flag	= false;

clean_up:
	if (cur_time)
		free(cur_time);
	return retv;
}

pSearch_Log Find_Log_Node(char* querysn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!Search_List || !querysn)
		return NULL;

	pSearch_Log result	= NULL;
	pSearch_Log pos		= Search_List->log_node;
	while (pos)
	{
		if (strcmp(pos->querysn , querysn) == 0)
		{
			result	= pos;
			break;
		}
		pos	= pos->next;
	}

	return result;
}

pSearch_Log Find_Log_Node_By_Dev(const char* devsn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!Search_List || !devsn)
		return NULL;

	pSearch_Log result	= NULL;
	pSearch_Log pos		= Search_List->log_node;
	while (pos)
	{
		if (strcmp(pos->devsn , devsn) == 0)
		{
			result	= pos;
			break;
		}
		pos	= pos->next;
	}

	return result;
}

pSearch_Log Add_Log_Node(pSearch_Log log_node)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	pSearch_Log result	= NULL;
	pSearch_Log pos		= Search_List->log_node;
	if (!pos)
	{
		Search_List->log_node	= log_node;
		Search_List->node_num ++;
		log_node->next	= NULL;
		return NULL;
	}
	while (pos)
	{
		if (strcmp(pos->devsn , log_node->devsn) == 0)
		{
			result	= pos;
		}
		if (pos->next)
			pos	= pos->next;
		else
			break;
	}

	pos->next	= log_node;
	log_node->next	= NULL;
	Search_List->node_num ++;

	return result;
}

void Free_Log_Node(char* querysn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!Search_List)
		return;
	pSearch_Log prev	= Search_List->log_node;
	pSearch_Log pos		= NULL;
	pSearch_Log tmp		= NULL;

	if (!prev)
		return;

	if (!strcmp(prev->querysn , querysn))
	{
		Search_List->log_node	= prev->next;
		tmp	= prev;
		Search_List->node_num --;
		goto clean_up;
	}

	pos	= prev->next;
	while (pos)
	{
		if (strcmp(pos->querysn , querysn) == 0)
		{
			prev->next	= pos->next;
			tmp	= pos;
			Search_List->node_num --;
			goto clean_up;
		}
		prev	= pos;
		pos	= prev->next;
	}

clean_up:
	if (tmp)
	{
		Destroy_ThreadList(&(tmp->t_list));
		free(tmp);
	}
	return;
}

void Destroy_Log_List()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!Search_List)
		return;
	pSearch_Log log_node	= Search_List->log_node;
	while(log_node)
	{
		Search_List->log_node	= log_node->next;
		free(log_node);
		log_node	= Search_List->log_node;
	}

	free(Search_List);
	return;
}

pSearch_Log Dump_Log_Node(pSearch_Log log_node)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!log_node)
	{
		ccis_log_err("无法复制查询节点：参数错误！");
		return NULL;
	}

	pSearch_Log tmp_node	= (pSearch_Log)malloc(sizeof(struct Search_Log));
	if (!tmp_node)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return NULL;
	}

	memmove(tmp_node , log_node , sizeof(struct Search_Log));
	tmp_node->next	= NULL;
	return tmp_node;
}
