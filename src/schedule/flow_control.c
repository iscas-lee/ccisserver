#include "flow_control.h"
#include "../log/ccis_log.h"
#include <string.h>

int	Create_FlowMap(const char* filepath);
void	Destroy_FlowMap();
int	Get_Index_By_Name(const char* flowname);
int	Check_Process_Flow(pFlow pfn , int number);
int	Init_FlowNode(pFlow pfn , int index);
int	Get_FlowName_By_Index(int node_index , char* flowname);
int	Get_Number_By_Index(int node_index);
void	Print_Map();

int	Analyze_FlowNode(FILE* fp);
int	Analyze_FlowEdge(FILE* fp);
int	Add_Edge_By_Condition(pFlow_Node node , char* condition , int des_index);
int	Add_Edge_Des_By_Condition(pFlow_Node node , char* c_name , int des_index);
int	Add_Edge_Des_By_Name(pFlow_Node node , char* arc_name , int des_index);
int	Add_Edge_Condition_By_Name(pFlow_Node node , char* arc_name , char* condition);
pFlow_Node Find_Node_By_Name(const char* node_name);
pFlow_Arc  Find_Arc_By_Condition(pFlow_Node pfn , const char* condition);

void	Delete_Space(char* buffer);


static char* strsplit_before(char **stringp , const char* delim)
{
	char *s;
	const char* spanp;
	int c , sc;
	char *tok;
	if ((s = *stringp) == NULL)
		return NULL;
	for (tok = s ; ; )
	{
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp ++ ) == c)
			{
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return tok;
			}
		}while(sc != 0);
	}
}

static char* strsplit_after(char** stringp , const char* delim)
{
	if (delim == NULL)
		delim	= "=";
	if (!stringp || !*stringp)
		return NULL;

	char* tok = strsep(stringp , delim);
	if (tok)
		tok	= strsep(stringp , delim);
	return tok;
}


int Create_FlowMap(const char* filepath)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!filepath)
	{
		printf("Configure File Path Cannot Be NULL !\n");
		return -1;
	}

	FILE* confp;
	char filebuf[_FC_MAXSIZE_]	= {0};
	char* pBuf	= NULL;
	int errcode	= 0;

	confp	= fopen(filepath , "rt");
	if (!confp)
	{
		perror("Configure File Cannot Open ");
		errcode	= -1;
		goto clean;
	}

	ALGraph	= (pALG)malloc(sizeof(struct ALG));
	if (!ALGraph)
	{
		perror("Memory Not Enough ");
		errcode	= -1;
		goto clean;
	}
	ALGraph->node_num	= 0;
	ALGraph->arc_num	= 0;

	do
	{
		if(fgets(filebuf , _FC_MAXSIZE_ , confp))
		{
			Delete_Space(filebuf);
		}
		else
			break;
	}while(strcmp(filebuf , _FC_NODE_HEAD_));

	if (fgets(filebuf , _FC_MAXSIZE_ , confp) == NULL)
	{
		printf("Configure File Format Error ! %d\n" , __LINE__);
		errcode	= -1;
		goto clean;
	}
	Delete_Space(filebuf);
	pBuf	= filebuf;
	while(*pBuf ++ != '=' && *pBuf != '\0');
	if (*pBuf == '\0')
		return -1;
	*(pBuf - 1)	= '\0';
	if (strcmp(filebuf , "FLOW_NUMBER"))
	{
		printf("Configure File Format Error ! %d\n" , __LINE__);
		errcode	= -1;
		goto clean;
	}
	ALGraph->node_num	= atoi(pBuf);
	ALGraph->FlowNodeArray	= (pFlow_Node*)malloc(sizeof(pFlow_Node) * ALGraph->node_num);
	if (!ALGraph->FlowNodeArray)
	{
		perror("Memory Not Enough ");
		errcode	= -1;
		goto clean;
	}
	memset(ALGraph->FlowNodeArray , 0 , ALGraph->node_num * sizeof(pFlow_Node));

	errcode	= Analyze_FlowNode(confp);
	if (errcode)
	{
		printf("Flow Node Init Failed ! \n");
		goto clean;
	}

	do
	{
		if (fgets(filebuf , _FC_MAXSIZE_ , confp))
		{
			Delete_Space(filebuf);
		}
		else
			break;
	}while(strcmp(filebuf , _FC_ARC_HEAD_));
	errcode	= Analyze_FlowEdge(confp);
	if (errcode)
	{
		printf("Flow Edge Init Failed ! \n");
		goto clean;
	}
	
	
clean:
	if(confp)
		fclose(confp);
	confp	= NULL;
#ifdef DEBUG
	if (errcode == 0)
		Print_Map();
#endif
	return errcode;
}

void Destroy_FlowMap()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ALGraph)
		return;
	pFlow_Node tmp_node	= NULL;
	pFlow_Arc tmp_arc	= NULL;
	
	int node_num	= ALGraph->node_num;
	int arc_num	= 0;

	for (int node_index = 0 ; node_index < node_num ; node_index ++)
	{
		tmp_node	= ALGraph->FlowNodeArray[node_index];
		if (tmp_node == NULL)
			continue;
		arc_num		= tmp_node->outdegree;
		int arc_index;
		for (arc_index = 0 , tmp_arc = tmp_node->first_arc ; arc_index < arc_num ; arc_index ++)
		{
			if (tmp_arc == NULL)
				break;
			tmp_node->first_arc	= tmp_arc->next;
			free(tmp_arc);
			tmp_arc	= NULL;
			tmp_arc	= tmp_node->first_arc;
		}
		free(tmp_node);
		tmp_node	= NULL;
	}
	free(ALGraph);
	ALGraph	= NULL;
}

int Analyze_FlowNode(FILE* confp)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	char filebuf[_FC_MAXSIZE_]	= {0};
	char *p	= NULL;
	int attr_num;
	int node_index;
	int node_num	= ALGraph->node_num;
	for (int i = 0 ; i < node_num ; i ++)
	{
		attr_num	= 3;
		node_index	= 0;
		while(attr_num --)
		{
			if(fgets(filebuf , _FC_MAXSIZE_ , confp) == NULL)
			{
				printf("Configure File Format Error ! %d\n" , __LINE__);
				return -1;
			}
			if (filebuf[0] == '\n')
			{
				printf("Node Analyze Done !\n");
				break;
			}
			if (filebuf[0] == '#')
			{
				attr_num ++;
				continue;
			}
			Delete_Space(filebuf);
			p	= filebuf;
			if (attr_num == 2)			//"id=..."
			{
				while(*p ++ != '=' && *p != '\0');
				if (*p == '\0')
				{
					printf("%d return \n" , __LINE__);
					return -1;
				}
				*(p - 1) = '\0';
				if (strcmp(filebuf , _FC_NODE_ID_))
				{
					printf("%d return \n" , __LINE__);
					return -1;
				}
				node_index	= atoi(p);
				if (ALGraph->FlowNodeArray[i] != NULL)
				{
					printf("Error : Redefine Flow Node %d !\n" , node_index);
					return -1;
				}
				ALGraph->FlowNodeArray[i]	= (pFlow_Node)malloc(sizeof(struct Flow_Node));
				if (ALGraph->FlowNodeArray[i] == NULL)
				{
					printf("%d return \n" , __LINE__);
					return -1;
				}
				ALGraph->FlowNodeArray[i]->first_arc	= NULL;
				ALGraph->FlowNodeArray[i]->number	= node_index;
				ALGraph->FlowNodeArray[i]->outdegree	= 0;
			}
			else if (attr_num == 1)			//"name=..."
			{
				while(*p ++ != '=' && *p != '\0');
				if (*p == '\0')
				{
					printf("%d return \n" , __LINE__);
					return -1;
				}
				*(p - 1) = '\0';
				if (strcmp(filebuf , _FC_NODE_NAME_))
				{
					printf("%d return \n" , __LINE__);
					return -1;
				}
				strncpy(ALGraph->FlowNodeArray[i]->FlowName , p , _FC_BUFFERSIZE_);
			}
			else if(attr_num == 0)			//"condition=..."
			{
				while(*p ++ != '=' && *p != '\0');
				if (*p == '\0')
				{
					printf("%d return \n" , __LINE__);
					return -1;
				}
				*(p - 1) = '\0';
				if (strcmp(filebuf , _FC_NODE_CONDITION_))
				{
					printf("%d return \n" , __LINE__);
					return -1;
				}
				char* q	= p;
				int arc_num	= 0;
				while (*q != '\0' && *q != '\n')
				{
					q ++;
					if (*q == ',')
						arc_num	++;
				}
				ALGraph->FlowNodeArray[i]->outdegree	= ++arc_num;
				ALGraph->arc_num	+= arc_num;
				char* condition		= NULL;
				for (condition = strsplit_before(&p , ",") ; condition != NULL ; condition = strsplit_before(&p , ","))
				{
					int ret	= Add_Edge_By_Condition(ALGraph->FlowNodeArray[i] , condition , -1);
					if (ret)
					{
						printf("Add Edge Failed !\n");
						return -1;
					}
				}
			}
			else
			{
				printf("Unknow Error !\n");
				return -1;
			}
		}
	}
	return 0;
}

int Analyze_FlowEdge(FILE* confp)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	char filebuf[_FC_MAXSIZE_]	= {0};
	char* value;
	char* name;
	char* condition;
	int des_index	= -1;

	while(fgets(filebuf , _FC_MAXSIZE_ , confp))
	{
		Delete_Space(filebuf);
		value	= filebuf;
		if (filebuf[0] == '#')
			continue;
		if (filebuf[0] == '\n' || filebuf[0] == '\0')
		{
			printf("Edge Analyze Done !\n");
			break;
		}

		name	= strsplit_before(&value , "=");
		if (name == NULL)
		{
			printf("%d return \n" , __LINE__);
			return -1;
		}
		condition	= name;
		name	= strsplit_before(&condition , ".");
		if (name == NULL)
		{
			printf("%d return \n" , __LINE__);
			return -1;
		}
		des_index	= atoi(value);

		pFlow_Node pfn	= Find_Node_By_Name(name);
		if (!pfn)
		{
			printf("无此节点：%s\n" , name);
			continue;
		}
		if (Add_Edge_Des_By_Condition(pfn , condition , des_index))
		{
			printf("无此条件：%s\n" , condition);
			continue;
		}
		
	}
	return 0;
}

int Add_Edge_By_Condition(pFlow_Node node , char* condition , int des_index)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	pFlow_Arc new_arc	= (pFlow_Arc)malloc(sizeof(struct Flow_Arc));
	if (!new_arc)
	{
		perror("malloc failed ");
		return -1;
	}
	memset(new_arc , 0 , sizeof(struct Flow_Arc));

	new_arc->next	= NULL;
	new_arc->node_index	= des_index;
	strncpy(new_arc->Condition , condition , _FC_BUFFERSIZE_);
	if (des_index != -1)
	{
		ALGraph->arc_num ++;
		node->outdegree ++;
	}

	pFlow_Arc tmp_arc	= node->first_arc;
	if (tmp_arc)
	{
		while(tmp_arc && tmp_arc->next)
			tmp_arc	= tmp_arc->next;
		tmp_arc->next	= new_arc;
	}
	else
		node->first_arc	= new_arc;
	return 0;
}

int Add_Edge_Des_By_Name(pFlow_Node node , char* arc_name , int des_index)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	pFlow_Arc arc	= node->first_arc;
	int ret		= 1;
	while(arc)
	{
		if (strcmp(arc->ArcName , arc_name) == 0)
		{
			arc->node_index	= des_index;
			ret	= 0;
			break;
		}
		arc	= arc->next;
	}
	return ret;
}
int Add_Edge_Condition_By_Name(pFlow_Node node , char* arc_name , char* condition)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	pFlow_Arc arc	= node->first_arc;
	int ret		= 1;
	while(arc)
	{
		if (strcmp(arc->ArcName , arc_name) == 0)
		{
			strncpy(arc->Condition , condition , _FC_BUFFERSIZE_);
			ret	= 0;
			break;
		}
		arc	= arc->next;
	}
	return ret;
}

int Add_Edge_Des_By_Condition(pFlow_Node node , char* c_name , int des_index)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	pFlow_Arc arc	= node->first_arc;
	int retv	= 1;
	int condition_verify	= 0;
	while (arc)
	{
		if (strcmp(arc->Condition , c_name) == 0)
		{
			condition_verify	= 1;
			if (arc->node_index == -1)
			{
				for (int i = 0 ; i < ALGraph->node_num ; i ++)
				{
					if (ALGraph->FlowNodeArray[i]->number == des_index)
					{
#ifdef DEBUG
						printf("找到目的地点，是%s的第一个顶点%d\n" , c_name , i);
#endif
						arc->node_index	= i;
						break;
					}
				}
				retv	= 0;
				break;
			}
		}
		arc	= arc->next;
	}
	if (condition_verify && retv)		//条件满足但是未能添加目的地点，意味着同个条件将存在多个目的顶点
	{
		int node_index	= 0;
		for ( ; node_index < ALGraph->node_num ; node_index ++)
		{
			if (ALGraph->FlowNodeArray[node_index]->number == des_index)
			{
#ifdef DEBUG
				printf("找到目的地点，是%s的第多个顶点%d\n" , c_name , node_index);
#endif
				break;
			}
			
		}
		if (Add_Edge_By_Condition(node , c_name , node_index))
		{
#ifdef DEBUG
			printf("为%s条件增加多个目的顶点时失败！\n" , c_name);
#endif
			retv	= 1;
		}
		else
			retv	= 0;
	}
	return retv;
}

pFlow_Node Find_Node_By_Name(const char* node_name)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	pFlow_Node result	= NULL;
	int	node_num	= ALGraph->node_num;
	for (int i = 0 ; i < node_num ; i ++)
	{
		if (strcmp(ALGraph->FlowNodeArray[i]->FlowName , node_name) == 0)
		{
			result	= ALGraph->FlowNodeArray[i];
			break;
		}
	}
	return result;
}

pFlow_Arc  Find_Arc_By_Condition(pFlow_Node pfn , const char* condition)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	pFlow_Arc result	= NULL;
	pFlow_Arc tmp_arc	= pfn->first_arc;
	while (tmp_arc)
	{
		if (strcmp(tmp_arc->Condition , condition) == 0)
		{
			result	= tmp_arc;
			break;
		}
		tmp_arc	= tmp_arc->next;
	}
	return result;
}

void Delete_Space(char* buf)
{
	int len	= strlen(buf);
	for (len -= 1 ; len >= 0 ; len --)
	{
		if (isspace(buf[len]))
			buf[len] = '\0';
		else
			break;
	}
}

void Print_Map()
{
	pFlow_Node node	= NULL;
	int count	= 0;
	while (count < ALGraph->node_num)
	{
		node	= ALGraph->FlowNodeArray[count];
		printf("%s--->" , node->FlowName);
		pFlow_Arc arc	= node->first_arc;
		while (arc)
		{
			printf("%s(%s)--->" , ALGraph->FlowNodeArray[arc->node_index]->FlowName , arc->Condition);
			arc	= arc->next;
		}
		printf("NULL\n");
		count ++;
	}
}

int Check_Process_Flow(pFlow pfn , int number)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pfn)
		return 1;
#ifdef DEBUG
	printf("*************流程控制************\n");
	printf("当前流程：%s(0x%x)\n" , pfn->FlowName , ALGraph->FlowNodeArray[pfn->node_index]->number);
	printf("当前条件：%s\n" , pfn->Condition);
	printf("期望执行：0x%x\n" , number);
	printf("*********************************\n");
#endif
	int retv	= 1;
	pFlow_Arc arc	= ALGraph->FlowNodeArray[pfn->node_index]->first_arc;
	while (arc)
	{
		if (ALGraph->FlowNodeArray[arc->node_index]->number == number)
		{
			if (strcmp(pfn->Condition , arc->Condition) == 0)
			{
				retv	= 0;
				printf("流程匹配！\n");
				memset(pfn->Condition , 0 , _FC_BUFFERSIZE_);
				pfn->node_index	= arc->node_index;
				strcpy(pfn->FlowName , ALGraph->FlowNodeArray[arc->node_index]->FlowName);
				break;
			}
		}
		arc	= arc->next;
	}
	return retv;
}

int Init_FlowNode(pFlow pfn , int index)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pfn)
		return 1;
	index --;
	if (index < 0)
		index	= 0;
	pfn->node_index	= index;
	strncpy(pfn->FlowName , ALGraph->FlowNodeArray[index]->FlowName , _FC_BUFFERSIZE_);
	return 0;
}

int Get_FlowName_By_Index(int node_index , char* flowname)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (node_index >= ALGraph->node_num || node_index < 0)
		return 1;

	strcpy(flowname , ALGraph->FlowNodeArray[node_index]->FlowName);
	return 0;
}

int Get_Number_By_Index(int node_index)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (node_index >= ALGraph->node_num || node_index < 0)
		return -1;
	return ALGraph->FlowNodeArray[node_index]->number;
}
