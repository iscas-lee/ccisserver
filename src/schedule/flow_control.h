#ifndef __FLOW_CONTROL__
#define __FLOW_CONTROL__
#include "stdio.h"
#include "math.h"
#include "unistd.h"
#include <string.h>
#include "stdlib.h"
#include "ctype.h"

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#define _FC_MAXSIZE_	1024
#define _FC_BUFFERSIZE_	64

#define _FC_NODE_HEAD_	"[FLOW_NODE]"
#define _FC_ARC_HEAD_	"[FLOW_ARC]"
#define _FC_MARCO_HEAD_	"[MARCO]"

#define _FC_NODE_ID_	"id"
#define _FC_NODE_NAME_	"name"
#define _FC_NODE_CONDITION_	"condition"

#define _FC_ARC_PATH_	"path"

struct Flow_Arc{
	char ArcName[_FC_BUFFERSIZE_];
	int node_index;			//终点流程节点的序号
	char Condition[_FC_BUFFERSIZE_];

	struct Flow_Arc* next;		//下一条边
	
};

typedef struct Flow_Arc* pFlow_Arc;

struct Flow_Node{
	int number;
	char FlowName[_FC_BUFFERSIZE_];
	int outdegree;			//出度
	
	struct Flow_Arc* first_arc;	
};

typedef struct Flow_Node* pFlow_Node;


struct ALG{					//图结构体
	pFlow_Node* FlowNodeArray;		//流程节点数组，双重指针
	int node_num;				//节点数量
	int arc_num;				//边数量
};

typedef struct ALG* pALG;

struct Flow{
	char FlowName[_FC_BUFFERSIZE_];
	int node_index;
	char Condition[_FC_BUFFERSIZE_];
};

typedef struct Flow* pFlow;

pALG ALGraph;

extern int	Create_FlowMap(const char* file_path);
extern void	Destroy_FlowMap();
extern int	Check_Process_Flow(pFlow pfn , int number);
extern int	Init_FlowNode(pFlow pfn , int index);
extern int	Get_Index_By_Name(const char* flowname);
extern int	Get_FlowName_By_Index(int node_index , char* flowname);
extern int	Get_Number_By_Index(int node_index);				//出错时返回-1

#endif
