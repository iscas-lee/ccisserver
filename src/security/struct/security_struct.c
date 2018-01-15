#include "security_struct.h"
#include "../../log/ccis_log.h"

int	Create_Ring_List();
int	Add_Ring_Node(pRing ring);
pRing	Find_Ring_Node(char* devsn);
pRing	Find_Ring_Node_By_IP(char* ip);
pRing	Find_Ring_Node_Accurate(const char* devsn , const char* ip , int fd);	//精确定位令牌环，必须传递fd值，devsn与ip可选
void	Free_Ring_Node(char* devsn);
void	Destroy_Ring_List();

int Create_Ring_List()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	Ring_List	= (pRLH)malloc(sizeof(struct Ring_List_Head));
	if (!Ring_List)
	{
		printf("malloc failed\n");
		retv	= 1;
		goto clean_up;
	}

	Ring_List->node_num	= 0;
	Ring_List->ring		= NULL;

clean_up:
	return retv;
}

int Add_Ring_Node(pRing ring)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!Ring_List || !ring)
	{
		return 1;
	}

	pRing pos	= Ring_List->ring;
	if (!pos)
	{
		Ring_List->ring	= ring;
		ring->next	= NULL;
		Ring_List->node_num ++;
		return 0;
	}

	while (pos)
	{
		if (strcmp(pos->devsn , ring->devsn) == 0)
		{
			strcpy(pos->tpmsn , ring->tpmsn);
			pos->tpm_key	= ring->tpm_key;
			pos->agent	= ring->agent;
			pos->verified	= ring->verified;
			strcpy(pos->pbcinfo.Orgid , ring->pbcinfo.Orgid);
			strcpy(pos->pbcinfo.User , ring->pbcinfo.User);
			strcpy(pos->pbcinfo.Pwd , ring->pbcinfo.Pwd);
			free(ring);
			return 0;
		}
		if (pos->next)
			pos	= pos->next;
		else
			break;
	}

	pos->next	= ring;
	ring->next	= NULL;
	Ring_List->node_num ++;

	return 0;
}

pRing Find_Ring_Node(char* devsn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!Ring_List || !devsn)
		return NULL;

	pRing result	= NULL;
	pRing pos	= Ring_List->ring;

	while (pos)
	{
		if (!strcmp(pos->devsn , devsn))
		{
			result	= pos;
			break;
		}
		pos	= pos->next;
	}

	return result;
}

pRing Find_Ring_Node_By_IP(char* ip)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!Ring_List || !ip)
		return NULL;

	pRing result	= NULL;
	pRing pos	= Ring_List->ring;

	while (pos)
	{
		if (!strcmp(pos->ip , ip))
		{
			result	= pos;
			break;
		}
		pos	= pos->next;
	}

	return result;
}

pRing Find_Ring_Node_Accurate(const char* devsn , const char* ip , int fd)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	pRing result	= NULL;
	if (!Ring_List || fd <= 0)
		goto clean_up;

	pRing pos	= Ring_List->ring;
	while (pos)
	{
		if (pos->fd == fd)
		{
			if (devsn)
				if (strcmp(devsn , pos->devsn))
				{
					pos	= pos->next;
					continue;
				}
			if (ip)
				if (strcmp(ip , pos->ip))
				{
					pos	= pos->next;
					continue;
				}
			result	= pos;
			break;
		}
		pos	= pos->next;
	}

clean_up:
	return result;
}

void Free_Ring_Node(char* devsn)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!Ring_List || !devsn)
		return;
	pRing prev	= Ring_List->ring;
	pRing pos	= NULL;
	if (!prev)
		return;
	
	if (!strcmp(prev->devsn , devsn))
	{
		Ring_List->ring	= prev->next;
		if (prev->tpm_key)
		{
			EVP_PKEY_free(prev->tpm_key);
		}
		free(prev);
		Ring_List->node_num --;
		return;
	}

	pos	= prev->next;
	while(pos)
	{
		if (strcmp(pos->devsn , devsn) == 0)
		{
			prev->next	= pos->next;
			if (pos->tpm_key)
			{
				EVP_PKEY_free(pos->tpm_key);
			}
			free(pos);
			Ring_List->node_num --;
			return;
		}
		prev	= pos;
		pos	= prev->next;
	}
	return;
}

void Destroy_Ring_List()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!Ring_List)
		return;
	pRing ring	= Ring_List->ring;
	while(ring)
	{
		Ring_List->ring	= ring->next;
		if (ring->tpm_key)
		{
			EVP_PKEY_free(ring->tpm_key);
		}
		free(ring);
		ring	= Ring_List->ring;
	}

	free(Ring_List);
	return;
}
