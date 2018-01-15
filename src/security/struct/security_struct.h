#ifndef __CCIS_SEC_ST_H__
#define __CCIS_SEC_ST_H__
#include "../../server/pbc/pbc.h"
#include "../../client/client_login.h"
#include "../../network/network.h"
#include <openssl/evp.h>

struct Ring{
	char devsn[DEVSN_LEN];
	char tpmsn[TPMSN_LEN];
	char ukeysn[UKEYSN_LEN];
	char ip[CCIS_IP_LEN];
	char zoneid[5];
	EVP_PKEY* tpm_key;		//取出RSA：tpm_key->pkey.rsa
	bool tpm_regsign;
	bool ukey_regsign;
	bool agent;
	unsigned int verified;

	int fd;

	pHardSN pstHard;

	PBC pbcinfo;

	struct Ring* next;
};
typedef struct Ring* pRing;

/****************令牌环链表头****************/
struct Ring_List_Head{
	int node_num;
	pRing ring;
};
typedef struct Ring_List_Head* pRLH;

pRLH Ring_List;
/********************************************/

extern int	Create_Ring_List();
extern int	Add_Ring_Node(pRing ring);
extern pRing	Find_Ring_Node(char* devsn);
extern pRing	Find_Ring_Node_By_IP(char* ip);
extern pRing	Find_Ring_Node_Accurate(const char* devsn , const char* ip , int fd);	//精确定位令牌环，必须传递fd值，devsn与ip可选
extern void	Free_Ring_Node(char* devsn);
extern void	Destroy_Ring_List();

#endif
