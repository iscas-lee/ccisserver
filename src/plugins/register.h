#ifndef __CCIS_UKEYREG_H__
#define __CCIS_UKEYREG_H__
#include "../ccis.h"
#include "../type.h"
#include "../network/network.h"
#include "../database/dbquery.h"
#include "../security/security.h"

typedef struct{
	Channel* ch;
	const EVP_PKEY* tpm_key;
	char filepath[CCIS_PATHLEN];
	char devsn[DEVSN_LEN];
	char ukeysn[UKEYSN_LEN];
}UKRegArgs;

typedef struct{
	Channel* ch;
	char filepath[CCIS_PATHLEN];
	char devsn[DEVSN_LEN];
	char* tpmsn;
}TPMRegArgs;

char*	ca_regaddr;
char*	cadb_ip;
int	cadb_port;
char*	cadb_user;
char*	cadb_passwd;
char*	cadb_tablename;

extern void	Ukey_Register(BSNMsg msg , Channel* ch , EVP_PKEY* tpm_key);
extern int	Update_UR_Sign(const char* ukeysn , int sign);
extern void	TPM_Register(BSNMsg msg , Channel* ch , char* tpmsn);
extern int	Update_TPM_Sign(const char* devsn , int sign);

#endif
