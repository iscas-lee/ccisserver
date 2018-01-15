#ifndef __CCIS_SSL_H__
#define __CCIS_SSL_H__
#include "../../ccis.h"
#include "openssl/bio.h"
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define	PRIVATE_KEY_PWD		"123123"

SSL_CTX*	pstCtx;
SSL_CTX*	clientCtx;
int	s_server_verify;
int	s_client_verify;

extern int	Read_Msg(SSL* ssl , char* buffer , int bufSize);
extern int	Write_Msg(SSL* ssl , const void* buffer , int bufSize);
extern int	SSL_Verify_Client_Cert(SSL* ssl);
extern int 	Init_SSL();
extern void	Close_SSL();
#endif
