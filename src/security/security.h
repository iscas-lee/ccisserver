#ifndef __CCIS_SECURITY_H__
#define __CCIS_SECURITY_H__
#include "../ccis.h"
#include "tpm/tpmapi.h"
#include "struct/security_struct.h"
#include "openssl/bio.h"
#include "openssl/buffer.h"
#include "openssl/pem.h"

#define PRIVATEKEY_PWD	"123123"

extern int	Decrypt_String_By_Server(char* pk_path , char* str , char* result , int len_in , int* len_out);			//服务端解密字符串
extern int	Encrypt_String_By_Server(EVP_PKEY* prikey , char* input , char* outpu , int* len_out);	//服务端加密字符串

extern int	Compute_String_MD5(const char* string , char* result);
extern int	Compute_File_MD5(const char* filepath , char* result);
extern int	Make_MD5_For_PBC(char *pcFlag, int iLen, char *pcSour, char *pcDest);

extern int	Base64_Encode(char *input , int len_in , char* output , int len_out);
extern int	Base64_Decode(char *input , int len_in , char* output , int len_out);

extern int	Store_New_Password(pRing ring);	//status=1表示服务端已获取新密码，未更新至客户端。reason=1表示由于过期自动触发
extern int	GetSha1FromCert(const char* certpath , char* result , int outlen);	//计算证书SHA1值
#endif
