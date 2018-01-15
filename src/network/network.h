#ifndef __CCIS_NT_H__
#define __CCIS_NT_H__
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "ssl/ssl.h"
#include "../ccis.h"
#include "unistd.h"
#include "fcntl.h"
#include "openssl/bio.h"
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define CCIS_IP_LEN	32

#define	CCIS_NONBLOCK	1
#define	CCIS_BLOCK	0

typedef struct{
	int fd;
	SSL *ssl;
	int sslConnected;
	int tcpConnected;
	int events;
	char r_ip[CCIS_IP_LEN];
}Channel;

typedef struct{
	int type;
	int control;
	unsigned int seq;
	unsigned int ack;
	int errcode;
	int status;
	int bodyLen;
}PackageHead;

typedef struct{
	char devsn[DEVSN_LEN];
	char querysn[QUERYSN_LEN];
	char reseve[CCIS_SMALLSIZE];
	int bufLen;
}PackageBody;

typedef struct{
	PackageHead head;
	PackageBody body;
}CTLMsg;

typedef struct{
	PackageHead head;
	PackageBody body;
	char buffer[CCIS_MAXSIZE];
}BSNMsg;

extern Channel*	Channel_New();
extern int	Create_Socket(const char* ip , int port , int domain , int type , int proto , int backlog , int nonblock);
extern void	Close_Socket(int fd);
extern int	Set_ChannelSock(Channel* ch , int fd , int events);
extern Channel*	Accept_Connection(int source_fd);
extern void	Free_Channel(Channel* ch);
extern int	Connect_Server(const char* ip , int port , int nonblock);
extern int	Set_NonBlock(int fd , int nonblock);

#endif
