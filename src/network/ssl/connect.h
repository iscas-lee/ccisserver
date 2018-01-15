#ifndef __CCIS_SSL_CONN_H__
#define __CCIS_SSL_CONN_H__
#include "../network.h"

extern int	SSL_HandShake(Channel* ch);
extern int	SSL_Connect(int* fd , SSL* ssl);

#endif
