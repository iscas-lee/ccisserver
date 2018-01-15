#ifndef __CCIS_GLOBAL_H__
#define __CCIS_GLOBAL_H__
#include "flow_control.h"
#include "../server/struct/server_struct.h"
#include "../security/security.h"
#include "../ccis.h"
#include "../network/network.h"

extern int	Business_Schedule(pSearch_Log log_node , pRing ring , BSNMsg msg , Channel* ch);
extern int	Client_Login_Schedule(BSNMsg msg , Channel* ch);
extern int	Global_Schedule(Channel* ch);
extern int	handleRead(Channel* ch);
extern int	handleWrite(Channel* ch);
extern int	Unexpected_Hup(Channel* ch);
#endif
