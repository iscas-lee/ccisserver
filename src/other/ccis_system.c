#include "ccis_system.h"
#include "../ccis.h"
#include "../log/ccis_log.h"
#include <stdlib.h>

unsigned long	GetMemUsed_KB();

unsigned long GetMemUsed_KB()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	char memfile[CCIS_PATHLEN];
	sprintf(memfile , "/proc/%d/status" , getpid());
	FILE* m_fp	= fopen(memfile , "r");
	if (!m_fp)
	{
		ccis_log_emerg("进程状态文件%s无法打开！" , memfile);
		retv	= 0;
		goto clean_up;
	}
	char mem_buffer[CCIS_MAXSIZE];
	while (fgets(mem_buffer , CCIS_MAXSIZE , m_fp))
	{
		if (strncasecmp(mem_buffer , "VmHWM:" , 6) == 0)
		{
			char* pos	= strchr(mem_buffer , ':');
			if (!pos)
			{
				ccis_log_emerg("Unable To Locate VmHWM Status！");
				retv	= 0;
				fclose(m_fp);
				goto clean_up;
			}
			pos ++;
			retv	= atol(pos);
			break;
		}
	}
clean_up:
	if (m_fp)
		fclose(m_fp);
	return retv;
}
