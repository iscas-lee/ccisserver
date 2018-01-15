#ifndef __CCIS_COMMON_H__
#define __CCIS_COMMON_H__

extern int	Write_File(const char* filepath , char* buffer , int bufLen , int status);
extern int	Get_Filepath(int type , char* filepath , const char* idnum , const char* querysn);
extern int	Get_Homepath(char* result);

#endif
