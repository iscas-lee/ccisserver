#include "ccis_charset.h"
#include "../log/ccis_log.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int	String_Code_Convert(char *pcFromCharset, char *pcToCharset, char *pcInbuf, size_t uiInlen, char *pcOutbuf, size_t uiOutlen);
int	File_Code_Convert(char *pcFromCharset, char *pcToCharset, char *pcFileName, char **ppcOutMem);

int String_Code_Convert(char *pcFromCharset, char *pcToCharset, char *pcInbuf, size_t uiInlen, char *pcOutbuf, size_t uiOutlen)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	iconv_t	stIconv;
	char **ppcIn	= &pcInbuf;
	char **ppcOut	= &pcOutbuf;

	if (!pcFromCharset || !pcToCharset || !pcInbuf || !pcOutbuf)
	{
		retv	= -1;
		goto clean_up;
	}

	stIconv	= iconv_open(pcToCharset , pcFromCharset);
	if (!stIconv)
	{
		perror("Create iconv_t failed ");
		retv	= -1;
		goto clean_up;
	}

	memset(pcOutbuf , 0 , uiOutlen);

	if (iconv(stIconv , ppcIn , &uiInlen , ppcOut , &uiOutlen) == -1)
	{
		retv	= 1;
		perror("Charset Convert Failed ");
		goto clean_up;
	}

clean_up:
	if (stIconv)
		iconv_close(stIconv);
	return retv;
	return retv;
}

int File_Code_Convert(char *pcFromCharset, char *pcToCharset, char *pcFileName, char **ppcOutMem)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	int iconvret	= 0;
	int fd		= 0;
	char* pcMMapBuf	= NULL;

	struct stat stStatBuf;
	if (!pcFromCharset || !pcToCharset || !pcFileName)
	{
		retv	= -1;
		goto clean_up;
	}

	if (stat(pcFileName , &stStatBuf) == -1)
	{
		perror("Cannot Get File Status ");
		retv	= -1;
		goto clean_up;
	}

	fd	= open(pcFileName , O_RDONLY);
	if (fd == -1)
	{
		fd	= 0;
		perror("Open File Failed ");
		retv	= -2;
		goto clean_up;
	}

	pcMMapBuf	= (char*)mmap(NULL , stStatBuf.st_size , PROT_READ , MAP_PRIVATE , fd , 0);
	if (pcMMapBuf == MAP_FAILED)
	{
		perror("Failed To MMap ");
		retv	= -3;
		goto clean_up;
	}

	*ppcOutMem	= (char*)malloc(stStatBuf.st_size * 2 + 1);
	memset(*ppcOutMem , 0 , stStatBuf.st_size * 2 + 1);

	iconvret	= String_Code_Convert(pcFromCharset , pcToCharset , pcMMapBuf , stStatBuf.st_size , *ppcOutMem , stStatBuf.st_size * 2);
	if (iconvret)
	{
		printf("Code Convert Failed\n");
		retv	= -4;
		goto clean_up;
	}

clean_up:
	if (pcMMapBuf)
		munmap(pcMMapBuf , stStatBuf.st_size);
	if (fd)
		close(fd);
	return retv;
}
