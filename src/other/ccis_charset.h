#ifndef __CCIS_CHARSET_H__
#define __CCIS_CHARSET_H__

#include "iconv.h"

extern int	String_Code_Convert(char *pcFromCharset, char *pcToCharset, char *pcInbuf, size_t uiInlen, char *pcOutbuf, size_t uiOutlen);
extern int	File_Code_Convert(char *pcFromCharset, char *pcToCharset, char *pcFileName, char **ppcOutMem);

#endif
