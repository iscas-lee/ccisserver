#ifndef __CCIS_COMPRESS_H__
#define __CCIS_COMPRESS_H__

#include "lz4frame.h"

#define LZ4_BUF_SIZE	(16*1024)
#define LZ4_HEADER_SIZE	19
#define LZ4_FOOTER_SIZE	4

extern int Compress_File(const char* in , const char* out);

#endif
