#ifndef UPLOAD_AGENT_H_INCLUDED
#define UPLOAD_AGENT_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include "../pbc.h"
#include "../../struct/server_struct.h"

#define MAX_BUFF_LEN 1048576 /*1M*/
#define FROMCHARSET "UTF-8"
#define TOCHARSET "UTF-8"
#define MAX_PICTURE_SIZE        1048576
#define MIDSIZE 128

struct Memorystruct 
{
        char *memory;
        size_t size;
};

extern int check_file_existed(char *filename);
extern int get_file_size(char *filename);
extern int http_post_file(const char* orgname , const char *idfilename, const char* checkfilename, const char* visfilename);
extern int upload_picture(const char* orgname , const char* idfilename, const char* checkfilename, const char* visfilename);
//extern static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
extern int upload_log_agent(pSearch_Log log_node , const char* orgname);
extern int Url_Encode(const char* str, const int strSize, char* result, const int resultSize);
extern void	Upload_CU_Thread(pSearch_Log log_node);

#endif 


