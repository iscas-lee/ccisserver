#include "upload_agent.h"
#include "../../../log/ccis_log.h"
#include "../../../other/ccis_string.h"
#include "../../../type.h"
#include <errno.h>

int	check_file_existed(char *filename);
int	http_post_file(const char* orgname , const char *idfilename, const char *checkfilename, const char *visfilename);
int	upload_picture(const char* orgname , const char* idfilename, const char* checkfilename, const char* visfilename);
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
int	upload_log_agent(pSearch_Log log_node , const char* orgname);
int	Url_Encode(const char* str, const int strSize, char* result, const int resultSize);
void	Upload_CU_Thread(pSearch_Log log_node);

int check_file_existed(char *filename)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	struct stat st;
	return (stat( filename, &st )==0 && S_ISREG(st.st_mode));
}

int get_file_size(char *filename)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int file_len = 0;
	int fd = 0;

	fd = open(filename, O_RDONLY);
	if(fd < 0)
	{
		perror("open");
		exit(-1);
	}

	file_len = lseek(fd, 0, SEEK_END);
	if(file_len < 0)
	{
		perror("lseek");
		exit(-1);
	}

	return file_len;
}

int http_post_file(const char* orgname , const char *idfilename, const char *checkfilename, const char *visfilename)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	CURL *curl = NULL;
	CURLcode res;

	struct curl_httppost *post=NULL;
	struct curl_httppost *last=NULL;

	//获取系统当前时间
	time_t nowtime;
	struct tm *timeinfo;
	char ltime[64] = {0};
	time( &nowtime );
	timeinfo = localtime( &nowtime );
	int year, month, day;
	year = timeinfo->tm_year + 1900;
	month = timeinfo->tm_mon + 1;
	day = timeinfo->tm_mday;
	sprintf(ltime,"%04d%02d%02d", year, month, day);
	printf("ltime:%s\n", ltime);
	//获取系统当前时间结束


	//编码转换
	char fromsite[MIDSIZE];
	strcpy(fromsite , orgname);
	unsigned int fromsitelen = strlen(fromsite);
	char enfromsite[MIDSIZE] = {0};
	Url_Encode(fromsite, fromsitelen, enfromsite, MIDSIZE);
	//编码转换结束

	//此处如果内容为汉字，需要进行编码格式转换
	curl_formadd(&post, &last,
			CURLFORM_COPYNAME, "fromSite",
			CURLFORM_COPYCONTENTS, enfromsite,
			CURLFORM_END);
	curl_formadd(&post, &last,
			CURLFORM_COPYNAME, "time",
			CURLFORM_COPYCONTENTS, ltime,
			CURLFORM_END);
	/* Add simple file section */
	if (idfilename)
	{
		if( curl_formadd(&post, &last, CURLFORM_COPYNAME, "upload",
					CURLFORM_FILE, idfilename, CURLFORM_END) != 0)
		{
			fprintf(stderr, "curl_formadd error.\n");
			goto out;
		}
	}

	if (checkfilename)
	{
		if( curl_formadd(&post, &last, CURLFORM_COPYNAME, "upload",
					CURLFORM_FILE, checkfilename, CURLFORM_END) != 0)
		{
			fprintf(stderr, "curl_formadd error.\n");
			goto out;
		}
	}

	if (visfilename)
	{
		if( curl_formadd(&post, &last, CURLFORM_COPYNAME, "upload",
					CURLFORM_FILE, visfilename, CURLFORM_END) != 0)
		{
			fprintf(stderr, "curl_formadd error.\n");
			goto out;
		}
	}

	/* Fill in the submit field too, even if this is rarely needed */
	curl = curl_easy_init();
	if(curl == NULL)
	{
		fprintf(stderr, "curl_easy_init() error.\n");
		goto out;
	}

	curl_easy_setopt(curl, CURLOPT_HEADER, 1);
	curl_easy_setopt(curl, CURLOPT_URL, pic_upload_url); /*Set URL*/
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
	int timeout = 5;
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

	res = curl_easy_perform(curl);
	if(res != CURLE_OK)
	{
		fprintf(stderr, "curl_easy_perform[%d] error.\n", res);
		curl_easy_cleanup(curl);
		goto out;
	}

	printf("res:%d\n", res);

	curl_easy_cleanup(curl);
out:
	curl_formfree(post);
	return 0;
}

int upload_picture(const char* orgname , const char* idfilename, const char* checkfilename, const char* visfilename)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	//对身份证照片检测
	if (!idfilename)
		return -1;

	int retv        = 0;
	if (access(idfilename , R_OK))
	{
		retv    = -1;
		ccis_log_err("无法上传照片%s:文件不存在", idfilename);
		idfilename	= NULL;
	}
	else if (get_file_size(idfilename) >= MAX_PICTURE_SIZE)
	{
		retv    = -1;
		ccis_log_err("无法上传照片%s:图片过大！", idfilename);
		idfilename	= NULL;
	}

	//对联网核查照片进行检测
	if (!checkfilename)
		return -1;


	if (access(checkfilename , R_OK))
	{
		retv    = -1;
		ccis_log_err("无法上传照片%s:文件不存在!", checkfilename);
		checkfilename	= NULL;
	}
	else if (get_file_size(checkfilename) >= MAX_PICTURE_SIZE)
	{
		retv    = -1;
		ccis_log_err("无法上传照片%s:文件不存在!", checkfilename);
		checkfilename	= NULL;
	}

	//对现场照片进行核查
	if (!visfilename)
		return -1;

	if (access(visfilename , R_OK))
	{
		retv    = -1;
		ccis_log_err("无法上传照片%s:文件不存在!", visfilename);
		visfilename	= NULL;
	}
	else if (get_file_size(visfilename) >= MAX_PICTURE_SIZE)
	{
		retv    = -1;
		ccis_log_err("无法上传照片%s:图片过大!", visfilename);
		visfilename	= NULL;
	}

	//调用curl对照片进行上传
	if (http_post_file(orgname , idfilename, checkfilename, visfilename))
	{
		retv    = 1;
		ccis_log_err("照片上传失败！");
	}

clean_up:
	return retv;
}


static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->pcBuf = realloc(mem->pcBuf, mem->uiSize + realsize + 1); 
	if(mem->pcBuf == NULL) 
	{
		/* out of memory! */ 
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}
	memcpy(&(mem->pcBuf[mem->uiSize]), contents, realsize);
	mem->uiSize += realsize;
	mem->pcBuf[mem->uiSize] = 0;

	return realsize;
}

int upload_log_agent(pSearch_Log log_node , const char* orgname)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	char getquerysource[] = "1";          //7
	char getqueryresult[] = "0";          //8
	//char getstepinfo[] = "0";             //11
	//char getscore[] = "0.966";            //12
	char getcertvalid[] = "1";            //17
	char getqueryreason[] = "04";         //19
	char getqueryver[] = "24";            //20
	char getisdel[]="1";          //23
	char getcheckmanualinfo[] = "null";   //24
	char getotherid[] = "-1";             //25
	char getreceivablefee[] = "10";       //28	应收金额
	char getwithdrawflag[] = "1";         //30
	//char getdissentid[] = "null";         //31
	char getreceivedfee[3] = "0";         //32	本次投入金额
	char getchargeagainst[3] = "0";        //33	上次收费金额
	char getchargeagainst2[3] = "0";       //34	已冲借金额
	char getchargemanualtakeoff[] = "0";  //35	人工找出金额
	char gettakeoffid[] = "null";         //36
	//char getrecievedtotal[]="10";   //此值不能为null37
	char getcardno[] = "null";            //38

	char contents[2048] = {0};
	//ada-add
	char* queryid = log_node->querysn;
	while (*queryid ++ == '0');
	queryid --;
	strcpy(contents, queryid);
	//ada-end
	strcat(contents,"|");
	strcat(contents, log_node->idnum);
	strcat(contents,"|");
	strcat(contents, log_node->idname);
	strcat(contents,"|");
	char querydate[64] = {0};
	strcpy(querydate , log_node->querydt);
	String_Replace(querydate , '/' , '-' , 0 , 0);
	strcat(contents, querydate);
	strcat(contents,"|");
	//ada-add
	//获取系统当前时间
	char curldata[MIDSIZE] = {0};
	char idphotopath[MIDSIZE] = {0};
	char livephotopath[MIDSIZE] = {0};

	time_t datatime;
	struct tm *curltime;
	datatime = time(NULL);
	curltime = localtime(&datatime);
	sprintf(curldata, "%04d%02d%02d", curltime->tm_year + 1900, curltime->tm_mon + 1, curltime->tm_mday);
	printf("curldata:%s\n", curldata);
	//获取完成

	//拼接现场照片存储路径
	sprintf(idphotopath, "/root/%s/%s.bmp", curldata, log_node->idnum);
	sprintf(livephotopath, "/root/%s/%s.jpg", curldata, log_node->idnum);
	strcat(contents, idphotopath);
	strcat(contents, "|");
	strcat(contents, livephotopath);   
	//ada-add-end

	/*ada-teat
	  if (!String_Delete_Char(log_node->idpic_path , '-' , 0 , 0))
	  {

	  strcat(contents, log_node->idpic_path);
	  }
	  else
	  {
	  ccis_log_alert("[%s:%d]String_Delete_Char Failed !" , __FUNCTION__ , __LINE__);
	  return 1;
	  }
	  strcat(contents,"|");
	  if (!String_Delete_Char(log_node->sppic_path , '-' , 0 , 0))
	  {
	  strcat(contents, log_node->sppic_path);
	  }
	  else
	  {
	  ccis_log_alert("[%s:%d]String_Delete_Char Failed !" , __FUNCTION__ , __LINE__);
	  return 1;
	  }
	  add-test-end*/
	strcat(contents,"|");
	strcat(contents, getquerysource);
	strcat(contents,"|");
	strcat(contents, getqueryresult);
	strcat(contents,"|");
	strcat(contents, querydate);
	strcat(contents,"|");
	strcat(contents, log_node->phonenum);
	strcat(contents,"|");
	//此处是否需要判断？0表示成功查询，１表示读卡成功用户自己取消，２身份核查系统异常，３身份核查结果失败，４照片对比失败，５照片不清楚，６个人征信系统异常
	printf("falres = 0x%x\n" , log_node->falres);
	if (log_node->falres == CCIS_PROC_ALL_DONE)
	{
		strcat(contents , "0");
	}
	else if ((log_node->falres & 0x000F) == 0)
	{
		strcat(contents , "1");
	}
	else if ((log_node->falres & 0x00F0) == CCIS_PROC_IDCARD_CHECK)
	{
		strcat(contents , "3");
	}
	else if ((log_node->falres & 0x00F0) == (CCIS_PROC_IDCARD_CHECK | CCIS_PROC_FACE_MATCH))
	{
		strcat(contents , "4");
	}
	else
		strcat(contents , "6");
	strcat(contents,"|");
	char* score	= malloc(5);
	if (unlikely(!score))
		strcat(contents, "0.00");
	else
	{
		sprintf(score , "%d" , (int)(log_node->rctrscr*100));
		strcat(contents , score);
		free(score);
	}
	strcat(contents,"|");
	strcat(contents, log_node->idsex);
	strcat(contents,"|");
	strcat(contents, log_node->nation);
	strcat(contents,"|");
	strcat(contents, log_node->issauth);
	strcat(contents,"|");
	strcat(contents, log_node->birthdt);
	strcat(contents,"|");
	strcat(contents, getcertvalid);
	strcat(contents,"|");
	strcat(contents, log_node->addr);
	strcat(contents,"|");
	strcat(contents, getqueryreason);
	strcat(contents,"|");
	strcat(contents, log_node->report_type);
	strcat(contents,"|");
	//下面参数是由管理网站的查询主机设置决定的，所以可能要进行判断
	strcat(contents, log_node->devname);
	//strcat(contents, "西红门测试102");
	strcat(contents,"|");
	strcat(contents, log_node->repno);
	strcat(contents,"|");
	strcat(contents, getisdel);
	strcat(contents,"|");
	strcat(contents, getcheckmanualinfo);
	strcat(contents,"|");
	strcat(contents, getotherid);
	strcat(contents,"|");
	strcat(contents, log_node->prtsgn);
	strcat(contents,"|");
	if (log_node->chgnum != 0)
		strcat(contents, "1");
	else
		strcat(contents , "0");
	strcat(contents,"|");
	strcat(contents, getreceivablefee);
	strcat(contents,"|");
	strcat(contents, log_node->chgno);
	strcat(contents,"|");
	strcat(contents, getwithdrawflag);
	strcat(contents,"|");
	strcat(contents, log_node->disid);
	strcat(contents,"|");
	sprintf(getreceivedfee , "%d" , log_node->chgnum - log_node->lastchgnum);
	strcat(contents, getreceivedfee);
	strcat(contents,"|");
	sprintf(getchargeagainst , "%d" , log_node->lastchgnum);
	strcat(contents, getchargeagainst);
	strcat(contents,"|");
	sprintf(getchargeagainst2 , "%d" , log_node->lastchgnum);
	strcat(contents, getchargeagainst2);
	strcat(contents,"|");
	strcat(contents, getchargemanualtakeoff);
	strcat(contents,"|");
	strcat(contents, gettakeoffid);
	strcat(contents,"|");
	//此处是已收取的费用
	char chgnum[3];
	sprintf(chgnum , "%d" , log_node->chgnum);
	strcat(contents, chgnum);
	strcat(contents,"|");
	strcat(contents, getcardno);
	printf("contents:%s\n contentslength:%d\n", contents, strlen(contents));
	CURL *curl=NULL;
	CURLcode res;
	//      curl_socket_t sockfd;    //ada-->test
	struct Memorystruct chunk;
	chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
	chunk.size = 0;    /* no data at this point */

	//struct curl_httppost *post=NULL;
	struct curl_slist *headerlist=NULL;

	//头部分来源编码转换+字符串拼接
	char fromsite[MIDSIZE];	//此处站点来源也是根据管理网站配置填写，是否需要写入配置文件？
	strcpy(fromsite , orgname);
	unsigned int fromsitelen = strlen(fromsite);
	char enfromsite[MIDSIZE] = {0};
	Url_Encode(fromsite, fromsitelen, enfromsite, MIDSIZE);
	char site[MIDSIZE] = {0};
	sprintf(site, "fromSite:%s",enfromsite);
	//转换结束


	headerlist=curl_slist_append(headerlist, "Content-Type:text/plain");
	headerlist=curl_slist_append(headerlist, "Accept-Charset:utf-8");
	headerlist=curl_slist_append(headerlist, "contentType:utf-8");
	headerlist=curl_slist_append(headerlist, site);
	headerlist=curl_slist_append(headerlist, "path:/root");

	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, log_upload_url);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
		//curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
		curl_easy_setopt(curl, CURLOPT_POST, 1);    //ada test
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);    //ada test
		curl_easy_setopt(curl, CURLOPT_HEADER, 0);    //ada test
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		//              curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);

		//              curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
		//      curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
		/* Now specify the POST data */

		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, contents);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

		/* we pass our 'chunk' struct to the callback function */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
		//ada--->test end



		/* Perform the request, res will get the return code */
		printf("begin!");
		res = curl_easy_perform(curl);
		if(res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));
			puts("");
		}
		printf("end!");
#ifdef DEBUG
		if ( strcmp(chunk.memory, "-1") == 0 ) 
		{
			printf("\n**********************\n");
			printf("the log contents is wrong chunk.memory:%s\n", chunk.memory);
			printf("*************************\n");
		}
		else if (strstr(chunk.memory, "html"))
		{
			printf("\n**********************\n");
			printf("the headlist wrong chunk.memory:%s\n", chunk.memory);
			printf("*************************\n");
		}
		else
		{
			//对方服务器返回的插入数据库id,本地是否需要保存
			printf("\n**********************\n");
			printf("upload sucessful chunk.memory:%s\n", chunk.memory);
			printf("*************************\n");

		}
#endif
	}



	curl_easy_cleanup(curl);

	//      curl_global_cleanup();
	return 0;


}

int Url_Encode(const char* str, const int strSize, char* result, const int resultSize)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int i;
	int j = 0;//for result index
	char ch;

	if ((str==NULL) || (result==NULL) || (strSize<=0) || (resultSize<=0)) 
	{
		return 0;
	}

	for ( i=0; (i<strSize)&&(j<resultSize); ++i) 
	{
		ch = str[i];
		if (((ch>='A') && (ch<'Z')) ||
				((ch>='a') && (ch<'z')) ||
				((ch>='0') && (ch<'9'))) {
			result[j++] = ch; 
		} else if (ch == ' ') {
			result[j++] = '+';
		} else if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
			result[j++] = ch;
		} else {
			if (j+3 < resultSize) {
				sprintf(result+j, "%%%02X", (unsigned char)ch);
				j += 3;
			} else {
				return 0;
			}
		}
	}

	result[j] = '\0';
	return j;

}

void Upload_CU_Thread(pSearch_Log log_node)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!log_node)
	{
		ccis_log_err("无法向代理系统上传查询信息：参数错误！");
		return ;
	}

#ifdef DEBUG
	printf("***************begin upload log to agent************************\n");
	printf("log_node->querysn:%s\n", log_node->querysn);
	printf("log_node->idnum:%s\n", log_node->idnum);
#endif
	if (upload_log_agent(log_node , log_node->orgname))
	{
		ccis_log_err("[%s]查询日志上传失败！" , log_node->querysn);
	}
#ifdef DEBUG
	printf("****************end upload log to agent***********************************************\n");
	printf("****************begin upload picture to agent***********************************************\n");
#endif
	if(upload_picture(log_node->orgname , log_node->idpic_path , log_node->authpic_path , log_node->sppic_path))
	{
		ccis_log_err("[%s]照片上传失败！身份证照片:%s;公安部照片:%s;现场照片:%s" , log_node->querysn , log_node->idpic_path , log_node->authpic_path , log_node->sppic_path);
	}
#ifdef DEBUG
	printf("****************end upload picture to agent***********************************************\n");
#endif

	if (log_node)
		free(log_node);
	return;
}
