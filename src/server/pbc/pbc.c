#include "pbc.h"
#include "../../security/security.h"
#include "../../other/ccis_common.h"
#include "../../other/ccis_charset.h"
#include "../../other/ccis_time.h"
#include "../../database/dbquery.h"
#include "../../log/ccis_log.h"
#include <sys/stat.h>

int	Connection_To_PBC(char *pcUserId, char *pcUserPwd, bool bAgtSign, char **ppNewPwd);
int	Login_Credit_Center(CURL *pstCurl, char *pcUserId, char *pcUserPwd, char **ppNewPwd);
int	Login_Credit_Agent(CURL *pstCurl, char *pcUserId, char *pcUserPwd);
bool	Check_Login_Status(CURL *pstCurl, char *pcUserId);
CURLcode	Do_Http_Post(CURL *pstCurl, char *pcUrl, char *pcPara, size_t (*pfWritFunc)(void *, size_t, size_t, void *), void *pvRelt);
int	Auto_Change_Password(CURL *pstCurl, char *pcUserId, char *pcUserPwd, char *pcNewPwd, bool bAgtSign);
size_t	Write_To_File_For_PBC(void *buffer, size_t size, size_t nmemb, void *userp);
size_t	Write_Memory(void *buffer, size_t size, size_t nmemb, void *userp);
int	Generate_Pwd(int iType, int iLen, char *pcNewPwd);
int	Download_Police_Photo(char *pcUserId, char *pcUserPwd,char **new_pwd,struct UserInfoStruct *pstUserInfo, char *pcPolicePhoto, bool bAgtSign);
CURLcode	Do_Http_Get(CURL *pstCurl, char *pcUrl, size_t (*pfWritFunc)(void *, size_t, size_t, void *), void *pvRelt);
int	Get_Charge_Information(char *pcUserId, char *(*apcFeeRet)[4], struct UserInfoStruct *pstUserInfo, bool bAgtSign);
int	Download_Report_Free(const char* querysn , char *pcUserId, char* pcUserPwd, char **new_pwd, struct UserInfoStruct *pstUserInfo,char *pcReportNo,char *pcReportFile, char **history, bool bAgtSign);
int	Get_Charge_Num(CURL *pstCurl, char *pcUserId, struct UserInfoStruct *pstUserInfo, char *pcChargeNo, bool bAgtSign);
int	Get_Report_Num(char *pcFileName, char *pcRepoNo);
int	Del_Report_Print_Button(char *report, int type);
void	Make_Dissent_Para_Struct(char cChargeSign, char *pcCharegNo, struct DissentParaStruct *pstDissPara);
int	Get_Dissent_Id(CURL *pstCurl, char *pcUserId, struct UserInfoStruct *pstUserInfo,struct DissentParaStruct stDissPara,char *pcDissentId, bool bAgtSign);
int	Logout_Credit_Agent(CURL *pstCurl, char *pcUserId);
int	Police_Verify_Cert(CURL *pstCurl, char *pcUserId, struct UserInfoStruct *pstUserInfo, bool bAgtSign);
int	Download_Report_Charge(const char* querysn , char *pcUserId, char* pcUserPwd, char **new_pwd, struct UserInfoStruct *pstUserInfo,char *pcReportNo, char* pcChargeNo , char *pcReportFile,  bool bAgtSign);
int	Init_Curl();
int	Clean_Curl();

/********Function Body**************************************/
/**  I Connection_To_PBC
 *function: function: 验证在征信中心的登录状态
 *parameters:1)pcUserId，征信用户id；
 *           2)pcUserPwd，征信用户密码;
 *           3)bAgtSign, 是否使用代理标记;
 *           4)ppNewPwd, 征信中心可能需要使用的新密码;
 *return(int)	0、登陆成功
        　　	1、征信账号或密码错误
            	2、无法连接到征信服务器或无法连接代理服务器
             	3、账号密码被锁定
		5、账号密码不可为空
		6、征信中心系统异常
		7、服务器系统异常
 */
int Connection_To_PBC(char *pcUserId, char *pcUserPwd, bool bAgtSign, char **ppNewPwd)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    int iLoginRet = 0;
	char acCookieDir[MIDSIZE];
	char acCookieTemp[MIDSIZE];
	char acCookie[MIDSIZE];
	struct stat stFileStat;
	int iFileLen = 0;

	memset(acCookieDir, 0, MIDSIZE);
	if (Get_Homepath(acCookieDir))
	{
		ccis_log_emerg("[%s:%d]Get Homepath Failed" , __FUNCTION__ , __LINE__);
	    return 7;
	}

	memset(acCookie, 0, MIDSIZE);
	memset(acCookieTemp, 0, MIDSIZE);
	sprintf(acCookieTemp, "%s%s_cookie.txt", DIR_SEPARATOR, pcUserId);
	strcpy(acCookie, acCookieDir);
	strcat(acCookie, acCookieTemp);

	if (stat(acCookie , &stFileStat) == 0)
	{
	    iFileLen = stFileStat.st_size;
	}
	if(iFileLen == 0)
	{
    	curl_easy_setopt(curl, CURLOPT_COOKIESESSION, 1);
	}

	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, acCookie);
	curl_easy_setopt(curl, CURLOPT_COOKIEJAR, acCookie);
    if (true == bAgtSign) {//需要代理
        iLoginRet = Login_Credit_Agent(curl, pcUserId, pcUserPwd);
    }
    else {
        iLoginRet = Login_Credit_Center(curl, pcUserId, pcUserPwd, ppNewPwd);
    }
    if (0 != iLoginRet) {
	ccis_log_warning("账号[%s]登陆失败... , 返回值%d" , pcUserId , iLoginRet);
        return iLoginRet;
    }
	ccis_log_info("账号[%s]已成功登陆征信中心" , pcUserId);

    return 0;
}

/**  II Login_Credit_Center
 *function: 登录征信中心网站
 *parameters: 1)pstCurl, CURL库提供的资源的句柄
 *            2)pcUserId,征信用户id;
 *            3)pcUserPwd，征信用户密码;
 *            4)ppNewPwd, 出参，征信中心如果需要修改密码，则账户新密码保存于此;
 *return(int)  0:成功;
               1: 帐号密码错误;
　　　　　　　  2: 无法链接征信中心;
　　　　　　　  3: 账号被锁定
		5：账号密码不可为空
		6：征信中心系统异常
		7：本地系统错误
 */
int Login_Credit_Center(CURL *pstCurl, char *pcUserId, char *pcUserPwd, char **ppNewPwd)//关于ppNewPwd
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    bool bArdyLogin = false;
    int iRet = 0;
    int iConvRet = 0;
    int iPwdRet = 0;
    char *pcLogonTemp = "%s_login.html";
    char *pcSuccSign = "欢迎";    //从数据库获取支行名称
    char *pcWrongSign1 = "用户名或密码错误";    //"logon.do?isDissentLogin=null";
    char *pcWrongSign2 = "您的密码已经过期";
    char *pcWrongSign3 = "用户被锁定";
    char *pcWrongSign4 = "首次登录或密码被重置";
    char *pcWrongSign5 = "请输入用户名和密码";
    char *pcMemUtf8 = NULL;
    char acLogonDir[MIDSIZE];
    char acLogonName[MIDSIZE];
    char acFileName[MIDSIZE];
    char acUrl[MIDSIZE];
    char acPara[MIDSIZE];
    char acNewPwd[MIDSIZE];
    char credit_user[128];
    char credit_pwd[128];

	strcpy(credit_user , pcUserId);
	strcpy(credit_pwd , pcUserPwd);

    bArdyLogin = Check_Login_Status(pstCurl, credit_user);
    if (true == bArdyLogin)
    {
	ccis_log_info("账号[%s]已登陆！" , pcUserId);
        return 0;
    }

    CURLcode iCurlCode;
    FILE *pstFp = NULL;
    FILE *pstFp2 = NULL;

    if (NULL == pstCurl) {
	ccis_log_alert("[%s:%d]pstCurl不可为空！" , __FUNCTION__ , __LINE__);
        return 7;
    }

    memset(acLogonDir, 0, MIDSIZE);
    if (Get_Homepath(acLogonDir)) {
	ccis_log_emerg("[%s:%d]Get Homepath Failed" , __FUNCTION__ , __LINE__);
        return 7;
    }

    memset(acLogonName, 0, MIDSIZE);
    sprintf(acLogonName, pcLogonTemp, credit_user);

    memset(acFileName, 0, MIDSIZE);
    strcpy(acFileName, acLogonDir);
    strcat(acFileName, DIR_SEPARATOR);
    strcat(acFileName, acLogonName);

    if ((pstFp = fopen(acFileName, "w")) == NULL) {
	ccis_log_alert("[%s:%d]无法打开文件%s , 失败原因：%s" , __FUNCTION__ , __LINE__ , acFileName , strerror(errno));
        return 7;
    }

    memset(acUrl, 0, MIDSIZE);
    strcpy(acUrl, zx_normal_url);
    strcat(acUrl, ZX_LOGIN_DO);

    memset(acPara, 0, MIDSIZE);
    sprintf(acPara, ZX_LOGIN_PARA, credit_user, credit_pwd);

    iCurlCode = Do_Http_Post(pstCurl, acUrl, acPara, Write_To_File_For_PBC, (void *) pstFp);//为何登录代理写内存，直接登录征信中心写文件
    fclose(pstFp);
    if (CURLE_OK != iCurlCode) {
	ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        if (0 != remove(acFileName)) {
		ccis_log_err("文件%s删除失败，失败原因：%s" , acFileName , strerror(errno));
        }
        return 2;
    }

    iConvRet = File_Code_Convert("gbk", "utf-8", acFileName, &pcMemUtf8);
    if (0 == iConvRet) {
        if (NULL != strstr(pcMemUtf8, pcWrongSign1)) {
		ccis_log_err("征信账号密码错误，尝试登陆账号：%s，登陆密码：%s" , credit_user , credit_pwd);
            iRet = 1;
        }
        else if (NULL != strstr(pcMemUtf8, pcWrongSign2) || NULL != strstr(pcMemUtf8, pcWrongSign4)) {
		ccis_log_alert("账号[%s]征信密码已过期，请联系管理员更新密码！" , credit_user);
            memset(acNewPwd, 0, MIDSIZE);
            iPwdRet = Auto_Change_Password(pstCurl, credit_user, credit_pwd, acNewPwd, 0);//自动生成新密码
            if (0 == iPwdRet) {
                char new_credit_pwd[128];

                memset(new_credit_pwd, 0, 128);
		strncpy(new_credit_pwd , acNewPwd , 128);
/*
                ret = Base64_Encode(acNewPwd, strlen(acNewPwd), new_credit_pwd, 128);    //base64加密新密码
                if (0 != ret) {
			ccis_log_err("[%s:%d]征信密码加密失败！" , __FUNCTION__ , __LINE__);
                    iRet = 3;
                }
*/
                *ppNewPwd = (char *) malloc(strlen(new_credit_pwd) + 1);
                if (*ppNewPwd == NULL)            
                {
			ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
                    return 7;
                }
                memset(*ppNewPwd, 0, strlen(new_credit_pwd) + 1);
                strncpy(*ppNewPwd, new_credit_pwd, strlen(new_credit_pwd));//出参的方法
                printf("*ppNewPwd:%s\n", *ppNewPwd);
                if ((pstFp2 = fopen(acFileName, "w")) == NULL) {
			ccis_log_err("[%s:%d]无法打开文件%s！失败原因：%s" , __FUNCTION__ , __LINE__ , acFileName , strerror(errno));
                    return 7;
                }
                memset(acPara, 0, MIDSIZE);
                sprintf(acPara, ZX_LOGIN_PARA, credit_user, new_credit_pwd);
                iCurlCode = Do_Http_Post(pstCurl, acUrl, acPara, Write_To_File_For_PBC, (void *) pstFp2);//为何登录代理写内存，直接登录征信中心写文件
                fclose(pstFp2);
                if (CURLE_OK != iCurlCode) {
			ccis_log_err("[%s:%d]密码更新成功，但Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
                    if (0 != remove(acFileName)) {
			ccis_log_err("文件%s删除失败，失败原因：%s" , acFileName , strerror(errno));
                    }
                    return 2;
                }
                else{
                    iConvRet = File_Code_Convert("gbk", "utf-8", acFileName, &pcMemUtf8);
                    if(iConvRet==0)
                    {
                        if (NULL != strstr(pcMemUtf8, pcSuccSign)) {
				ccis_log_info("账号[%s]登陆征信中心成功，密码已更新！" , credit_user);
				ccis_log_debug("旧密码：%s，更新后密码：%s" , credit_pwd , new_credit_pwd);
                            return 0;
                        }
                        else{
                            printf("系统错误！\n");
				ccis_log_err("[%s:%d]征信中心系统错误！" , __FUNCTION__ , __LINE__);
                            return 6;
                        }
                    }
                    else{
			ccis_log_err("征信中心返回报文转码失败！密码已更新！失败原因：%s" , strerror(errno));
                        return 6;
                    }
                }
            }
            else {
		ccis_log_err("账号[%s]自动更新密码失败，请联系管理员操作！错误码：%d" , credit_user , iPwdRet);
                iRet = 7;
            }
        }//密码过期或密码重置解决完毕
        else if (NULL != strstr(pcMemUtf8, pcWrongSign3)) {
		ccis_log_warning("账号[%s]被锁定，系统将于1小时后自动解锁，或与本行用户管理员联系！" , credit_user);
            iRet = 3;
        }
        else if (NULL != strstr(pcMemUtf8, pcWrongSign5)) {
		ccis_log_err("征信账号/密码不可为空！");
            iRet = 5;
        }
            //根据收到的结果标识字段，判断是否登录成功
        else if (NULL != strstr(pcMemUtf8, pcSuccSign)) {
            iRet = 0;
        }
        else {
		ccis_log_err("账号[%s]登陆失败，原因未知！" , credit_user);
            iRet = 6;
        }
    }
    else {
	ccis_log_err("账号[%s]登陆报文转码失败！失败原因：%s" , credit_user , strerror(errno));
        iRet = 6;
    }

    if (0 != iRet) {
	ccis_log_debug("pcUserId:%s, pcUserPwd:%s, credit_user:%s, credit_pwd:%s, pcSuccSign:%s", pcUserId, pcUserPwd,credit_user, credit_pwd, pcSuccSign);
    }

    if (NULL != pcMemUtf8) {
        free(pcMemUtf8);
        pcMemUtf8 = NULL;
    }
    if (0 == access(acFileName, 0)) {
        if (0 != remove(acFileName))
        {
		ccis_log_err("文件%s删除失败，失败原因：%s" , acFileName , strerror(errno));
        }
    }

    return iRet;
}


/**  III Login_Credit_Agent
 *function: 登录征信中心代理网站
 *parameters: 1)pstCurl, CURL库提供的资源的句柄
 *            2)pcUserId,征信用户id；
 *            3)pcUserPwd，征信用户密码；
 *return(int) 0:成功;  
　　　　　　　1：帐号密码错误
　　　　　　　2: 无法链接代理
　　　　　　  3: 其它
 */
int Login_Credit_Agent(CURL *pstCurl, char *pcUserId, char *pcUserPwd)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    bool bArdyLogin = false;
    int iRet = 0;
    char *pcSuccSign = "success:true";    //从数据库获取支行名称
    char *pcFaildSign = "success:false";    //从数据库获取支行名称
    char *pcWrongSign1 = "用户名密码错误";    //"logon.do?isDissentLogin=null";
    char acUrl[MIDSIZE];
    char acPara[MIDSIZE];
    char credit_user[128];
    char credit_pwd[128];

    CURLcode iCurlCode;

    struct MemoryStruct stChunk;
    stChunk.pcBuf = NULL;
    stChunk.uiSize = 0;

    if (NULL == pstCurl) {
	ccis_log_alert("[%s:%d]pstCurl不可为空！" , __FUNCTION__ , __LINE__);
        return 3;
    }

	strcpy(credit_user , pcUserId);
	strcpy(credit_pwd , pcUserPwd);

    /*//登录之前登出
    iLogOutRelt = logout_credit_agent(pstCurl, pcUserId, pcUserPass);
    if (0 != iLogOutRelt) {
        printf("%s:登录之前登出失败!, iLogOutRelt = %d\n", pcUserId, iLogOutRelt);
        iRelt = iLogOutRelt;
        return iRelt;
    }
    printf("%s:登录之前登出成功!\n", pcUserId);*/

    //判断是否已登录
    bArdyLogin = Check_Login_Status(pstCurl, credit_user);
    if (true == bArdyLogin)
    {
	ccis_log_info("账号[%s]已登陆征信中心！" , credit_user);
       return 0;
    }

    memset(acUrl, 0, MIDSIZE);
    strcpy(acUrl, zx_agent_url);
    strcat(acUrl, ZX_LOGIN_DO);

    memset(acPara, 0, MIDSIZE);
    sprintf(acPara, ZX_LOGIN_AGENT_PARA, credit_user, credit_pwd, Get_Systemtime_MS());

    //curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
    //curl_easy_setopt(pstCurl, CURLOPT_COOKIEFILE, acCookie);

    iCurlCode = Do_Http_Post(pstCurl, acUrl, acPara, Write_Memory, (void *) &stChunk);
    if (CURLE_OK != iCurlCode) {
	ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        return 3;
    }
    if (NULL == strstr(stChunk.pcBuf, pcSuccSign)) {				//warning 这个地方会报段错误
        if (NULL != strstr(stChunk.pcBuf, "用户已经登录系统")) {
		ccis_log_err("账号[%s]已在其他地方登陆代理系统，请稍后重试或更换账号！" , credit_user);
            iRet = 3;
        }
        else {
		ccis_log_err("账号[%s]登陆代理系统失败，错误信息：%s" , credit_user , stChunk.pcBuf);
            iRet = 3;
        }
    }
    else {
        iRet = 0;
    }

    if (NULL != stChunk.pcBuf) {
        free(stChunk.pcBuf);

        stChunk.pcBuf = NULL;
    }

    return iRet;
}

/**  IV Check_Login_Status
 *function:  验证是否已登录征信中心
 *parameters: 1)pstCurl, curl库提供的资源句柄 2)pcUserId,征信中心账户ID;
 *return:(bool) true:已登录;false:未登录
 */
bool Check_Login_Status(CURL *pstCurl, char *pcUserId)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    bool bAlreLogin = false;
    char acUrl[MIDSIZE];
    char acPara[MIDSIZE];
    char *pcSuccSign = "success:true";
    char *pcFalseSign = "success:false";

    CURLcode iCurlCode;
    //FILE *fp_already_login;
    //struct curl_slist *http_header = NULL;

    struct MemoryStruct stChunk;
    stChunk.pcBuf = NULL;
    stChunk.uiSize = 0;

    if (NULL == pstCurl) {
	ccis_log_alert("[%s:%d]pstCurl不可为空！" , __FUNCTION__ , __LINE__);
        return bAlreLogin;
    }
    /*if ((fp_already_login= fopen("isAlreadyLogin.html", "w")) == NULL)
    {
        printf("Cannot write isAlreadylogin.html");
        return bAlreLogin;
    }*/
    memset(acUrl, 0, MIDSIZE);
    strcpy(acUrl, zx_normal_url);
    strcat(acUrl, ZX_ALREADY_LOGIN_DO);

    memset(acPara, 0, MIDSIZE);
    sprintf(acPara, ZX_ALREADY_LOGIN_PARA, Get_Systemtime_MS());

    iCurlCode = Do_Http_Post(pstCurl, acUrl, acPara, Write_Memory, (void *) &stChunk);
    //curl_easy_cleanup(curl);
    //curl_global_cleanup();
    if (CURLE_OK != iCurlCode) {
	ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        bAlreLogin = false;
    }
    else {
        if (NULL != strstr(stChunk.pcBuf, pcSuccSign)) {
            bAlreLogin = true;
        }
        /*else if (NULL != strstr(stChunk.pcBuf, pcFalseSign)) {
            bAlreLogin = false;
        }*/
    }

    if (NULL != stChunk.pcBuf) {
        free(stChunk.pcBuf);
        stChunk.pcBuf = NULL;
    }

    return bAlreLogin;
}

/**  V Do_Http_Post
 *function:  调用curl库函数，访问指定URL并发送报文
 *parameters: 1)pstCurl, curl库提供的资源句柄
 *            2)pcUrl,要访问的URL
 *            3)pcPara，要发送的报文
 *            4)pfWritFunc接收网页回复报文的方法，函数
 *            5)pvRelt，接受报文存放地址
 *return:(bool) 0:失败;1:发送成功
 */
CURLcode Do_Http_Post(CURL *pstCurl, char *pcUrl, char *pcPara, size_t (*pfWritFunc)(void *, size_t, size_t, void *), void *pvRelt)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    CURLcode iCurlCode;

    if (NULL == pstCurl)
    {
        iCurlCode = CURLE_FAILED_INIT;
    }
    curl_easy_setopt(pstCurl, CURLOPT_URL, pcUrl);
    curl_easy_setopt(pstCurl, CURLOPT_POSTFIELDS, pcPara);//向服务器post出去的内容
    curl_easy_setopt(pstCurl, CURLOPT_WRITEFUNCTION, pfWritFunc);
    curl_easy_setopt(pstCurl, CURLOPT_WRITEDATA, pvRelt);
	curl_easy_setopt(pstCurl , CURLOPT_TIMEOUT , link_timeout_s);

    iCurlCode = curl_easy_perform(pstCurl);

    //curl_easy_cleanup(pstCurl);
    //curl_global_cleanup();

    return iCurlCode;
}

/**  VI Auto_Change_Password
 *function: 自动修改过期密码
 *parameters: 1)pstCurl，登录传入的curl；
 *            2)pcUserId，征信中心账户ID；
 *            3)pcUserPass，征信中心账户密码；
 *            4)pcNewPwd，新账户密码
 *return(int) 0：登录成功；1：Curl资源获取失败，检查内存；2：生成密码失败；3：征信系统更改密码失败；4：创建目录失败、写文件失败；
 *            5：httppost失败; 6: 编码转换失败；
 */
int Auto_Change_Password(CURL *pstCurl, char *pcUserId, char *pcUserPwd, char *pcNewPwd, bool bAgtSign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    int iPwdRet = 0;
    int iConvRet = 0;
    int iType = 3;
    int iLen = 12;
    char *pcPwdTemp = "%s_pwd.html";
    char *pcSuccSign = "密码修改成功";
    char *pcMemUtf8 = NULL;
    char acPwdDir[MIDSIZE];
    char acPwdName[MIDSIZE];
    char acFileName[MAXSIZE];
    char acUrl[MIDSIZE];
    char acPara[MAXSIZE];

    CURLcode iCurlCode;
    FILE *pstFp = NULL;

    if (NULL == pstCurl) {
        return 1;
    }

    iPwdRet = Generate_Pwd(iType, iLen, pcNewPwd);//iType写死了
    if (0 != iPwdRet) {
       return 2;
    }

    memset(acPwdDir, 0, MIDSIZE);
    if (Get_Homepath(acPwdDir)) {
	ccis_log_emerg("[%s:%d]Get Homepath Failed" , __FUNCTION__ , __LINE__);
        return 4;
    }

    memset(acPwdName, 0, MIDSIZE);
    sprintf(acPwdName, pcPwdTemp, pcUserId);

    memset(acFileName, 0, MAXSIZE);
    strcpy(acFileName, acPwdDir);
    strcat(acFileName, DIR_SEPARATOR);
    strcat(acFileName, acPwdName);

    if ((pstFp = fopen(acFileName, "w")) == NULL) {
	ccis_log_alert("[%s:%d]无法打开文件%s , 失败原因：%s" , __FUNCTION__ , __LINE__ , acFileName , strerror(errno));
        return 4;
    }

    memset(acUrl, 0, MIDSIZE);
    strcpy(acUrl, zx_normal_url);
    strcat(acUrl, ZX_CHANGE_PWD_DO);

    //判断是否需要通过代理登录
    memset(acPara, 0, MAXSIZE);
    if (bAgtSign == 0) {
        sprintf(acPara, ZX_CHANGE_PWD_PARA, pcUserId, pcNewPwd, pcNewPwd, pcUserPwd);//不需要代理
    }
    else {
        sprintf(acPara, ZX_CHANGE_PWD_AGENT_PARA, pcUserId, pcUserPwd, pcNewPwd, pcNewPwd);
    }

    iCurlCode = Do_Http_Post(pstCurl, acUrl, acPara, Write_To_File_For_PBC, (void *) pstFp);
    fclose(pstFp);
    if (CURLE_OK != iCurlCode) {
	ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        if (0 != remove(acFileName)) {
		ccis_log_err("文件%s删除失败，失败原因：%s" , acFileName , strerror(errno));
        }
        return 5;
    }

    iConvRet = File_Code_Convert("gbk", "utf-8", acFileName, &pcMemUtf8);
    if (0 == iConvRet) {
        if (NULL == strstr(pcMemUtf8, pcSuccSign)) {
		ccis_log_err("账号[%s]自动更新密码失败，请联系管理员操作！错误码：%d" , pcUserId , iPwdRet);
            iRet = 3;
        }
        else {
            iRet = 0;
        }
    }
    else {
	ccis_log_err("账号[%s]登陆报文转码失败！失败原因：%s" , pcUserId , strerror(errno));
        iRet = 6;
    }

    if (NULL != pcMemUtf8) {
        free(pcMemUtf8);
        pcMemUtf8 = NULL;
    }
    if (0 != remove(acFileName)) {
	ccis_log_err("文件%s删除失败，失败原因：%s" , acFileName , strerror(errno));
    }

    return iRet;
}

/**  VII Write_To_File_For_PBC
 *function: 将网页返回值保存为文件
 *parameters:　1)buffer，网页返回内容；
 * 　　　　　   2)size,数据项大小
 *             3)numb,数据项个数
 *             4)userp, 用户开辟的文件保存地址
 *return(size_t) 返回新文件的大小
 */
size_t Write_To_File_For_PBC(void *buffer, size_t size, size_t nmemb, void *userp)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    FILE *fptr = (FILE*)userp;
    fwrite(buffer, size, nmemb, fptr);

    return (size * nmemb);
}

/**  VIII Write_Memory
 *function: 将网页返回值保存为文件
 *parameters:　1)buffer，网页返回内容；
 * 　　　　　   2)size,数据项大小
 *             3)numb,数据项个数
 *             4)userp, 用户开辟的文件保存地址
 *return(size_t) 返回数据量大小
 */
size_t Write_Memory(void *buffer, size_t size, size_t nmemb, void *userp)//向userp位置保存size个nmemb大小的数据，实际内容为buffer，完成后返回占用内存大小realsize
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->pcBuf = (char *)realloc(mem->pcBuf, mem->uiSize + realsize + 1);
    if(mem->pcBuf == NULL) {
	ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        return 0;
    }//防止内存泄漏

    memcpy(&(mem->pcBuf[mem->uiSize]), buffer, realsize);
    mem->uiSize += realsize;  //记录当前已经使用内存大小
    mem->pcBuf[mem->uiSize] = 0;

    return realsize;
}

/**  IX Generate_Password
 *function: 生成新密码
 *parameters: 1)iType，组合类型（0，全数字；1，第一位是大写字母；
 *                           2，第一位特殊字符，第二位大写字母；3，第一位大写字母，第二位和第三位小写字母；
 *                           4，第一位特殊字符，第二位大写字母，第三位小写字母，第四位大写字母）；
 *            2)iLen，密码整数长度；
 *            3)pcNewPwd，新密码
 *return（int）0：成功；1：失败；
 */
int Generate_Pwd(int iType, int iLen, char *pcNewPwd)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    char acInteger[] = "0123456789";
    char acSpecialChar[] = "@#_-";
    char acLowerCase[] = "abcdefghijklmnopqrstuvwxy";
    char acUpperCase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char acPwd[MIDSIZE];

    assert(NULL != pcNewPwd);
    if (PWD_LEN > iLen) {
	ccis_log_err("当前密码长度为%d，密码长度必须大于等于8" , iLen);
        return 1;
    }

    memset(acPwd, 0, MIDSIZE);
    srand((unsigned) time(NULL));    //初始先采用time生成种子
    srand(rand() % 65535);             //接着再使用上一步产生的种子产生一个随机数重新作为种子
	iType	= 4;			//将密码修改成最复杂的形式
    switch (iType) {
        case 0: {
            for (int i = 0; i < iLen; i++) {
                acPwd[i] = acInteger[rand() % strlen(acInteger)];
            }
            break;
        }
        case 1: {
            acPwd[0] = acUpperCase[rand() % strlen(acUpperCase)];
            for (int i = 1; i < iLen; i++) {
                acPwd[i] = acInteger[rand() % strlen(acInteger)];
            }
            break;
        }
        case 2: {
            acPwd[0] = acSpecialChar[rand() % strlen(acSpecialChar)];
            acPwd[1] = acUpperCase[rand() % strlen(acUpperCase)];
            for (int i = 2; i < iLen; i++) {
                acPwd[i] = acInteger[rand() % strlen(acInteger)];
            }
            break;
        }
        case 3: {
            acPwd[0] = acUpperCase[rand() % strlen(acUpperCase)];
            acPwd[1] = acLowerCase[rand() % strlen(acLowerCase)];
            acPwd[2] = acLowerCase[rand() % strlen(acLowerCase)];
            for (int i = 3; i < iLen; i++) {
                acPwd[i] = acInteger[rand() % strlen(acInteger)];
            }
            break;
        }
        case 4: {
            acPwd[0] = acSpecialChar[rand() % strlen(acSpecialChar)];
            acPwd[1] = acUpperCase[rand() % strlen(acUpperCase)];
            acPwd[2] = acLowerCase[rand() % strlen(acLowerCase)];
            acPwd[3] = acUpperCase[rand() % strlen(acUpperCase)];
            for (int i = 4; i < iLen; i++) {
                acPwd[i] = acInteger[rand() % strlen(acInteger)];
            }
            break;
        }
        default: {
		ccis_log_err("生成密码类型错误：%d" , iType);
            iRet = 1;
            break;
        }
    }

    if (1 != iRet) {
        strncpy(pcNewPwd, acPwd, strlen(acPwd));
    }

    return iRet;
}

/**  X Download_Police_Photo
 *function: 下载公安部联网核查平台高清照片
 *parameters: 1)pstcurl，curl库结构体创建句柄；
 *            2)pcUserId，征信用户id；
 *            3)pcUserPwd, 征信用户密码
 *            4)new_pwd，　新密码
 *            5)pstUserInfo, 查询用户信息结构体指针;
 *            6)pcPolicePhoto,出参，公安部照片存放路径+文件名
 *            7)bAgtSIgn, 设置是否使用代理标志位
 *return(int) 返回值：
	          0、身份证验证通过并且照片下载成功
	          1、无登记的高清照片
	          2、身份证号码与姓名不匹配
	          3、身份证号码无效
	          4、身份证验证不通过
	          5、无法下载高清照片
	          6、公安部服务器连接失败
		  7、征信账号密码错误
	          8、未知错误
 */
int Download_Police_Photo(char *pcUserId, char *pcUserPwd,char **new_pwd,struct UserInfoStruct *pstUserInfo, char *pcPolicePhoto, bool bAgtSign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    int iLoginRet = 0;
    int iLogOutRet = 0;
    int iCertRet = 0;

    char acUrl[MIDSIZE];

    char *pcPhoto = NULL;

    CURLcode iCurlCode;
    FILE *pstFp = NULL;

/*
	curl	= curl_easy_init();
	if (!curl)
	{
	    printf("CURL point is NULL, check memory!\n");
		return 7;
	}
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_HEADER, 0);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1); //patch1129 未知来源代码
*/
    iLoginRet = Connection_To_PBC(pcUserId, pcUserPwd, bAgtSign, new_pwd);
    printf("iLoginRet:%d\n", iLoginRet);//test login status
    if (0 != iLoginRet) {
	ccis_log_err("[%s:%d]账号[%s]与征信中心连接出错" , __FUNCTION__ , __LINE__ , pcUserId);
	ccis_log_err("[%s:%d]Connection_To_PBC returned %d" , __FUNCTION__ , __LINE__ , iLoginRet);
	if (iLoginRet == 1 || iLoginRet == 3 || iLoginRet == 5)
		return 7;
        return 6;
    }
	ccis_log_info("账号[%s]联网核查系统登陆成功！" , pcUserId);

    //检验身份证姓名和号码是否一致，是否存在相应照片
    iCertRet = Police_Verify_Cert(curl, pcUserId, pstUserInfo,bAgtSign);
	ccis_log_debug("police_verify_cert returned %d" , iCertRet);
    if (iCertRet == 4) {
        iLoginRet = Connection_To_PBC(pcUserId, pcUserPwd, bAgtSign, new_pwd);
	ccis_log_debug("[%s:%d]Connection_To_PBC returned %d" , __FUNCTION__ , __LINE__ , iLoginRet);
        if (0 != iLoginRet) {
		ccis_log_err("账号[%s]联网核查失败，原因：征信中心登录失败" , pcUserId);
            return 6;
        }
        iCertRet = Police_Verify_Cert(curl, pcUserId, pstUserInfo,bAgtSign);
	ccis_log_debug("police_verify_cert2 return %d", iCertRet);
    }
    if (0 != iCertRet && 5 != iCertRet) {
	ccis_log_err("身份验证失败！");
        return iCertRet;
    }
    else if(iCertRet == 5)
    {
	ccis_log_err("身份证验证未知错误！");
        return 8;
    }
    else {
        //向数据库插入联网核查结果
	ccis_log_debug("联网核查成功，号码与姓名一致，且照片存在");

	pcPhoto	= (char*)malloc(sizeof(char) * CCIS_PATHLEN);
	if (!pcPhoto)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return 8;
	}
	int path_ret = Get_Filepath(1, pcPhoto , pstUserInfo->acCertNo, NULL);
	ccis_log_debug("高清照片路径 : %s", pcPhoto);
        if (0 != path_ret) {
		ccis_log_emerg("[%s:%d]Get_Filepath Failed!" , __FUNCTION__ , __LINE__);
            if (pcPhoto)                //memory leak patch
                free(pcPhoto);
            return 8;
        }

        if ((pstFp = fopen(pcPhoto, "w")) == NULL) {
		ccis_log_err("[%s:%d]无法打开文件%s！失败原因：%s" , __FUNCTION__ , __LINE__ , pcPhoto , strerror(errno));
            if (pcPhoto)
                free(pcPhoto);            //memory leak patch
            return 8;
        }
    }

    memset(acUrl, 0, MIDSIZE);

    //判断是否需要代理
    if (true == bAgtSign) {
    	strcpy(acUrl, zx_agent_url);
        strcat(acUrl, zx_agent_sign);
    }
	else
	{
		strcpy(acUrl , zx_normal_url);
	}
    strcat(acUrl, ZX_POLICE_DOWN_SERVLET);
    strcat(acUrl, "?");
    strcat(acUrl, ZX_POLICE_DOWN_PARA);
    //sprintf(acPara, ZX_POLICE_DOWN_PARA);

    iCurlCode = Do_Http_Get(curl, acUrl, Write_To_File_For_PBC, (void *) pstFp);
    fclose(pstFp);

    if (CURLE_OK != iCurlCode) {
	ccis_log_err("[%s:%d]Do_Http_Get Failed , returned %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        return 5;
    }
    else {
        iRet = 0;
    }

    strncpy(pcPolicePhoto, pcPhoto, strlen(pcPhoto)); //把pcPhoto内容拷贝到pcPolicePhoto
    if (NULL != pcPhoto) {
        free(pcPhoto);
        pcPhoto = NULL;
    }
    if (true == bAgtSign) {
        iLogOutRet = Logout_Credit_Agent(curl, pcUserId);
        if(iLogOutRet !=0)
        {
		ccis_log_err("账号[%s]登出征信中心失败！" , pcUserId);
        }
    }

    return iRet;
}

/**  XI Do_Http_Get
 *function:  调用curl库函数，向ｈｔｔｐ服务器发送Ｇｅｔ请求
 *parameters: 1)pstCurl, curl库提供的资源句柄
 *            2)pcUrl,要访问的URL
             3)pfWritFunc接收网页回复报文的方法，函数
 *            5)pvRelt，接受报文存放地址
 *return:(bool) 0:失败;1:发送成功
 */
CURLcode Do_Http_Get(CURL *pstCurl, char *pcUrl, size_t (*pfWritFunc)(void *, size_t, size_t, void *), void *pvRelt)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    CURLcode iCurlCode;

    if (NULL == pstCurl)
    {
        iCurlCode = CURLE_FAILED_INIT;
    }
    //curl_easy_setopt函数为libcurl中针对http参数的设置函数
    curl_easy_setopt(pstCurl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(pstCurl, CURLOPT_URL, pcUrl);  //设置访问该URL，应添加好协议头，如http://,ftp://等
    curl_easy_setopt(pstCurl, CURLOPT_WRITEFUNCTION, pfWritFunc);//用pfwritFunc函数作为数据保存功能，如下载文件。一旦检测到有下载的数据，便调用此函数
    curl_easy_setopt(pstCurl, CURLOPT_WRITEDATA, pvRelt); //WRITEDATA表明WRITEFUNCTION中stream的来源，通常是一个FILE流，写入指定的FILE
    //curl_easy_setopt(pstCurl, CURLOPT_COOKIEFILE, acCookie);

    iCurlCode = curl_easy_perform(pstCurl);//该函数执行curl_easy_setopt指定的所有选项，访问目标URL

    //curl_easy_cleanup(pstCurl);
    //curl_global_cleanup();

    return iCurlCode;
}

/**  XII Get_Charge_Information
 *function:  验证是否需要收费
 *parameters: 1) pstCurl，curl库创建资源句柄；
 *            2) pcUserId, 征信用户id;
 *            3）apcFeeRet，四维字符指针的数组，分别存储是否收费（0：不收费，1：收费）、收费金额、历史查询记录、上次查询失败已收取金额；
 *            4）pstUserInfo,用户信息结构指针
 *            5）是否设置代理标志位
 *return（int）0，成功；1，CURL库获取资源失败，检查内存; 2.httppost失败；3，征信系统查询错误，返回信息未知；
 *               4，获取主目录或写操作失败； 5，编码转换错误
 *            NOTE:是否需要收费，请验apcFeeRet[0]. 0免费，１收费。
 */
int Get_Charge_Information(char *pcUserId, char *(*apcFeeRet)[4], struct UserInfoStruct *pstUserInfo, bool bAgtSign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    int iConvRet = 0;
    char *pcUrlGbk = NULL;
    char *pcParaGbk = NULL;
    char *pcVerifyTemp = "%s_verify.html";
    char *pcFeeSign = "var secondchargestat = \"";
    char *pcFeePos = NULL;
    char *pcMemUtf8 = NULL;
    char acUrl[MIDSIZE];
    char acPara[MAXSIZE];
    char acVerifyDir[MIDSIZE];
    char acVerifyName[MIDSIZE];
    char acVerifyFile[MIDSIZE];

	//CURL* pstCurl	= NULL;
    CURLcode iCurlCode;
    FILE *pstFp = NULL;

	//pstCurl	= curl_easy_init();
    /*if (NULL == pstCurl) {
        printf("CURL pointer is NULL, check memory!\n");
        return 1;
    }*/


    memset(acVerifyDir, 0, MIDSIZE);
    if (Get_Homepath(acVerifyDir)) {
	ccis_log_alert("[%s:%d]Get_Homepath Failed" , __FUNCTION__ , __LINE__);
        return 4;
    }

    memset(acVerifyName, 0, MIDSIZE);
    sprintf(acVerifyName, pcVerifyTemp, pstUserInfo->acCertNo);

    memset(acVerifyFile, 0, MIDSIZE);
    strcpy(acVerifyFile, acVerifyDir);
    strcat(acVerifyFile, DIR_SEPARATOR);
    strcat(acVerifyFile, acVerifyName);

    if ((pstFp = fopen(acVerifyFile, "w")) == NULL) {
	ccis_log_alert("[%s:%d]无法打开文件%s , 失败原因：%s" , __FUNCTION__ , __LINE__ , acVerifyFile , strerror(errno));
        return 4;
    }

    memset(acUrl, 0, MIDSIZE);
    //判断是否需要代理
    if (true == bAgtSign) {
    	strcpy(acUrl, zx_agent_url);
        strcat(acUrl, zx_agent_sign);
    }
	else
	{
		strcpy(acUrl , zx_normal_url);
	}
    strcat(acUrl, ZX_INNER_QUERY_DO);

    memset(acPara, 0, MAXSIZE);
    sprintf(acPara, ZX_VERIFY_FEE_PARA, pstUserInfo->acQueryType, pstUserInfo->acCertName, pstUserInfo->acCertType,
            pstUserInfo->acCertNo, pstUserInfo->acMobileNo);

    //设置acUrl编码格式为GBK
    pcUrlGbk = (char *) malloc(strlen(acUrl) * 2 + 1);
    if (pcUrlGbk == NULL)        //0726 patch
    {
	ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        fclose(pstFp);
        return 5;
    }
    memset(pcUrlGbk, 0, strlen(acUrl) * 2 + 1);
    iConvRet = String_Code_Convert("utf-8", "gbk", acUrl, strlen(acUrl), pcUrlGbk, strlen(acUrl) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        fclose(pstFp);        //0725 patch
        return 5;
    }

    //设置acPara编码格式为GBK
    pcParaGbk = (char *) malloc(strlen(acPara) * 2 + 1);
    if (pcParaGbk == NULL)
    {
	ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (pcUrlGbk)
            free(pcUrlGbk);
        fclose(pstFp);
	    //curl_easy_cleanup(curl);
        return 5;
    }

    memset(pcParaGbk, 0, strlen(acPara) * 2 + 1);
    iConvRet = String_Code_Convert("utf-8", "gbk", acPara, strlen(acPara), pcParaGbk, strlen(acPara) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        if (NULL != pcParaGbk) {
            free(pcParaGbk);
            pcParaGbk = NULL;
        }
        fclose(pstFp);
        return 5;
    }

    iCurlCode = Do_Http_Post(curl, pcUrlGbk, pcParaGbk, Write_To_File_For_PBC, (void *) pstFp);
    fclose(pstFp);
    if (NULL != pcUrlGbk) {
        free(pcUrlGbk);
        pcUrlGbk = NULL;
    }
    if (NULL != pcParaGbk) {
        free(pcParaGbk);
        pcParaGbk = NULL;
    }

    if (CURLE_OK != iCurlCode) {

        if (0 != remove(acVerifyName)) {
		ccis_log_err("文件%s删除失败，失败原因：%s" , acVerifyName , strerror(errno));
        }
	    //curl_easy_cleanup(curl);
	ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        return 2;
    }

    iConvRet = File_Code_Convert("gbk", "utf-8", acVerifyFile, &pcMemUtf8);
    if (0 == iConvRet) {
        pcFeePos = strstr(pcMemUtf8, pcFeeSign);//有机会看一下pcMemUtf8
        if (NULL != pcFeePos) {
            char cChargeStat = pcFeePos[strlen(pcFeeSign)];
            if ('1' == cChargeStat) {
                size_t iYuanLen = 0;
                size_t iHistoryLen = 0;
                char *pcStarYuan = "本次查询需要收费";
                char *pcStarYuanSite = NULL;
                char *pcEndYuan = "元";
                char *pcEndYuanSite = NULL;

                char *pcStarHistory = "<td id=\"chargemsg\" ></td>";
                char *pcStarHistorySite = NULL;
                char *pcEndHistory = "<td colspan=\"3\"></td>";
                char *pcEndHistorySite = NULL;

                (*apcFeeRet)[0] = (char *) malloc(strlen("1") + 1);
                memset((*apcFeeRet)[0], 0, strlen("1") + 1);
                strcpy((*apcFeeRet)[0], "1");

                pcStarYuanSite = strstr(pcMemUtf8, pcStarYuan);
                if (NULL != pcStarYuanSite) {
                    pcEndYuanSite = strstr(pcStarYuanSite, pcEndYuan);
                }
                if (NULL != pcStarYuanSite && NULL != pcEndYuanSite) {
                    iYuanLen = pcEndYuanSite - (pcStarYuanSite + strlen(pcStarYuan));
                    (*apcFeeRet)[1] = malloc(iYuanLen + 1);
                    memset((*apcFeeRet)[1], 0, iYuanLen + 1);
                    strncpy((*apcFeeRet)[1], pcStarYuanSite + strlen(pcStarYuan), iYuanLen);
                }

                pcStarHistorySite = strstr(pcMemUtf8, pcStarHistory);
                if (NULL != pcStarHistorySite) {
                    pcEndHistorySite = strstr(pcStarHistorySite, pcEndHistory);
                }
                if (NULL != pcStarHistorySite && NULL != pcEndHistorySite) {
                    iHistoryLen = pcEndHistorySite + strlen(pcEndHistory) - pcStarHistorySite + strlen("<tr> ") +
                                  strlen(" </tr>");
                    (*apcFeeRet)[2] = (char *) malloc(iHistoryLen + 1);
                    memset((*apcFeeRet)[2], 0, iHistoryLen + 1);

                    size_t iHistTemp = pcEndHistorySite + strlen(pcEndHistory) - pcStarHistorySite;
                    char *pcHistTemp = (char *) malloc(iHistTemp + 1);
                    memset(pcHistTemp, 0, iHistTemp + 1);
                    strncpy(pcHistTemp, pcStarHistorySite, iHistTemp);

                    strcpy((*apcFeeRet)[2], "<tr> ");
                    strcat((*apcFeeRet)[2], pcHistTemp);
                    strcat((*apcFeeRet)[2], " </tr>");
                    if (NULL != pcHistTemp) {
                        free(pcHistTemp);
                        pcHistTemp = NULL;
                    }
                }

                iRet = 0;
            }//发现本次查询需要收费，开始拼接报文
            else if ('0' == cChargeStat) {
                (*apcFeeRet)[0] = (char *) malloc(strlen("0") + 1);
                memset((*apcFeeRet)[0], 0, strlen("0") + 1);
                strcpy((*apcFeeRet)[0], "0");

                iRet = 0;
            }//本次查询免费
            else {
		ccis_log_alert("获取到未知的缴费信息！请查看报文，更新异常处理信息！");
                iRet = 3;
            }
        }
        else {
		ccis_log_err("获取到空报文，请查看原文！");
            iRet = 3;
        }
    }
    else {
	ccis_log_err("已获取查询缴费信息，但转码失败！");
        iRet = 5;
    }

    if (NULL != pcMemUtf8) {
        free(pcMemUtf8);
        pcMemUtf8 = NULL;
    }
    if (0 != remove(acVerifyFile)) {
	ccis_log_err("文件%s删除失败，失败原因：%s" , acVerifyFile , strerror(errno));
    }

	//curl_easy_cleanup(curl);
    return iRet;
}

/**  XIII Download_Report_Free
 *function:   向征信中心查询信用报告，并获取报告编号
 *parameters: 1)pstCurl,CURL库提供的资源句柄;
 *            2)pstUserId, 征信用户Id，
 *            3)pstUserInfo，查询用户信息结构体指针；
 *            4)pcReportNo,出参，信用报告编号；
 *            5)pcReportFile，出参，信用报告文件名（含路径）
 *            6)是否使用代理标志位
 *return(int) 0、报告下载成功
	          1、初始查询系统错误:征信系统用户名或密码错误
	          2、初始查询系统错误:征信系统服务器连接失败
	          3、初始查询系统错误:报告号获取失败
	          4、初始查询其他错误;获取异议号失败
	          5、需要收费（此时需要赋值history参数）
		  6、获取收费信息失败
	          7、未知错误
 */
int Download_Report_Free(const char* querysn , char *pcUserId, char* pcUserPwd, char **new_pwd, struct UserInfoStruct *pstUserInfo,
                         char *pcReportNo,char *pcReportFile, char **history, bool bAgtSign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    struct DissentParaStruct stDissPara;
    int iRet = 0;
    int iLoginRet = 0;
    int iConvRet = 0;
    int iLogOutRet = 0;
    int iDissRet = 0;
    int iFeeRet = 0;
    int iRepoNoRet = 0;
    int del_ret = 0;
    char acUrl[MIDSIZE];
    char acPara[MAXSIZE];
    char *pcChargeNoDiss = "";
    char cChargeSign = '\0';
    char *pcChargeNo = "undefined";
    char *pcRepoNameTemp = "%s.html";
    char *DissentId = NULL;
    char *pcUrlGbk = NULL;
    char *pcParaGbk = NULL;
    char *pcMemUtf8 = NULL;
    char *pcNoReportSign = "个人征信系统中没有此人的征信记录";
    char *pcBeginPos = NULL;
    char *apcFeeRet[4];
    char *pcReport = NULL;
    CURLcode iCurlCode;
    FILE *pstFp = NULL;
    char acCookieDir[MIDSIZE];
    char acCookieTemp[MIDSIZE];
    char acCookie[MIDSIZE];
    int i=0;

    for(i=0;i<4;i++)
        apcFeeRet[i] = NULL;

    memset(acCookieDir, 0, MIDSIZE);
    if (Get_Homepath(acCookieDir)) {
	ccis_log_emerg("[%s:%d]Get Homepath Failed" , __FUNCTION__ , __LINE__);
        return 7;
    }
    memset(acCookie, 0, MIDSIZE);
    memset(acCookieTemp, 0, MIDSIZE);
    sprintf(acCookieTemp, "%s%s_cookie.txt", DIR_SEPARATOR, pcUserId);
    strcpy(acCookie, acCookieDir);
    strcat(acCookie, acCookieTemp);
#if 0
    if ((pstFp = fopen(acCookie, "w")) == NULL) {//打开只写文件
        printf("Cannot write %s\n", acCookie);
        return 6;
    }
	curl_easy_setopt(curl, CURLOPT_COOKIESESSION, 1);//curl = curl_easy_init(); 选择全局变量还是局部变量呢？
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, acCookie);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, acCookie);
    fclose(pstFp);
#endif
	/*curl	= curl_easy_init();
    if (NULL == curl) {
        printf("Curl pointer is NULL, check memory!\n");
        return 6;
    }
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_HEADER, 0);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);*/
    iLoginRet = Connection_To_PBC(pcUserId, pcUserPwd, bAgtSign, new_pwd);
    printf("iLoginRet:%d\n", iLoginRet);//test login status
    if (iLoginRet) {
	ccis_log_err("[%s:%d]账号[%s]与征信中心连接出错" , __FUNCTION__ , __LINE__ , pcUserId);
	ccis_log_err("[%s:%d]Connection_To_PBC returned %d" , __FUNCTION__ , __LINE__ , iLoginRet);
	if (iLoginRet == 1 || iLoginRet == 3 || iLoginRet == 5)
		return 1;
	else
		return 2;
    }
    iFeeRet = Get_Charge_Information(pcUserId, &apcFeeRet,pstUserInfo, bAgtSign);
    if(0 != iFeeRet )
    {
	ccis_log_err("账号[%s]获取收费信息失败！" , pcUserId);
        return 6;
    }

    cChargeSign = apcFeeRet[0][0];

    if(cChargeSign == '1')//需要收费的
    {
        char *sep_sign = "**";
        unsigned long aFR0, aFR1, aFR2, aFR3, sep_l;
        aFR0 = aFR1 = aFR2 = aFR3 = sep_l = 0;
        if (apcFeeRet[0] != NULL)
            aFR0 = strlen(apcFeeRet[0]);
        if (apcFeeRet[1] != NULL)
            aFR1 = strlen(apcFeeRet[1]);
        if (apcFeeRet[2] != NULL)
            aFR2 = strlen(apcFeeRet[2]);
        if (apcFeeRet[3] != NULL)
            aFR3 = strlen(apcFeeRet[3]);
        sep_l = strlen(sep_sign);
        ccis_log_debug("aFR[0].len = %ld", aFR0);
        ccis_log_debug("aFR[1].len = %ld", aFR1);
        ccis_log_debug("aFR[2].len = %ld", aFR2);
        ccis_log_debug("aFR[3].len = %ld", aFR3);
        unsigned long str_len = 3 * sep_l + aFR0 + aFR1 + aFR2 + aFR3;

        *history = (char*) malloc(str_len + 1);

        if (*history == NULL)            //0726 patch
        {
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
            if (NULL != apcFeeRet[0]) {
                free(apcFeeRet[0]);
                apcFeeRet[0] = NULL;
            }
            if (NULL != apcFeeRet[1]) {
                free(apcFeeRet[1]);
                apcFeeRet[1] = NULL;
            }
            if (NULL != apcFeeRet[2]) {
                free(apcFeeRet[2]);
                apcFeeRet[2] = NULL;
            }
            if (NULL != apcFeeRet[3]) {
                free(apcFeeRet[3]);
                apcFeeRet[3] = NULL;
            }
            return 7;
        }
        memset(*history, 0, str_len + 1);
        for ( i = 0; i < 4; i++) {
            if (apcFeeRet[i] != NULL) {
                strncat(*history, apcFeeRet[i], strlen(apcFeeRet[i]));
            }
            if (i != 3) {
                strncat(*history, sep_sign, strlen(sep_sign));
            }
        }
        //调用数据库接口，将查询结果和状态存入数据库，并得到logId

        //释放内存:
        if (NULL != apcFeeRet[0]) {
            free(apcFeeRet[0]);
            apcFeeRet[0] = NULL;
        }
        if (NULL != apcFeeRet[1]) {
            free(apcFeeRet[1]);
            apcFeeRet[1] = NULL;
        }
        if (NULL != apcFeeRet[2]) {
            free(apcFeeRet[2]);
            apcFeeRet[2] = NULL;
        }
        if (NULL != apcFeeRet[3]) {
            free(apcFeeRet[3]);
            apcFeeRet[3] = NULL;
        }
        //curl_easy_cleanup(curl);
        return 5;
    }//需要收费的流程，end of if cChargeSign==1


    if (cChargeSign == '0') {
        DissentId = (char*)malloc(MIDSIZE); //MIDSIZE有点大，dissid是固定长的。可以考虑写死。未free.
        memset(DissentId , 0 , sizeof(char) * MIDSIZE);
        Make_Dissent_Para_Struct(cChargeSign, pcChargeNoDiss, &stDissPara);
        iDissRet = Get_Dissent_Id(curl, pcUserId, pstUserInfo, stDissPara, DissentId, bAgtSign);
        if (0 != iDissRet) {
		ccis_log_err("账号[%s]获取异议号失败，失败原因：%d" , pcUserId , iDissRet);
            //curl_easy_cleanup(curl);
            return 4;
        }
	ccis_log_debug("征信报告异议号：%s" , DissentId);

	pcReport	= (char*)malloc(sizeof(char) * CCIS_PATHLEN);
	if (!pcReport)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return 7;
	}
        int path_ret = Get_Filepath(4 , pcReport , pstUserInfo->acCertNo , querysn);	//warning
        if (0 != path_ret) {
		ccis_log_emerg("[%s:%d]Get_Filepath Failed!" , __FUNCTION__ , __LINE__);
            if (pcReport)            //memory leak patch
                free(pcReport);
            //curl_easy_cleanup(curl);
            return 7;
        }

        if ((pstFp = fopen(pcReport, "w")) == NULL) {
		ccis_log_err("[%s:%d]无法打开文件%s！失败原因：%s" , __FUNCTION__ , __LINE__ , pcReport , strerror(errno));
            if (pcReport)            //memory leak patch
                free(pcReport);
            //curl_easy_cleanup(curl);
            return 7;
        }

        memset(acPara, 0, MAXSIZE);
        memset(acUrl, 0, MIDSIZE);
        //判断是否需要代理
        if (true != bAgtSign) {
            strcpy(acUrl, zx_normal_url);
            sprintf(acPara, ZX_INQUIRE_REPORT_PARA, pstUserInfo->acCertName, pstUserInfo->acCertNo,
                    pstUserInfo->acCertType,
                    pstUserInfo->acQueryType, DissentId, pcChargeNo);
        } else {
            //log_id需要从数据库查询得到，暂时用“01”代替
            strcpy(acUrl, zx_agent_url);
            strcat(acUrl, zx_agent_sign);
            sprintf(acPara, ZX_INQUIRE_REPORT_AGENT_PARA, pstUserInfo->acCertName, pstUserInfo->acCertNo,
                    pstUserInfo->acCertType, pstUserInfo->acQueryType, DissentId, pcChargeNo, atoi(pstUserInfo->acQuerySn));
        }
        strcat(acUrl, ZX_INQUIRE_REPORT_DO);
        //设置acUrl编码格式为GBK
        pcUrlGbk = (char *) malloc(strlen(acUrl) * 2 + 1);
        memset(pcUrlGbk, 0, strlen(acUrl) * 2 + 1);
        iConvRet = String_Code_Convert("utf-8", "gbk", acUrl, strlen(acUrl), pcUrlGbk, strlen(acUrl) * 2);
        if (0 != iConvRet) {
		ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
            if (NULL != pcUrlGbk) {
                free(pcUrlGbk);
                pcUrlGbk = NULL;
            }
            fclose(pstFp);
            //curl_easy_cleanup(curl);
            return 7;
        }

        //设置acPara编码格式为GBK
        pcParaGbk = (char *) malloc(strlen(acPara) * 2);
        memset(pcParaGbk, 0, strlen(acPara) * 2);
        iConvRet = String_Code_Convert("utf-8", "gbk", acPara, strlen(acPara), pcParaGbk, strlen(acPara) * 2);
        if (0 != iConvRet) {
		ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
            if (NULL != pcUrlGbk) {
                free(pcUrlGbk);
                pcUrlGbk = NULL;
            }
            if (NULL != pcParaGbk) {
                free(pcParaGbk);
                pcParaGbk = NULL;
            }
            fclose(pstFp);        //0725 patch
            return 7;
        }

        iCurlCode = Do_Http_Post(curl, pcUrlGbk, pcParaGbk, Write_To_File_For_PBC, (void *) pstFp);
        fclose(pstFp);
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        if (NULL != pcParaGbk) {
            free(pcParaGbk);
            pcParaGbk = NULL;
        }

        if (CURLE_OK != iCurlCode) {
		ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
            return 7;
        }

        iConvRet = File_Code_Convert("gbk", "utf-8", pcReport, &pcMemUtf8);
        if (0 == iConvRet) {
            pcBeginPos = strstr(pcMemUtf8, pcNoReportSign);
            if (NULL != pcBeginPos) {
		ccis_log_notice("个人征信系统中没有此人的征信记录！");
                iRet = 0;
            } else {
                iRepoNoRet = Get_Report_Num(pcReport, pcReportNo);
                if (0 == iRepoNoRet) {
                    iRet = 0;
                } else {
			ccis_log_err("征信系统查询错误：获得报告，获取报告号失败！");
                    iRet = 3;
                }
            }
        } else {
		ccis_log_err("获取报告成功，报告转码失败！失败原因：%s" , strerror(errno));
            return 7;
        }


        if (7 != iRet) {
            del_ret = Del_Report_Print_Button(pcReport, 0);
        } else {
            del_ret = Del_Report_Print_Button(pcReport, 1);
        }
        if (0 != del_ret) {
		ccis_log_err("无法删除报告中的按钮！");
            iRet = 7;
        }
        strcpy(pcReportFile, pcReport);//这里可能还有一点问题，目前无法copy。。我的报告都在pcReport里


        if (NULL != pcReport) {
            free(pcReport);
            pcReport = NULL;
        }
        if (NULL != pcMemUtf8) {
            free(pcMemUtf8);
            pcMemUtf8 = NULL;
        }
    }//获取免费报告流程结束

    if (true == bAgtSign) {
        iLogOutRet = Logout_Credit_Agent(curl, pcUserId);
        if(iLogOutRet !=0)
        {
		ccis_log_err("账号[%s]登出征信中心失败！" , pcUserId);
        }
    }

    return iRet;
}

/**  XIV Get_Report_Num
 *function:  获取报告编号
 *parameters: 1)pcFileName，报告所在路径，包括文件名；
 *            2)pcRepoNo，出参，报告编号
 *return(int) 0:成功；
 * 　　　　　　1：获取到异常报告;
 * 　　　　　　2: 其它错误
*/
int Get_Report_Num(char *pcFileName, char *pcRepoNo)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    int iConvRet = 1;
    int iFd = 0;    //文本描述符
    char *pcMMapBuf = NULL;
    char *pcIconvBuf = NULL;
    char *pcRepoNoLocSign = "报告编号:";
	char* pcRepoNoBeginSign = "creditReportSN";
	char* pcRepoNoMidSign	= "value=";
    char *pcRepoNoEndSign = ">";
    char *pcBeginPos = NULL;
    char *pcEndPos = NULL;

    struct stat stStatBuf;

    if (-1 == stat(pcFileName, &stStatBuf)) {
	ccis_log_err("[%s:%d]无法获取到文件%s的状态！" , __FUNCTION__ , __LINE__ , pcFileName);
        return 2;
    }

    iFd = open(pcFileName, O_RDONLY);
    if (-1 == iFd) {
	ccis_log_err("[%s:%d]无法打开文件%s！失败原因：%s" , __FUNCTION__ , __LINE__ , pcFileName , strerror(errno));
        return 2;
    }

    //建立内存映射，用来将某个文件内容映射到内存中，对该内存区域的存取即是直接对该文件内容的读写。
    pcMMapBuf = (char *) mmap(NULL, stStatBuf.st_size, PROT_READ, MAP_PRIVATE, iFd, 0);
    if (MAP_FAILED == pcMMapBuf) {
	ccis_log_err("文件%s创建内存映射失败！失败原因：%s" , pcFileName , strerror(errno));
        close(iFd);
        return 2;
    }

    //编码转换
    pcIconvBuf = (char *) malloc(stStatBuf.st_size * 2);
    if (pcIconvBuf == NULL)
    {
        close(iFd);
        return 2;
    }
    memset(pcIconvBuf, 0, stStatBuf.st_size * 2);

    iConvRet = String_Code_Convert("gbk", "utf-8", pcMMapBuf, stStatBuf.st_size, pcIconvBuf, stStatBuf.st_size * 2);
    if (0 != iConvRet) {
	ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        //解除内存映射
        if (-1 == munmap(pcMMapBuf, stStatBuf.st_size)) {
		ccis_log_err("文件%s解除内存映射失败！失败原因：%s" , pcFileName , strerror(errno));
        }
        free(pcIconvBuf);    //0725 patch
        close(iFd);        //0725 patch
        return 2;
    }

    //获取报告编号
	char* tmppos	= NULL;
    tmppos = strstr(pcIconvBuf, pcRepoNoLocSign);
    if (NULL != tmppos) {
	tmppos		= strstr(tmppos , pcRepoNoBeginSign);
	if (!tmppos)
	{
        	if (-1 == munmap(pcMMapBuf, stStatBuf.st_size)) {
			ccis_log_err("文件%s解除内存映射失败！失败原因：%s" , pcFileName , strerror(errno));
       		}
       		close(iFd);        //0725 patch
        	free(pcIconvBuf);    //0725 patch
        	return 1;
	}
	pcBeginPos	= strstr(tmppos , pcRepoNoMidSign);
	if (pcBeginPos)
	{
        	pcEndPos = strstr(pcBeginPos, pcRepoNoEndSign);
	}
	else
	{
        	if (-1 == munmap(pcMMapBuf, stStatBuf.st_size)) {
			ccis_log_err("文件%s解除内存映射失败！失败原因：%s" , pcFileName , strerror(errno));
       		}
       		close(iFd);        //0725 patch
        	free(pcIconvBuf);    //0725 patch
        	return 1;
	}	
    }//截取报告
    if ((NULL != pcBeginPos) && (NULL != pcEndPos)) {
	pcBeginPos	+= strlen(pcRepoNoMidSign);
	while ((!isxdigit(*pcBeginPos)) && (pcBeginPos < pcEndPos))
		pcBeginPos ++;
	if (pcBeginPos >= pcEndPos)
	{
        	if (-1 == munmap(pcMMapBuf, stStatBuf.st_size)) {
			ccis_log_err("文件%s解除内存映射失败！失败原因：%s" , pcFileName , strerror(errno));
        	}
        	close(iFd);        //0725 patch
        	free(pcIconvBuf);    //0725 patch
        	return 1;
	}
	while ((!isxdigit(*pcEndPos)) && (pcEndPos > pcBeginPos))
		pcEndPos --;
	if (pcEndPos <= pcBeginPos)
	{
        	if (-1 == munmap(pcMMapBuf, stStatBuf.st_size)) {
			ccis_log_err("文件%s解除内存映射失败！失败原因：%s" , pcFileName , strerror(errno));
        	}
        	close(iFd);        //0725 patch
        	free(pcIconvBuf);    //0725 patch
        	return 1;
	}

        strncpy(pcRepoNo, pcBeginPos , REPNOLEN);
        iRet = 0;//获取报告成功
    }
    else {

        if (-1 == munmap(pcMMapBuf, stStatBuf.st_size)) {
		ccis_log_err("文件%s解除内存映射失败！失败原因：%s" , pcFileName , strerror(errno));
        }
        close(iFd);        //0725 patch
        free(pcIconvBuf);    //0725 patch
        return 1;
    }

    //解除内存映射
    if (-1 == munmap(pcMMapBuf, stStatBuf.st_size)) {
	ccis_log_err("文件%s解除内存映射失败！失败原因：%s" , pcFileName , strerror(errno));
        close(iFd);        //0725 patch
        free(pcIconvBuf);    //0725 patch
    }

    close(iFd);
    free(pcIconvBuf);    //应不应该释放？保存了报告

    return iRet;
}

/**  XV Del_Report_Print_Button
 *function:  删除html文件中的打印、保存和返回按钮
 *parameters:1)pcReport，信用报告文件名（含路径)；
 *           2)type，0，有信用记录，1，无信用记录
 *return（int）0：成功；-1:传入的参数为空；
 *           1：设置文件状态失败；2:打开文件失败；3:建立内存映射失败；4:解除内存映射失败
 *
*/
int Del_Report_Print_Button(char *report, int type)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    int iFd = 0;
    char *pcBegin = NULL;
    char *pcEnd = NULL;
    char *pcBeginSign1 = "<table width=\"100%\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" id=\"footertable\">";
    char *pcBeginSign2 = "<table id=\"print\" width=\"616\" cellpadding=\"5\" cellspacing=\"0\">";
    char *pcEndSign = "</div>";
    char *pcMMapBuf = NULL;

    struct stat stStatBuf;

    if (NULL == report) {
        printf("del report print button failed, input parameter is null\n");
        return -1;
    }

    //获取文件状态
    if (-1 == stat(report, &stStatBuf)) {
	ccis_log_err("[%s:%d]无法获取到文件%s的状态！" , __FUNCTION__ , __LINE__ , report);
        iRet = 1;
        return iRet;
    }

    //打开文件
    iFd = open(report, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (-1 == iFd) {
	ccis_log_err("[%s:%d]无法打开文件%s！失败原因：%s" , __FUNCTION__ , __LINE__ , report , strerror(errno));
        iRet = 2;
        return iRet;
    }

    //建立内存映射，用来将某个文件内容映射到内存中，对该内存区域的存取即是直接对该文件内容的读写。
    pcMMapBuf = (char *) mmap(NULL, stStatBuf.st_size, PROT_WRITE, MAP_SHARED, iFd, 0);
    if (MAP_FAILED == pcMMapBuf) {
	ccis_log_err("文件%s创建内存映射失败！失败原因：%s" , report , strerror(errno));
        close(iFd);
        iRet = 3;
        return iRet;
    }

    if (0 == type) {
        pcBegin = strstr(pcMMapBuf, pcBeginSign1);
    }
    else {
        pcBegin = strstr(pcMMapBuf, pcBeginSign2);
    }
    if (NULL != pcBegin) {
        ccis_log_debug("pcBegin:%s", pcBegin);
        pcEnd = strstr(pcBegin, pcEndSign);
        if (NULL != pcBegin) {
            int iLen = pcEnd - pcBegin;
            ccis_log_debug("iLen = %d", iLen);
            for (int i = 0; i < iLen; i++) {
                *(pcBegin + i) = ' ';
            }
        }
    }

    msync(pcMMapBuf, stStatBuf.st_size, MS_SYNC);

    //解除内存映射
    if (-1 == munmap(pcMMapBuf, stStatBuf.st_size)) {
        iRet = 4;
	ccis_log_err("文件%s解除内存映射失败！失败原因：%s" , report , strerror(errno));
    }
    close(iFd);

    return iRet;
}

/**  XVI Make_Dissent_Para_Struct
 *function: 配置获取异议ID所需的参数结构体stDissPara
 *parameters: 1) cChargeSign，收费标识；
 *            2) pcCharegNo，收费编码；
 *            3) pstDissPara，异议查询参数结构体指针
 *return:void
 */
void Make_Dissent_Para_Struct(char cChargeSign, char *pcCharegNo, struct DissentParaStruct *pstDissPara)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    memset(pstDissPara->acChargeNo, 0, sizeof(pstDissPara->acChargeNo));
    memset(pstDissPara->acBackButton, 0, sizeof(pstDissPara->acBackButton));

    strcpy(pstDissPara->acChargeNo, pcCharegNo);
    strcpy(pstDissPara->acBackButton, ZX_DISSENT_ID_BACK_BUTTON);

    //0代表免费，1代表收费
    if ('0' == cChargeSign) {
        pstDissPara->cChargeStat = '0';
        pstDissPara->cHistoryChargeStat = '0';
    }
    else if ('1' == cChargeSign) {
        pstDissPara->cChargeStat = '1';
        pstDissPara->cHistoryChargeStat = '1';
    }
}

/**  XVII Get_Dissent_Id
 *function:  获取异议ID
 *parameters: 1)pstCurl，登录传入的curl；
 *            2)pstUserInfo，用户信息结构指针；
 *            3)stDissPara,异议查询参数结构体
 *            4)pcDissentId, 存放异议号位置
 *            5)bAgtSign, 使用代理标志位
 *return(int): 0：成功；
 *             1：获取异议号失败；
 *             2：其它错误
 */
int Get_Dissent_Id(CURL *pstCurl, char *pcUserId, struct UserInfoStruct *pstUserInfo,struct DissentParaStruct stDissPara,char *pcDissentId, bool bAgtSign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    int iMD5Ret = 0;
    int iConvRet = 0;

    char *pcDissIdBegin = "index_label=branchpersonalcreditreport&dissentid=";
    char *pcDissIdEnd = "')\">";
    char *pcBeginPos = NULL;
    char *pcEndPos = NULL;
    char *pcSpecSign = NULL;
    char *pcUrlGbk = NULL;
    char *pcParaGbk = NULL;
    char *pcMemUtf8 = NULL;
    char *pcDissentTemp = "%s_dissent.html";

    char acUrl[MIDSIZE];
    char acPara[MAXSIZE];
    //一位大写字母+三位数字
    char acMD5Flag[] = {'0', '2', '2', '2'};
    char acMD5[MIDSIZE];
    char acDissentDir[MIDSIZE];
    char acDissentName[MIDSIZE];
    char acDissentFile[MIDSIZE];

    CURLcode iCurlCode;
    FILE *pstFp = NULL;

    if (NULL == pstCurl) {
	ccis_log_alert("[%s:%d]pstCurl不可为空！" , __FUNCTION__ , __LINE__);
        return 2;
    }

    memset(acDissentDir, 0, MIDSIZE);
    if (Get_Homepath(acDissentDir)) {
	ccis_log_emerg("[%s:%d]Get Homepath Failed" , __FUNCTION__ , __LINE__);
        return 2;
    }

    memset(acDissentName, 0, MIDSIZE);
    sprintf(acDissentName, pcDissentTemp, pstUserInfo->acCertNo);

    memset(acDissentFile, 0, MIDSIZE);
    strcpy(acDissentFile, acDissentDir);
    strcat(acDissentFile, DIR_SEPARATOR);
    strcat(acDissentFile, acDissentName);

    if ((pstFp = fopen(acDissentFile, "w")) == NULL) {
	ccis_log_err("[%s:%d]无法打开文件%s！失败原因：%s" , __FUNCTION__ , __LINE__ , acDissentFile , strerror(errno));
        return 2;
    }

    memset(acUrl, 0, MIDSIZE);
    //判断是否需要代理
    if (true == bAgtSign) {
    	strcpy(acUrl, zx_agent_url);
        strcat(acUrl, zx_agent_sign);
    }
	else
	{
    		strcpy(acUrl, zx_normal_url);
	}
    strcat(acUrl, ZX_BRANCH_QUERY_DO);

    memset(acPara, 0, MAXSIZE);
    memset(acMD5, 0, MIDSIZE);
    iMD5Ret = Make_MD5_For_PBC(acMD5Flag, sizeof(acMD5Flag), pstUserInfo->acCertNo, acMD5);
    if (1 == iMD5Ret) {
	ccis_log_err("[%s:%d]MD5摘要生成失败！" , __FUNCTION__ , __LINE__);
        fclose(pstFp);
        return 2;
    }

    sprintf(acPara, ZX_DISSENT_ID_PARA, pstUserInfo->acCertName, pstUserInfo->acCertNo, pstUserInfo->acCertType,
            pstUserInfo->acQueryType, pstUserInfo->acMobileNo, stDissPara.acBackButton, stDissPara.acChargeNo,
            stDissPara.cChargeStat, pstUserInfo->acQueryType, stDissPara.cHistoryChargeStat, acMD5);

    //设置acUrl编码格式为GBK
    pcUrlGbk = (char *) malloc(strlen(acUrl) * 2 + 1);
    memset(pcUrlGbk, 0, strlen(acUrl) * 2 + 1);
    iConvRet = String_Code_Convert("utf-8", "gbk", acUrl, strlen(acUrl), pcUrlGbk, strlen(acUrl) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        fclose(pstFp);
        return 2;
    }

    //设置acPara编码格式为GBK
    pcParaGbk = (char *) malloc(strlen(acPara) * 2 + 1);
    memset(pcParaGbk, 0, strlen(acPara) * 2 + 1);
    iConvRet = String_Code_Convert("utf-8", "gbk", acPara, strlen(acPara), pcParaGbk, strlen(acPara) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));

        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        if (NULL != pcParaGbk) {
            free(pcParaGbk);
            pcParaGbk = NULL;
        }
        fclose(pstFp);        //0725 patch
        return 2;
    }

    iCurlCode = Do_Http_Post(pstCurl, pcUrlGbk, pcParaGbk, Write_To_File_For_PBC, (void *) pstFp);
    fclose(pstFp);
    if (NULL != pcUrlGbk) {
        free(pcUrlGbk);
        pcUrlGbk = NULL;
    }
    if (NULL != pcParaGbk) {
        free(pcParaGbk);
        pcParaGbk = NULL;
    }
    if (CURLE_OK != iCurlCode) {
	ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        if (0 != remove(acDissentFile)) {
		ccis_log_err("文件%s删除失败，失败原因：%s" , acDissentFile , strerror(errno));
        }
        return 2;
    }

    iConvRet = File_Code_Convert("gbk", "utf-8", acDissentFile, &pcMemUtf8);
    if (0 == iConvRet) {
        pcBeginPos = strstr(pcMemUtf8, pcDissIdBegin);
        if (NULL != pcBeginPos) {
            pcEndPos = strstr(pcBeginPos, pcDissIdEnd);
        }
        if ((NULL != pcBeginPos) && (NULL != pcEndPos)) {
            strncpy(pcDissentId, pcBeginPos + strlen(pcDissIdBegin), pcEndPos - pcBeginPos - strlen(pcDissIdBegin));
            pcSpecSign = strstr(pcDissentId, "{");
            if (NULL != pcSpecSign) {
                strncpy(pcDissentId, pcBeginPos + strlen(pcDissIdBegin),
                        pcSpecSign - pcBeginPos - strlen(pcDissIdBegin));
            }

            iRet = 0;
        }
        else {
		ccis_log_debug("Diss ID File abnormal, can't get desired info!");
            iRet = 2;
        }
    }
    else {
	ccis_log_debug("file_code_convert failed when getting dissent ID");
        iRet = 2;
    }

    if (NULL != pcMemUtf8) {
        free(pcMemUtf8);
        pcMemUtf8 = NULL;
    }
    if (0 != remove(acDissentFile)) {
	ccis_log_err("文件%s删除失败，失败原因：%s" , acDissentFile , strerror(errno));
    }

    return iRet;
}

/**  XVIII Logout_Credit_Agent
 *function: 登出征信中心代理网站
 *parameters: 1)pstCurl, CURL库提供的资源的句柄
 *            2)pcUserId,征信用户id；
 *            3)pcUserPwd，征信用户密码；
 *return(int) 0:成功;  1：curl句柄空，检查内存; 2: HTTPpost错误，请检查网络; 3: 代理登出失败;
 *            -1：sql数据库解密错误
 */
int Logout_Credit_Agent(CURL *pstCurl, char *pcUserId)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    char *pcSuccSign = "success:true";    //从数据库获取支行名称
    char *pcFaildSign = "success:false";    //从数据库获取支行名称
    char acUrl[MIDSIZE];
    char acPara[MIDSIZE];

    CURLcode iCurlCode;

    struct MemoryStruct stChunk;
    stChunk.pcBuf = NULL;
    stChunk.uiSize = 0;

    if (NULL == pstCurl) {
        iRet = 1;
        return iRet;
    }

    /*memset(credit_user, 0, 128);
    ret = Base64_Decode(pcUserId, strlen(pcUserId), credit_user, 128);    //base64数据解密数据库账户
    if (0 != ret) {
        printf("decode mysql user failed!\n");
        LOGGER(1, "sql", "SQL用户名解密失败！尝试用户名：%s", pcUserId);
        return -1;
    }
    memset(credit_pwd, 0, 128);
    ret = Base64_Decode(pcUserPass, strlen(pcUserPass), credit_pwd, 128);    //base64数据解密数据库密码
    if (0 != ret) {
        printf("decode mysql password failed!\n");
        LOGGER(1, "sql", "SQL密码解密失败！尝试用户名：%s , 尝试密码：%s", pcUserId, pcUserPass);
        return -1;
    }*/

    memset(acUrl, 0, MIDSIZE);
    strcpy(acUrl, zx_agent_url);
    strcat(acUrl, ZX_LOGOUT_DO);

    memset(acPara, 0, MIDSIZE);
    sprintf(acPara, ZX_LOGOUT_PARA, Get_Systemtime_MS());

    //curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
    //curl_easy_setopt(pstCurl, CURLOPT_COOKIEFILE, acCookie);

    iCurlCode = Do_Http_Post(pstCurl, acUrl, acPara, Write_Memory, (void *) &stChunk);
    if (CURLE_OK != iCurlCode) {
	ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        iRet = 2;
        return iRet;
    }
    if (NULL == strstr(stChunk.pcBuf, pcSuccSign)) {
        ccis_log_err("账号[%s]代理登出失败，错误信息：%s", pcUserId , stChunk.pcBuf);
        iRet = 3;
    }
    else {
        iRet = 0;
    }

    if (NULL != stChunk.pcBuf) {
        free(stChunk.pcBuf);
        stChunk.pcBuf = NULL;
    }

    return iRet;
}

/**  XIX Police_Verify_Cert
 *function: 公安部联网核查平台身份验证，且反馈是否存在照片
 *parameters: 1)pstcurl，curl库结构体创建句柄；
 *            2)pcUserId，征信用户id；
 *            3)pstUserInfo, 查询用户信息结构体指针;
 *return(int) 0:号码与姓名一致，且照片存在；
 *            1:无登记的高清照片　
 *            2:身份证号码与姓名不匹配；
 *            3:号码不存在；
 *            4:联网核查系统查询错误；
 *            5:其它错误
 *   */

int Police_Verify_Cert(CURL *pstCurl, char *pcUserId, struct UserInfoStruct *pstUserInfo, bool bAgtSign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    int iEncodeRet = 0;
    int iConvRet = 0;
    char *pcUrlGbk = NULL;
    char *pcParaGbk = NULL;
    char *pcCertVerifyTemp = "%s_cert_verify.html";
    char *pcReltSign = "号码与姓名一致，且照片存在";
    char *pcReltSign1 = "号码与姓名一致，但照片不存在";
    char *pcReltSign2 = "号码存在但与姓名不匹配";
    char *pcReltSign3 = "号码不存在";
    char *pcReltSign4 = "请输入用户ID和密码登录系统";
    char *pcMemUtf8 = NULL;
    char acUrl[MIDSIZE];
    char acPara[MAXSIZE];
    char acEncodeCertNo[MIDSIZE];
    char acCertVerifyDir[MIDSIZE];
    char acCertVerifyName[MIDSIZE];
    char acCertVerifyFile[MIDSIZE];

    CURLcode iCurlCode;
    FILE *pstFp = NULL;

    if (NULL == pstCurl) {
	ccis_log_alert("[%s:%d]pstCurl不可为空！" , __FUNCTION__ , __LINE__);
        return 5;
    }

    memset(acCertVerifyDir, 0, MIDSIZE);
    if (Get_Homepath(acCertVerifyDir)) {
	ccis_log_emerg("[%s:%d]Get Homepath Failed" , __FUNCTION__ , __LINE__);
        return 5;
    }

    memset(acCertVerifyName, 0, MIDSIZE);
    sprintf(acCertVerifyName, pcCertVerifyTemp, pstUserInfo->acCertNo);

    memset(acCertVerifyFile, 0, MIDSIZE);
    strcpy(acCertVerifyFile, acCertVerifyDir);
    strcat(acCertVerifyFile, DIR_SEPARATOR);
    strcat(acCertVerifyFile, acCertVerifyName);

    if ((pstFp = fopen(acCertVerifyFile, "w")) == NULL) {
	ccis_log_alert("[%s:%d]无法打开文件%s , 失败原因：%s" , __FUNCTION__ , __LINE__ , acCertVerifyFile , strerror(errno));
        return 5;
    }

    memset(acEncodeCertNo, 0, MIDSIZE);
    strcpy(acEncodeCertNo, pstUserInfo->acCertNo);
    if (strlen(pstUserInfo->acCertNo) > CERTNOLEN) {
        memset(acEncodeCertNo, 0, MIDSIZE);
        iEncodeRet = Base64_Encode(pstUserInfo->acCertNo, strlen(pstUserInfo->acCertNo), acEncodeCertNo, MIDSIZE);
        if (1 == iEncodeRet) {
		ccis_log_err("[%s:%d]acEncodeCertNo is too small!" , __FUNCTION__ , __LINE__);
            fclose(pstFp);                //0725 patch
            return 5;
        }
    }

    memset(acUrl, 0, MIDSIZE);

    //判断是否需要代理
    if (true == bAgtSign) {
    	strcpy(acUrl, zx_agent_url);
        strcat(acUrl, zx_agent_sign);
    }
	else
	{
    		strcpy(acUrl, zx_normal_url);
	}
    strcat(acUrl, ZX_POLICE_VERIFY_DO);

    memset(acPara, 0, MAXSIZE);
    sprintf(acPara, ZX_POLICE_VERIFY_PARA, pstUserInfo->acCertName, acEncodeCertNo);

    //设置acUrl编码格式为GBK
    pcUrlGbk = (char *) malloc(strlen(acUrl) * 2 + 1);
    if (pcUrlGbk == NULL)
    {
        fclose(pstFp);
	ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        return 5;
    }
    memset(pcUrlGbk, 0, strlen(acUrl) * 2 + 1);
    iConvRet = String_Code_Convert("utf-8", "gbk", acUrl, strlen(acUrl), pcUrlGbk, strlen(acUrl) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        fclose(pstFp);        //0725 patch
        return 5;
    }

    //设置acPara编码格式为GBK
    pcParaGbk = (char *) malloc(strlen(acPara) * 2 + 1);
    if (pcParaGbk == NULL)           //0726 patch
    {
        if (pcUrlGbk)
            free(pcUrlGbk);
        fclose(pstFp);
	ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        return 5;
    }

    memset(pcParaGbk, 0, strlen(acPara) * 2 + 1);
    iConvRet = String_Code_Convert("utf-8", "gbk", acPara, strlen(acPara), pcParaGbk, strlen(acPara) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        if (NULL != pcParaGbk) {
            free(pcParaGbk);
            pcParaGbk = NULL;
        }
        fclose(pstFp);        //0725 patch
        return 5;
    }

    iCurlCode = Do_Http_Post(pstCurl, pcUrlGbk, pcParaGbk, Write_To_File_For_PBC, (void *) pstFp);
    fclose(pstFp);
    if (NULL != pcUrlGbk) {
        free(pcUrlGbk);
        pcUrlGbk = NULL;
    }
    if (NULL != pcParaGbk) {
        free(pcParaGbk);
        pcParaGbk = NULL;
    }

    if (CURLE_OK != iCurlCode) {//发送操作不成功，则删除accertverify文件
	ccis_log_err("[%s:%d]Do_Http_Post失败，公安部连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        if (0 != remove(acCertVerifyFile)) {
		ccis_log_err("文件%s删除失败，失败原因：%s" , acCertVerifyName , strerror(errno));
        }
        return 5;
    }

    iConvRet = File_Code_Convert("gbk", "utf-8", acCertVerifyFile, &pcMemUtf8);//从gbk格式转为utf-8格式
    if (0 == iConvRet) {
        //printf("police_verify_cert pcMemUtf8:%s\n", pcMemUtf8);
        if (NULL != strstr(pcMemUtf8, pcReltSign)) {//服务器结果与本地结果比对
            iRet = 0;
        }
        else if (NULL != strstr(pcMemUtf8, pcReltSign1)) {
            iRet = 1;
        }
        else if (NULL != strstr(pcMemUtf8, pcReltSign2)) {
            iRet = 2;
        }
        else if (NULL != strstr(pcMemUtf8, pcReltSign3)) {
            iRet = 3;
        }
        else if (NULL != strstr(pcMemUtf8, pcReltSign4)) {
            iRet = 4;
        }
        else {
		ccis_log_err("发现未知报文类型！文件路径：%s" , acCertVerifyFile);
            iRet = 5;
        }
    }
    else {
	ccis_log_err("[%s:%d]报文转码错误！" , __FUNCTION__ , __LINE__);
        iRet = 5;//依然是转码错误提示
    }

    if (NULL != pcMemUtf8) {
        free(pcMemUtf8);
        pcMemUtf8 = NULL;
    }
    if (0 != remove(acCertVerifyFile)) {
	ccis_log_err("文件%s删除失败，失败原因：%s" , acCertVerifyFile , strerror(errno));
    }

    return iRet;
}

/**  XX Download_Report_Charge
 *function:   获取收费报告
 *parameters: 1)pstCurl,CURL库提供的资源句柄;
 *            2)pstUserId, 征信用户Id，
 *            3)pstUserInfo，查询用户信息结构体指针；
 *            4)pcReportNo,出参，信用报告编号；
 *            5)pcReportFile，出参，信用报告文件名（含路径）
 *            6)是否使用代理标志位
 *return(int) 0、报告下载成功
	          1、初始查询系统错误:征信系统用户名或密码错误
	          2、初始查询系统错误:征信系统服务器连接失败
	          3、初始查询系统错误:报告号获取失败
	          4、初始查询其他错误;获取异议号失败
		  6、获取收费信息失败
	          7、未知错误
 */
int Download_Report_Charge(const char* querysn , char *pcUserId, char* pcUserPwd, char **new_pwd, struct UserInfoStruct *pstUserInfo,
                         char *pcReportNo, char* pcChargeNo , char *pcReportFile,  bool bAgtSign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    char cChargeSign = '1';
    int iRet = 0;
    int iLoginRet = 0;
    int iDissRet = 0;
    int iChargeRet = 0;
    int iConvRet = 0;
    int iRepoNoRet = 0;
    char acCookieDir[MIDSIZE];
    char acCookieTemp[MIDSIZE];
    char acCookie[MIDSIZE];
    char *pcUrlGbk = NULL;
    char *pcMemUtf8 = NULL;
    char *pcParaGbk = NULL;
    int del_ret = 0;
    char acUrl[MIDSIZE];
    char acPara[MAXSIZE];
    char* chargenum= NULL;
    char* DissentId = NULL;
    char *pcReport = NULL;
    char *pcNoReportSign = "个人征信系统中没有此人的征信记录";
    struct DissentParaStruct stDissPara;
    CURLcode iCurlCode;
    char *pcBeginPos = NULL;
    FILE *pstFp = NULL;
    memset(acCookieDir,0,MIDSIZE);
    if(Get_Homepath(acCookieDir))
    {
	ccis_log_emerg("[%s:%d]Get Homepath Failed" , __FUNCTION__ , __LINE__);
        return 7;
    }
    memset(acCookie,0,MIDSIZE);
    memset(acCookieTemp,0,MIDSIZE);
    sprintf(acCookieTemp,"%s%s_cookie.txt", DIR_SEPARATOR,pcUserId);
    strcpy(acCookie,acCookieDir);
    strcat(acCookie, acCookieTemp);
#if 0
    if((pstFp = fopen(acCookie, "w"))== NULL)
    {
        printf("cannot write %s\n", acCookie);
        return 6;
    }
	
    curl_easy_setopt(curl,CURLOPT_COOKIESESSION, 1);
	curl_easy_setopt(curl,CURLOPT_COOKIEFILE,acCookie);
    curl_easy_setopt(curl,CURLOPT_COOKIEJAR,acCookie);
	fclose(pstFp);
#endif
    /*curl	= curl_easy_init();
    if (NULL == curl) {
        printf("Curl pointer is NULL, check memory!\n");
        return 6;
    }
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);*/
    iLoginRet = Connection_To_PBC(pcUserId, pcUserPwd, bAgtSign, new_pwd);
    if (0 != iLoginRet) {
	ccis_log_err("[%s:%d]账号[%s]与征信中心连接出错" , __FUNCTION__ , __LINE__ , pcUserId);
	ccis_log_err("[%s:%d]Connection_To_PBC returned %d" , __FUNCTION__ , __LINE__ , iLoginRet);
	if (iLoginRet == 1 || iLoginRet == 3 || iLoginRet == 5)
		return 1;
	else
		return 2;
    }
    ccis_log_info("账号[%s]征信中心登录成功!", pcUserId);
    chargenum = (char*)malloc(30);
    memset(chargenum,0,30);//为chargenum申请空间。是否有更好的做法。未free
    iChargeRet =  Get_Charge_Num(curl, pcUserId, pstUserInfo, chargenum , bAgtSign);
    if(iChargeRet != 0)
    {
        ccis_log_err("账号[%s]获取收费号失败，错误码:%d", pcUserId , iChargeRet);
        return 6;
    }
	ccis_log_info("收费编号：%s" , chargenum);
	strcpy(pcChargeNo , chargenum);
    DissentId = (char*)malloc(MIDSIZE);
    memset(DissentId,0,MIDSIZE);
    Make_Dissent_Para_Struct(cChargeSign,chargenum,&stDissPara);
    iDissRet = Get_Dissent_Id(curl, pcUserId, pstUserInfo, stDissPara, DissentId, bAgtSign);
    if (0 != iDissRet) {
        ccis_log_err("账号[%s]获取异议号失败，错误码：%d", pcUserId , iDissRet);
        //curl_easy_cleanup(curl);
        return 4;
    }
    ccis_log_debug("New disid is :%s", DissentId);

	pcReport	= (char*)malloc(sizeof(char) * CCIS_PATHLEN);
	if (!pcReport)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return 7;
	}
    int path_ret = Get_Filepath(4 , pcReport , pstUserInfo->acCertNo, querysn);	//warning
    if (0 != path_ret) {
	ccis_log_emerg("[%s:%d]Get Homepath Failed" , __FUNCTION__ , __LINE__);
        if (pcReport)            //memory leak patch
            free(pcReport);
        //curl_easy_cleanup(curl);
        return 7;
    }

    if ((pstFp = fopen(pcReport, "w")) == NULL) {
	ccis_log_alert("[%s:%d]无法打开文件%s , 失败原因：%s" , __FUNCTION__ , __LINE__ , pcReport , strerror(errno));
        if (pcReport)            //memory leak patch
            free(pcReport);
        //curl_easy_cleanup(curl);
        return 7;
    }

    memset(acPara, 0, MAXSIZE);
    memset(acUrl, 0, MIDSIZE);
    //判断是否需要代理
    if (true != bAgtSign) {
        strcpy(acUrl, zx_normal_url);
        sprintf(acPara, ZX_INQUIRE_REPORT_PARA, pstUserInfo->acCertName, pstUserInfo->acCertNo,
                pstUserInfo->acCertType,
                pstUserInfo->acQueryType, DissentId, chargenum);
    } else {
        //log_id需要从数据库查询得到，暂时用“01”代替
        strcpy(acUrl, zx_agent_url);
        strcat(acUrl, zx_agent_sign);
        sprintf(acPara, ZX_INQUIRE_REPORT_AGENT_PARA, pstUserInfo->acCertName, pstUserInfo->acCertNo,
                pstUserInfo->acCertType, pstUserInfo->acQueryType, DissentId, chargenum, atoi(pstUserInfo->acQuerySn));
    }
    strcat(acUrl, ZX_INQUIRE_REPORT_DO);
    //设置acUrl编码格式为GBK
    pcUrlGbk = (char *) malloc(strlen(acUrl) * 2 + 1);
    memset(pcUrlGbk, 0, strlen(acUrl) * 2 + 1);
    iConvRet = String_Code_Convert("utf-8", "gbk", acUrl, strlen(acUrl), pcUrlGbk, strlen(acUrl) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        fclose(pstFp);
        return 7;
    }

    //设置acPara编码格式为GBK
    pcParaGbk = (char *) malloc(strlen(acPara) * 2);
    memset(pcParaGbk, 0, strlen(acPara) * 2);
    iConvRet = String_Code_Convert("utf-8", "gbk", acPara, strlen(acPara), pcParaGbk, strlen(acPara) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        if (NULL != pcParaGbk) {
            free(pcParaGbk);
            pcParaGbk = NULL;
        }
        fclose(pstFp);        //0725 patch
        return 7;
    }

    iCurlCode = Do_Http_Post(curl, pcUrlGbk, pcParaGbk, Write_To_File_For_PBC, (void *) pstFp);
    fclose(pstFp);
    if (NULL != pcUrlGbk) {
        free(pcUrlGbk);
        pcUrlGbk = NULL;
    }
    if (NULL != pcParaGbk) {
        free(pcParaGbk);
        pcParaGbk = NULL;
    }

    if (CURLE_OK != iCurlCode) {
	ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        return 7;
    }

    iConvRet = File_Code_Convert("gbk", "utf-8", pcReport, &pcMemUtf8);
    if (0 == iConvRet) {
        pcBeginPos = strstr(pcMemUtf8, pcNoReportSign);
        if (NULL != pcBeginPos) {
            ccis_log_debug("个人征信系统中没有此人的征信记录!");
            iRet = 0;
        } else {
            iRepoNoRet = Get_Report_Num(pcReport, pcReportNo);
            if (0 == iRepoNoRet) {
                iRet = 0;
            } else {
                ccis_log_err("账号[%s]征信系统查询错误：获得报告，获取报告号失败！" , pcUserId);
                iRet = 3;
            }
        }
    } else {
        ccis_log_err("账号[%s]获取报告成功，报告转码失败！失败原因：%s" , pcUserId , strerror(errno));
        //curl_easy_cleanup(curl);
        return 7;
    }


    if (7 != iRet) {
        del_ret = Del_Report_Print_Button(pcReport, 0);
    } else {
        del_ret = Del_Report_Print_Button(pcReport, 1);
    }
    if (0 != del_ret) {
	ccis_log_err("无法删除报告中的按钮！");
        iRet = 7;
    }
    strncpy(pcReportFile, pcReport, strlen(pcReport));//同样，这个函数写文件失败。是否考虑fgetc,fputc?


    if (NULL != pcReport) {
        free(pcReport);
        pcReport = NULL;
    }
    if (NULL != pcMemUtf8) {
        free(pcMemUtf8);
        pcMemUtf8 = NULL;
    }
	return iRet;
}//获取免费报告流程结束


/**  XXI Get_Charge_Num
 *function:   获取收费报告
 *parameters: 1)pstCurl,CURL库提供的资源句柄;
 *            2)pstUserId, 征信用户Id，
 *            3)pstUserInfo，查询用户信息结构体指针；
 *            4)pcChargeNo,出参，收费编号；
 *            5)bAgtSign,是否使用代理标志位
 *return(int) 0:获取收费号成功
 * 　　　　　　1:获取失败
 * 　　　　　　2:其它错误
 */
int Get_Charge_Num(CURL *pstCurl, char *pcUserId, struct UserInfoStruct *pstUserInfo, char *pcChargeNo, bool bAgtSign)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
    int iRet = 0;
    int iCurlCode = 0;
    int iConvRet = 0;
    char acUrl[MIDSIZE];
    char acPara[MAXSIZE];

    char *pcChargeNumSign = "1H";
    char *pcNoPos = NULL;
    char *pcUrlGbk = NULL;
    char *pcParaGbk = NULL;
    char *pcChunMemUtf8 = NULL;

    struct MemoryStruct stChunk;
    stChunk.pcBuf = NULL;
    stChunk.uiSize = 0;

    if (NULL == pstCurl) {
	ccis_log_alert("[%s:%d]pstCurl不可为空！" , __FUNCTION__ , __LINE__);
        return 2;
    }

    memset(acUrl, 0, MIDSIZE);
    memset(acPara, 0, MAXSIZE);
    if (true == bAgtSign) {
        strcpy(acUrl, zx_agent_url);
        strcat(acUrl, zx_agent_sign);
        sprintf(acPara, ZX_CHARGE_NO_AGENT_PARA, pstUserInfo->acCertName, pstUserInfo->acCertType,
                pstUserInfo->acCertNo, pstUserInfo->acQueryType, pstUserInfo->acMobileNo);
    }
    else {
        strcpy(acUrl, zx_normal_url);
        sprintf(acPara, ZX_CHARGE_NO_PARA, pstUserInfo->acCertName, pstUserInfo->acCertType, pstUserInfo->acCertNo,
                pstUserInfo->acQueryType, pstUserInfo->acMobileNo, Get_Systemtime_MS());
    }
    strcat(acUrl, ZX_INNER_QUERY_DO);

    //设置acUrl编码格式为GBK
    pcUrlGbk = (char *) malloc(strlen(acUrl) * 2 + 1);
    if (pcUrlGbk == NULL)
    {
	ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        return 2;
    }
    memset(pcUrlGbk, 0, strlen(acUrl) * 2 + 1);
    iConvRet = String_Code_Convert("utf-8", "gbk", acUrl, strlen(acUrl), pcUrlGbk, strlen(acUrl) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        return 2;
    }

    //设置acPara编码格式为GBK
    pcParaGbk = (char *) malloc(strlen(acPara) * 2 + 1);
    if (pcParaGbk == NULL)        //0726 patch
    {
	ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (pcUrlGbk)
            free(pcUrlGbk);
        return 2;
    }
    memset(pcParaGbk, 0, strlen(acPara) * 2 + 1);
    iConvRet = String_Code_Convert("utf-8", "gbk", acPara, strlen(acPara), pcParaGbk, strlen(acPara) * 2);
    if (0 != iConvRet) {
	ccis_log_err("[%s:%d]UTF8-->GBK转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        if (NULL != pcUrlGbk) {
            free(pcUrlGbk);
            pcUrlGbk = NULL;
        }
        if (NULL != pcParaGbk) {
            free(pcParaGbk);
            pcParaGbk = NULL;
        }
        return 2;
    }

    iCurlCode = Do_Http_Post(pstCurl, pcUrlGbk, acPara, Write_Memory, (void *) &stChunk);//这里征信中心竟然不需要gbk!直接要utf8我也是醉了
    if (NULL != pcUrlGbk) {
        free(pcUrlGbk);
        pcUrlGbk = NULL;
    }
    if (NULL != pcParaGbk) {
        free(pcParaGbk);
        pcParaGbk = NULL;
    }
    if ((CURLE_OK == iCurlCode) && (NULL != stChunk.pcBuf)) {
        //设置stChunk编码格式，由gbk转为utf-8
        pcChunMemUtf8 = (char *) malloc(stChunk.uiSize * 2 + 1);
        memset(pcChunMemUtf8, 0, stChunk.uiSize * 2 + 1);
        iConvRet = String_Code_Convert("gbk", "utf-8", stChunk.pcBuf, stChunk.uiSize, pcChunMemUtf8, stChunk.uiSize * 2);
        if (0 != iConvRet) {
            iRet = 2;
		ccis_log_err("[%s:%d]GBK-->UTF8转码失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
        }
        else {
            pcNoPos = strstr(pcChunMemUtf8, pcChargeNumSign);
            if (NULL != pcNoPos) {
		//int curlen	= strlen(pcNoPos) - strlen(pcChargeNumSign);
                strncpy(pcChargeNo, pcNoPos + strlen(pcChargeNumSign), CHGNOLEN);		//定长23位
                iRet = 0;
            }
            else {
                ccis_log_err("[%s:%d]获取报告号异常，请检查报文！" , __FUNCTION__ , __LINE__);
                iRet = 1;
            }
        }
        if (NULL != pcChunMemUtf8) {
            free(pcChunMemUtf8);
            pcChunMemUtf8 = NULL;
        }
    }
    else {
	ccis_log_err("[%s:%d]Do_Http_Post失败，征信中心连接出现异常！iCurlCode = %d" , __FUNCTION__ , __LINE__ , iCurlCode);
        iRet = 2;
    }

    if (NULL != stChunk.pcBuf) {
        free(stChunk.pcBuf);
        stChunk.pcBuf = NULL;
    }

    return iRet;

}

int Init_Curl()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (curl)
	{
		curl_easy_cleanup(curl);
		curl	= NULL;
	}

	curl	= curl_easy_init();
	if (!curl)
		return 1;

	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_HEADER, 0);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);

	return 0;
}

int Clean_Curl()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	curl_easy_cleanup(curl);
	curl	= NULL;
	return 0;
}

