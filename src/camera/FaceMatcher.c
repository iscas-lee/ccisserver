#include "FaceMatcher.h"
#include "unistd.h"
#include "stdio.h"
#include "errno.h"
#include "string.h"
#include "../log/ccis_log.h"

int Face_Check(float threshold, float *score, char *v_image, char *id_image , char *police_image , short* comp_time);//0比对通过，-1基本错误，-2照片处理失败，-3比对不通过

int Pre_Process_Image();

int Face_Check(float threshold, float *score, char *v_image, char *id_image , char *police_image , short* comp_time)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!score || !v_image || !id_image || !police_image || !comp_time)
	{
		ccis_log_err("人脸识别失败：参数错误！");
		return -1;
	}
	int retv	= -3;
	int nStatus	= 0;
	int nH_vis , nH_id , nH_pol;
	int nW_vis , nW_id , nW_pol;
	unsigned char vis_buf[MAX_IMAGE_SIZE] , id_buf[MAX_IMAGE_SIZE] , pol_buf[MAX_IMAGE_SIZE];
	memset(vis_buf , 0 , MAX_IMAGE_SIZE);
	memset(id_buf , 0 , MAX_IMAGE_SIZE);
	memset(pol_buf , 0 , MAX_IMAGE_SIZE);

	int nFeatureLen	= FM_GetFeatureLen(fm_instance_2);

	float pfFeature_vis[nFeatureLen];
	float pfFeature_id[nFeatureLen];
	float pfFeature_pol[nFeatureLen];

	if (access(v_image , R_OK))
	{
		retv	= errno;
		ccis_log_err("无法获取现场照片%s！" , v_image);
		goto clean_up;
	}
	else if (access(id_image , R_OK))
	{
		retv	= errno;
		ccis_log_err("无法获取身份证照片%s！" , id_image);
		goto clean_up;
	}

	*comp_time	= *comp_time + 1;
	retv	= pre_processimg_file(v_image , vis_buf , MAX_IMAGE_SIZE , &nW_vis , &nH_vis);
	if (retv <= 0)
	{
		ccis_log_err("现场照片%s预处理失败 , 返回值%d！" , v_image , retv);
		retv	= -1;
		goto clean_up;
	}

	retv	= pre_processimg_file(id_image , id_buf , MAX_IMAGE_SIZE , &nW_id , &nH_id);
	if (retv <= 0)
	{
		ccis_log_err("身份证照片%s预处理失败 ， 返回值%d！" , id_image , retv);
		retv	= -1;
		goto clean_up;
	}

	ccis_log_debug("照片预处理完成！");
	retv	= FM_ExtractFeature_BGRBuf(fm_instance_2 , pfFeature_vis , vis_buf , nW_vis , nH_vis , &nStatus , NULL);
	if (retv != FME_OK || nStatus != 0)
	{
		ccis_log_err("现场照片%s可见光提取失败 ， 返回值%d，status = %d！" , v_image , retv , nStatus);
		retv	= -2;
		goto clean_up;
	}

	retv	= FM_ExtractFeature_BGRBuf(fm_instance_2 , pfFeature_id , id_buf , nW_id , nH_id , &nStatus , NULL);
	if (retv != FME_OK || nStatus != 0)
	{
		ccis_log_err("身份证照片%s可见光提取失败 ， 返回值%d , status = %d！" , id_image , retv , nStatus);
		retv	= -2;
		goto clean_up;
	}
	ccis_log_debug("照片可见光特性提取完成！");

	*score	= FM_Match(pfFeature_vis , pfFeature_id , nFeatureLen);
	ccis_log_info("可见光:身份证照 = %f" , *score);

	if (*score >= threshold)
	{
		retv	= 0;
		goto clean_up;
	}

	if (access(police_image , R_OK))
	{
		retv	= errno;
		ccis_log_err("无法获取公安部照片%s！" , police_image);
		goto clean_up;
	}
	*comp_time	= *comp_time + 1;
	retv	= pre_processimg_file(police_image , pol_buf , MAX_IMAGE_SIZE , &nW_pol , &nH_pol);
	if (retv <= 0)
	{
		ccis_log_err("公安部照片%s预处理失败！返回值%d" , police_image , retv);
		retv	= -1;
		goto clean_up;
	}
	ccis_log_debug("照片预处理完成！");

	retv	= FM_ExtractFeature_BGRBuf(fm_instance_2 , pfFeature_pol , pol_buf , nW_pol , nH_pol , &nStatus , NULL);
	if (retv != FME_OK || nStatus != 0)
	{
		ccis_log_err("公安部照片%s可见光提取失败！返回值%d , status=%d" , police_image , retv , nStatus);
		retv	= -2;
		goto clean_up;
	}
	ccis_log_debug("照片可见光特性提取完成！");

	*score	= FM_Match(pfFeature_vis , pfFeature_pol , nFeatureLen);
	ccis_log_info("可见光:公安部照片 = %f" , *score);

	if (*score >= threshold)
	{
		retv	= 0;
		goto clean_up;
	}
	else
		retv	= -3;

clean_up:
	return retv;
}

int Pre_Process_Image()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 1;
	int nStatus	= 0;
	int nH_test;
	int nW_test;
	unsigned char test_buf[MAX_IMAGE_SIZE];
	memset(test_buf , 0 , MAX_IMAGE_SIZE);

	int nFeatureLen	= FM_GetFeatureLen(fm_instance_2);

	float pfFeature_test[nFeatureLen];
	if (access(TEST_IMAGE , R_OK))
	{
		retv	= errno;
		ccis_log_err("测试照片%s无法找到！" , TEST_IMAGE);
		goto clean_up;
	}
	retv	= pre_processimg_file(TEST_IMAGE , test_buf , MAX_IMAGE_SIZE , &nW_test , &nH_test);
	if (retv <= 0)
	{
		ccis_log_err("测试照片%s预处理失败 , 返回值%d！" , TEST_IMAGE , retv);
		retv	= -1;
		goto clean_up;
	}
	retv	= FM_ExtractFeature_BGRBuf(fm_instance_2 , pfFeature_test , test_buf , nW_test , nH_test , &nStatus , NULL);
	retv	= 0;
clean_up:
	return retv;
}
