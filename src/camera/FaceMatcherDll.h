/*
 * FaceMatcherDll.h
 *
 * @author		叶伟龙<weilong.ye.2012@gmail.com>
 * @version		2.8.0
 *  - just support linux64
 *  - just can use fms-1.0
 * @since		2016-04-26
 */

#ifndef FACEMATCHERDLL_H_
#define FACEMATCHERDLL_H_

#ifdef _WIN32
#ifdef FACEMATCHERDll_EXPORTS
	#define FM_API __declspec(dllexport)
#else
	#define FM_API __declspec(dllimport)	
	#pragma comment(lib, "FaceMatcherDll.lib")	
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------------------------------------------------------------

/*
 * Error codeadd FD_DetectFace_BGRBuf()
 */
#define FME_OK                                  0
#define FME_INVALID_INSTANCE                    -10001
#define FME_INVALID_FACE_ID                  	-10000 
#define FME_BAD_ALLOC                           -9999
#define FME_FACE_DETECT_INIT_MODEL_FAILED       -9998
#define FME_FACE_RECOGNIZE_INIT_MODEL_FAILED    -9997
#define FME_INVALID_INPUT_ARGUMENTS             -9996
#define FME_INVALID_OUTPUT_ARGUMENTS         	-9995
#define FME_IMG_DECODE_FAIL						-9990
#define FME_FACE_LANDMARK_INIT_MODEL_FAILED		-9988

//---------------------------------------------------------------------------------------------------------------------------------

/*
 * 人脸位置信息
 */
typedef struct
{
	int left;		// 矩形框左上角x坐标
	int top;		// 矩形框左上角y坐标
	int right;		// 矩形框右下角x坐标
	int bottom;		// 矩形框右下角y坐标
} FM_Rect;

//---------------------------------------------------------------------------------------------------------------------------------

/*
 * 创建人脸检测实例
 *
 * 必须先于任何其它人脸检测接口调用 
 *
 * @param pIns, 输出参数，存放一个内部检测类实例指针
 * @param strModelDir, models directory
 * @param strLog, 输入参数，异常日志文件名，若此文件存在，日志将被添加文件尾，否则将创建新日志文件
 * @return FME_OK, 成功创建
 */
#ifdef _WIN32
FM_API
#endif
int FD_CreateIns(long long* pIns, const char* strModelDir, const char* strLog);	

/*
 * 销毁人脸检测实例
 *
 * 必须与FD_CreateIns(pIns)成对调用
 *
 * @param pIns, 输入参数，需要销毁的人脸检测实例，销毁后(*pIns)将被设为0
 * @return FME_OK, 成功销毁
 */
#ifdef _WIN32
FM_API
#endif
int FD_DestroyIns(long long* pIns);

/*
 * 设置人脸检测参数
 * 若不调用此接口，默认值为dMinDetWidthRatio=0.18, dFaceRectExpandRatio=1.0
 * obsolete becasue of new detection algorithm
 *
 * @param ins, 输入参数，人脸检测实例
 * @param dMinDetWidthRatio, 输入参数，设定能检测到的最小人脸框尺寸，例如输入图像 width=1000，hight=1500，设置dMinDetWidthRatio=0.1，则最小检测框尺寸为150=1500*0.1
 * @param dRaceRectExpandRatio, 输入参数，设定结果检测框扩展倍率(面积），需>=1.0
 * @return FME_OK, 成功设置
 */
//#ifdef _WIN32
//FM_API
//#endif
//int FD_SetParams(long long ins, double dMinDetWidthRatio, double dFaceRectExpandRatio);

/*
 * 检测人脸
 *
 * 结果的返回另有接口，此接口只进行人脸检测动作
 *
 * @param ins, 输入参数，人脸检测实例
 * @param pBGRBuf, 输入参数，按BGR顺序存储的一维字节数组，不能包含有行字节对齐空位
 * @param nW, 输入参数，图像宽度
 * @param nH, 输入参数，图像高度
 * @return FME_OK, 成功检测
 */
#ifdef _WIN32
FM_API
#endif
int FD_DetectFace_BGRBuf(long long ins, const unsigned char* pBGRBuf, int nW, int nH);

/*
 * 获取检测到的人脸数目
 * 
 * @param ins, 输入参数，人脸检测实例
 * @param pnFaceNum, 输出参数，存放人脸数目
 * @return FME_OK, 成功获取
 */
#ifdef _WIN32
FM_API
#endif
int FD_GetFaceNum(long long ins, int* pnFaceNum);

/*
 * 获取检测到的某一个人脸
 *
 * @param ins, 输入参数，人脸检测实例
 * @param id, 输入参数，取出第id个检测到的人脸，取值范围为[0,nFaceNum-1], nFaceNum为FD_GetFaceNum()的输出结果
 * @param pDetFace, 输出参数，存放获取到的单个人脸
 * @return FME_OK, 成功获取
 */
#ifdef _WIN32
FM_API
#endif
int FD_GetFace(long long ins, int id, FM_Rect* pRect);

//---------------------------------------------------------------------------------------------------------------------------------



/*
 * 创建实例
 * 
 * @param pIns, 输出参数，存放一个内部实例指针
 * @param strModelDir, 输入参数，模型文件夹，存放了所需要用到的所有模型文件，里面的文件结构和文件名称均不能变动
 * @param strLog, 输入参数，异常日志文件名，若此文件存在，日志将被添加文件尾，否则将创建新日志文件
 *		若strLog==NULL, 日志将输出到屏幕
 * @return FME_OK, 成功创建实例
 */
#ifdef _WIN32
FM_API 
#endif
int FM_CreateIns(long long* pIns, const char* strModelDir, const char* strLog);

/*
 * 销毁实例
 *
 * 必须与FM_CreateIns()成对调用
 *
 * @param pIns, 输入参数，需要销毁的人脸检测实例，销毁后(*pIns)将被设为0
 * @return FME_OK, 成功销毁
 */
#ifdef _WIN32
FM_API 
#endif
int FM_DestroyIns(long long* pIns);

/*
 * 获取特征数组长度
 *
 * @param ins, 输入参数，实例句柄
 * @return 特征数组长度
 */
#ifdef _WIN32
FM_API
#endif
int FM_GetFeatureLen(long long ins);

/*
 * 人脸特征提取
 * 内部将根据输入的感兴趣矩形区域对图片进行裁切，然后进行人脸检测，选取最大脸进行处理 
 *
 * @param ins, 输入参数，实例句柄
 * @param pfFeature, 输出参数，计算出的浮点型特征数组，需要在外部开辟空间，大小可由GetFeatureLen()获得
 * @param pBGRBuf, 输入参数，按BGR顺序存储的一维字节数组，不能包含有行字节对齐空位
 * @param nW, 输入参数，图像宽度
 * @param nH, 输入参数，图像高度
 * @param pnStatus, 状态返回信息
 *		0：正常提取特征, pfFeature有效 
 *		1：此输入图像没有检测到人脸, pfFeature无效 
 * @param pRect, 感兴趣区域设置 
 * @return FME_OK, 成功运行，但是并不能说明pfFeature输出有效，还需检查pnStatus
 */
#ifdef _WIN32
FM_API
#endif
int FM_ExtractFeature_BGRBuf(long long ins, float* pfFeature, const unsigned char* pBGRBuf, int nW, int nH, int* pnStatus, const FM_Rect* pRect);

/*
 * 计算两张照片的得分
 * 调用此函数不需要先创建实例
 * 对应于不同的数据集，阈值可能需要进行调整，可通过测试集寻找最佳阈值
 * 参考阈值为0.6
 *
 * @param pfFeature1, 输入参数，第一个特征数组
 * @param pfFeature2, 输入参数，第二个特征数组
 * @param nLen, 输入参数，特征数组长度
 * @return 匹配得分， 值域 (0,1)
 */
#ifdef _WIN32
FM_API 
#endif
float FM_Match(const float* pfFeature1, const float* pfFeature2, int nLen); 

//---------------------------------------------------------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif // end of FaceMatcherDll_H_
