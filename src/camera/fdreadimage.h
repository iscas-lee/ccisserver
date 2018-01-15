#ifdef __cplusplus
extern "C" {
#endif


/*
	转换内存中的图像文件（JPG，PNG等）到可以被人脸算法识别的格式
	
	src：图像数据
	srclen: 图像数据长度
	dest:调用方分配的空间（至少width*height*3)
	destlen:dest的空间长度
	width:图像的宽度（传出）
	height:图像高度（传出）
	
	返回：
		-1：参数不对
		0：检测的图像宽度和高度无效
		-2：dest空间不够
		
		其余返回实际往dest写的数据长度
	
*/
int pre_processimg_file(char* src_file, unsigned char*dest, int destlen, int* width, int* height);

/*
	转换指定图像文件（JPG，PNG等）到可以被人脸算法识别的格式
	
	src_file：图像文件名
	dest:调用方分配的空间（至少width*height*3)
	destlen:dest的空间长度
	width:图像的宽度（传出）
	height:图像高度（传出）
	
	返回：
		-1：参数不对
		0：检测的图像宽度和高度无效
		-2：dest空间不够
		
		其余返回实际往dest写的数据长度
	
*/
int pre_processimg_buf(unsigned char* src, int srclen ,unsigned char*dest, int destlen, int* width, int* height);

#ifdef __cplusplus
}
#endif
