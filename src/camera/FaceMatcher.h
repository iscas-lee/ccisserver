#ifndef __CCIS_FM_H__
#define __CCIS_FM_H__
#include "fdreadimage.h"
#include "FaceMatcherDll.h"
#include "../ccis.h"

#define MAX_IMAGE_SIZE	2000000

#define TEST_IMAGE	"/etc/CCIS/ccis_test.jpg"

long long	fm_instance_1;
long long	fm_instance_2;

extern int Face_Check(float threshold, float *score, char *v_image, char *id_image , char *police_image , short* comp_time);
extern int Pre_Process_Image();

#endif
