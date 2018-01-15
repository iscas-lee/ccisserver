#ifndef __CONF_H__
#define __CONF_H__

#include <stdio.h>
#include <glib-object.h>
#include <glib.h>

#define CONF_FILE_PATH  "/etc/CCIS/CCISServer.conf"
extern GKeyFile* keyFile;

extern gchar* get_string_accord_group_key(GKeyFile *keyfile, const char *conf_file, const char *group, const char *key);	//读取字符串
extern int get_int_accord_group_key(GKeyFile *keyfile, const char *conf_file, const char *group, const char *key);		//读取整形

#endif
