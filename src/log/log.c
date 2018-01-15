/**
 * log.c
 */
#include <stdarg.h>
#include <unistd.h>
#include "ccis_log.h"
#include "../ccis.h"







/*
void _ccis_log(int level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	sd_journal_print(level, fmt, args);
	va_end(args);
}
*/
/**
 * ccis_get_loglevel(): get log level from config file
 * return log level 
 */
int ccis_get_loglevel()
{
	return log_level;
}
