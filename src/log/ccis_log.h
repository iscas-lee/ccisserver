/**
 * ccis_log.h:
 */

#ifndef __CCIS_LOG_
#define __CCIS_LOG_ 1

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <systemd/sd-journal.h>
#define CCIS_LOG_EMERG     LOG_EMERG       /* system is unusable */
#define CCIS_LOG_ALERT     LOG_ALERT       /* action must be taken immediately */
#define CCIS_LOG_CRIT      LOG_CRIT        /* critical conditions */
#define CCIS_LOG_ERR       LOG_ERR         /* error conditions */
#define CCIS_LOG_WARNING   LOG_WARNING     /* warning conditions */
#define CCIS_LOG_NOTICE    LOG_NOTICE      /* normal but significant condition */
#define CCIS_LOG_INFO      LOG_INFO        /* informational */
#define CCIS_LOG_DEBUG     LOG_DEBUG       /* debug-level messages */

#define CCIS_LOG_LEVELMASK 7     /* mask off the level value */

#ifndef DEFAULT_LOGLEVEL
#define DEFAULT_LOGLEVEL        CCIS_LOG_DEBUG
#endif
/**
 * CCISLOGNO() should be used at the start of the format string passed
 * to ccis_log_error() and friends. The argument must be a 5 digit decimal
 * number. It creates a tag of the form "CCIS02182: "
 */
#define CCISLOGNO(n)              "CCIS" #n ": "

/**
 * CCIS_LOG_MAX_LOGLEVEL can be defined to remove logging above
 * specified level at compile time.
 */
#ifndef CCIS_LOG_MAX_LOGLEVEL
#define CCIS_LOG_MAX_LOGLEVEL DEFAULT_LOGLEVEL
#endif
#define CCIS_LOG_IS_LEVEL(level)  \
          ( (((level)&CCIS_LOG_LEVELMASK) <= CCIS_LOG_MAX_LOGLEVEL) && \
            ( (((level)&CCIS_LOG_LEVELMASK) <= CCIS_LOG_NOTICE) ||      \
              (CCIS_LOG_DEBUG >= ((level)&CCIS_LOG_LEVELMASK)) ) )

#define ccis_log_emerg(...) ccis_log(CCIS_LOG_EMERG, __VA_ARGS__)
#define ccis_log_alert(...) ccis_log(CCIS_LOG_ALERT, __VA_ARGS__)
#define ccis_log_crit(...)  ccis_log(CCIS_LOG_CRIT, __VA_ARGS__)
#define ccis_log_err(...) ccis_log(CCIS_LOG_ERR, __VA_ARGS__)
#define ccis_log_warning(...) ccis_log(CCIS_LOG_WARNING, __VA_ARGS__)
#define ccis_log_notice(...)  ccis_log(CCIS_LOG_NOTICE, __VA_ARGS__)
#define ccis_log_info(...)  ccis_log(CCIS_LOG_INFO, __VA_ARGS__)
#define ccis_log_debug(...) ccis_log(CCIS_LOG_DEBUG, __VA_ARGS__)

#define ccis_log(...) __ccis_log(__VA_ARGS__)
#define __ccis_log(level, ...)           \
    do {if (CCIS_LOG_IS_LEVEL(level)) \
          sd_journal_send("MESSAGE="__VA_ARGS__, \
                          "PRIORITY=%i", level, \
                          "SYSLOG_FACILITY=%i", 19, \
                          NULL);  \
} while(0)
int ccis_get_loglevel();
#endif /* ccis_log.h */

