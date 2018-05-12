#ifndef LOG_H
#define LOG_H

#define ERROR_LEVEL	0x00
#define INFO_LEVEL	0x01
#define DEBUG_LEVEL	0x02

#ifndef LOG_LEVEL
#define LOG_LEVEL	ERROR_LEVEL
#endif

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */


#define FLOG(format, ...)   printf(format, ##__VA_ARGS__)

#define ERROR_TAG	"ERROR"
#define INFO_TAG	"INFO"
#define DEBUG_TAG	"DEBUG"

#if LOG_LEVEL >= DEBUG_LEVEL
#define LOG_DEBUG(message, args...) FLOG(CYAN message RESET, ## args)
#else
#define LOG_DEBUG(message, args...)
#endif

#if LOG_LEVEL >= INFO_LEVEL
#define LOG_INFO(message, args...)  FLOG(YELLOW message RESET, ## args)
#else
#define LOG_INFO(message, args...)
#endif

#if LOG_LEVEL >= ERROR_LEVEL
#define LOG_ERROR(message, args...) FLOG(RED message RESET, ## args)
#else
#define LOG_ERROR(message, args...)
#endif

#endif