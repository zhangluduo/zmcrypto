
#if !defined _LOG_HEADER_H
#define _LOG_HEADER_H

#define LOG(...) logMsg(__FILE__, __PRETTY_FUNCTION__, __LINE__, __VA_ARGS__);
void logMsg(const char* const file, const char* const fn, int ln, const char* const fmt, ...);

#endif