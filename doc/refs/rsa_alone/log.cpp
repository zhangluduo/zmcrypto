
#include <string>
#include <cstdarg>

#include <string.h>
#include <unistd.h>

#include "log.h"

const std::string timeToStr(time_t t) {
	std::string s;
	char timestr[128];
	memset(timestr, 0, 128);
	struct tm utctime;
	(void)localtime_r(&t, &utctime);
	if (strftime(timestr, sizeof(timestr) - 1, "%FT%T%z", &utctime) == 0) {
		s = "[Time conv error]";
	}
	s = timestr;
	return s;
}

void logMsg(const char* const file, const char* const fn, int ln, const char* const fmt, ...) {
	/* Start printing logs */
	std::string msg;

	char temp[20] = {0};
	sprintf(temp, "%d", ln);

	char temp2[20] = {0};
	sprintf(temp2, "%d", getpid());

	/*
		When we use dlopen function to load this dynamic library and to do nothing, 
		and then use dlclose function to release the dynamic library,
		At this point, using valgrind to track memory leaks, you will find that there 
		are two sentences in this code that will cause memory leaks.
		But now they have been fixed.
		Zhang Luduo 02/15/2022
	*/
	msg.append("[BEANPOD]")
	.append("[").append(timeToStr(time(NULL))).append("]")
    .append("[")
    .append(temp2)//.append(std::to_string(getpid())) /* memory leaks in valgrind, fixed by Zhang Luduo, 02/15/2022 */
    .append("] ")
	.append(file)
	.append(", ")
    .append(fn)
    .append(":")
    .append(temp);//.append(std::to_string(ln)); /* memory leaks in valgrind, fixed by Zhang Luduo, 02/15/2022 */

	char* strp;
	va_list args;
	va_start(args, fmt);
	const int ret = vasprintf(&strp, fmt, args);
	va_end(args);
	if (ret == -1) {
		msg.append(" [logs internal]: MEMORY ALLOCATION ERROR");
	} else {
		msg.append(" ").append(strp);
		free(strp);
	}

	msg.append("\n");
	/* End printing logs */

/*
    FILE* pf = fopen("/opt/usda/log.dat", "a+b");
    if (!pf){
        printf("%s", msg.c_str());
        return;
    }
    fwrite(msg.c_str(), 1, msg.length(), pf);
    fclose(pf);
*/
	printf("%s", msg.c_str());
}