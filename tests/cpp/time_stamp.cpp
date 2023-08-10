
#include "time_stamp.h"
#include <time.h>

#if defined _WIN32
#include <windows.h>
	uint64_t get_timestamp_us()
	{
		double v = 0.0f;
		LARGE_INTEGER PerformanceCount = { 0 };
		LARGE_INTEGER Frequency = { 0 };
		if (QueryPerformanceCounter(&PerformanceCount) && QueryPerformanceFrequency(&Frequency))
			v = (double)(PerformanceCount.QuadPart) * 1000000.0f / (double)(Frequency.QuadPart);
		return (uint64_t)v;
	}
#else
	uint64_t get_timestamp_us()
	{
		struct timespec tm;
		clock_gettime(CLOCK_MONOTONIC, &tm);
		double v = tm.tv_sec * 1000000.0f;
		v += tm.tv_nsec / 1000000.0f;
		return (uint64_t)v;
	}
#endif
