// machine.cpp: implementation of the machine class.

#include "machine_info.h"
#include <time.h>
#include <stdio.h>
#include <string.h>

#if defined _WIN32
    #include <windows.h>
#elif defined __linux__
	#include <unistd.h>
	#include <sys/types.h>
	#include <sys/time.h>
#endif

std::string get_datetime()
{
#if defined __linux__
        std::string s;
        char timestr[128];
        memset(timestr, 0, 128);
        time_t t = time(NULL);
        struct tm utctime;
        (void)localtime_r(&t, &utctime);
        if (strftime(timestr, sizeof(timestr) - 1, "%FT%T%z", &utctime) == 0) {
            s = "[Time conv error]";
        }
        s = timestr;
        return s;
#elif defined _WIN32
    std::string s;
    char timestr[128];
    memset(timestr, 0, 128);
    time_t ltime;
    time(&ltime);
    struct tm *today = localtime( &ltime );
    strftime(timestr, 128, "%Y-%m-%dT%H:%M:%SZ", today);
    s = timestr;
    return s;
#endif
}

std::string get_os()
{
    std::string s;

#if defined __ANDROID__
	s = "Android";
#elif defined __linux__
	s = "Linux";
#elif defined(__APPLE__) && defined(__MACH__)
    s = "Apple OS X";
#elif defined _WIN32 && defined (_MSC_VER) && _MSC_VER > 1200

	typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
	
	OSVERSIONINFOEX osvi;
	SYSTEM_INFO si;
	PGNSI pGNSI;
	BOOL bOsVersionInfoEx;
	
	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	
	// Try calling GetVersionEx using the OSVERSIONINFOEX structure.
	// If that fails, try using the OSVERSIONINFO structure.
	
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	
	if (!(bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO *)&osvi)))
	{
		osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
		if (!GetVersionEx((OSVERSIONINFO *)&osvi))
			return "";
	}
	
	// Call GetNativeSystemInfo if supported
	// or GetSystemInfo otherwise.
	
	pGNSI = (PGNSI)GetProcAddress(
		GetModuleHandle(TEXT("kernel32.dll")),
		"GetNativeSystemInfo");
	if (NULL != pGNSI)
		pGNSI(&si);
	else
		GetSystemInfo(&si);
	
		/*
		Operating system	Version number	dwMajorVersion	dwMinorVersion	Other
		Windows 10	10.0*	10	0	OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION
		Windows Server 2016	10.0*	10	0	OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION
		Windows 8.1	6.3*	6	3	OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION
		Windows Server 2012 R2	6.3*	6	3	OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION
		Windows 8	6.2	6	2	OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION
		Windows Server 2012	6.2	6	2	OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION
		Windows 7	6.1	6	1	OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION
		Windows Server 2008 R2	6.1	6	1	OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION
		Windows Server 2008	6.0	6	0	OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION
		Windows Vista	6.0	6	0	OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION
		Windows Server 2003 R2	5.2	5	2	GetSystemMetrics(SM_SERVERR2) != 0
		Windows Home Server	5.2	5	2	OSVERSIONINFOEX.wSuiteMask & VER_SUITE_WH_SERVER
		Windows Server 2003	5.2	5	2	GetSystemMetrics(SM_SERVERR2) == 0
		Windows XP Professional x64 Edition	5.2	5	2	(OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION) && (SYSTEM_INFO.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
		
		  Windows XP	5.1	5	1	Not applicable
		  Windows 2000	5.0	5	0	Not applicable
		  * For applications that have been manifested for Windows 8.1 or Windows 10. Applications not manifested for Windows 8.1 or Windows 10 will return the Windows 8 OS version value (6.2). To manifest your applications for Windows 8.1 or Windows 10, refer to Targeting your application for Windows.
	*/
/*
	printf("%d, %d, %d, %d, %d, \n",
		osvi.dwOSVersionInfoSize,
		osvi.dwMajorVersion,
		osvi.dwMinorVersion,
		osvi.dwBuildNumber,
		osvi.dwPlatformId
		);
*/	
	if (osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0)
	{
		if (osvi.wProductType == VER_NT_WORKSTATION)
			s = "Windows 10";
		else if (osvi.wProductType != VER_NT_WORKSTATION)
			s = "Windows Server 2016";
	}
	else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 3)
	{
		if (osvi.wProductType == VER_NT_WORKSTATION)
			s = "Windows 8.1";
		else if (osvi.wProductType != VER_NT_WORKSTATION)
			s = "Windows Server 2012 R2";
	}
	else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2)
	{
		if (osvi.wProductType == VER_NT_WORKSTATION)
			s = "Windows 8";
		else if (osvi.wProductType != VER_NT_WORKSTATION)
			s = "Windows Server 2012";
	}
	else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1)
	{
		if (osvi.wProductType == VER_NT_WORKSTATION)
			s = "Windows 7";
		else if (osvi.wProductType != VER_NT_WORKSTATION)
			s = "Windows Server 2008 R2";
	}
	else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)
	{
		if (osvi.wProductType == VER_NT_WORKSTATION)
			s = "Windows Vista";
		else if (osvi.wProductType != VER_NT_WORKSTATION)
			s = "Windows Server 2008";
	}
	else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2)
	{
		if (GetSystemMetrics(SM_SERVERR2) != 0)
			s = "Windows Server 2003 R2";
		else if (osvi.wSuiteMask & /*VER_SUITE_WH_SERVER*/0x00008000)
			s = "Windows Home Server";
		else if (GetSystemMetrics(SM_SERVERR2) == 0)
			s = "Windows Server 2003";
		else if ((osvi.wProductType == VER_NT_WORKSTATION) && (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64))
			s = "Windows XP Professional x64 Edition";
	}
	else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1)
	{
		s = "Windows XP";
	}
	else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0)
	{
		s = "Windows 2000";
	}
	
	char temp[128] = {0};
	sprintf(temp, " Build(%d)", osvi.dwBuildNumber);
	s += temp;
#endif
    return s;
}

std::string get_cpu()
{
    std::string s;

/* detect x86/i386 32bit */
#if defined(__i386__) || defined(__i386) || defined(_M_IX86)
    s = "x86/i386 32bit, little endia";
#endif

/* detect amd64/x64 */
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
    s = "amd64/x64, little endia";
#endif

/* detects MIPS */
#if (defined(_mips) || defined(__mips__) || defined(mips))
    #if defined(_MIPSEB) || defined(__MIPSEB) || defined(__MIPSEB__)
		s = "MIPS 64bit, big endia";
    #else
		s = "MIPS 64bit, little endia";
    #endif
#endif

/* detect AIX */
#if defined(_AIX) && defined(_BIG_ENDIAN)
  #if defined(__LP64__) || defined(_ARCH_PPC64)
	s = "MIPS 64bit, big endia";
  #else
	s = "MIPS 32bit, big endia";
  #endif
#endif

/* detect HP-UX */
#if defined(__hpux) || defined(__hpux__)
    #if defined(__ia64) || defined(__ia64__) || defined(__LP64__)
	 	s = "MIPS 64bit, big endia";
    #else
		s = "MIPS 32bit, big endia";
    #endif
#endif

/* detect SPARC and SPARC64 */
#if defined(__sparc__) || defined(__sparc)
    #if defined(__arch64__) || defined(__sparcv9) || defined(__sparc_v9__)
        #define ENDIAN_64BITWORD
		s = "SPARC64 64bit, big endia";
    #else
        #define ENDIAN_32BITWORD
		s = "SPARC 32bit, big endia";
    #endif
#endif

/* detect IBM S390(x) */
#if defined(__s390x__) || defined(__s390__)
    #if defined(__s390x__)
		s = "IBM S390(x) 64bit, big endia";
    #else
		s = "IBM S390(x) 32bit, big endia";
    #endif
#endif

/* detect ARM64/AARCH64 */
#if defined(__aarch64__)
	s = "aarch64";
#endif

    return s;
}

std::string get_memory()
{
    std::string s;

#if defined _WIN32

#elif defined __linux__
    FILE* pf = fopen("/proc/meminfo","r");
    if(!pf){
		return 0;
    }

    char MemTotal[50] = { 0 };
    fscanf(pf,"MemTotal: %s kB\n",MemTotal);
    fclose(pf);
    s = MemTotal;
	s += " KB";
#endif

    return s;
}

std::string get_compiler()
{
    std::string s;

#if defined __GNUC__
	s = "gcc";
	char buffer[20] = {0};
	sprintf (buffer, " %d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
	s += buffer;
#endif

#if defined _WIN32 && defined (_MSC_VER)
    switch (_MSC_VER)
    {
    case 1100:
        s = "VC++ 5.0";
        break;
    case 1200:
        s = "VC++ 6.0";
        break;
    case 1300:
        s = "VC++ 7.0 (Visual C++ 2002)";
        break;
    case 1310:
        s = "VC++ 7.1 (Visual C++ 2003)";
        break;
    case 1400:
        s = "VC++ 8.0 (Visual C++ 2005)";
        break;
    case 1500:
        s = "VC++ 9.0 (Visual C++ 2008)";
        break;
    case 1600:
        s = "VC++ 10.0 (Visual C++ 2010)";
        break;
    case 1700:
        s = "VC++ 11.0 (Visual C++ 2012)";
        break;
    case 1800:
        s = "VC++ 12.0 (Visual C++ 2013)";
        break;
    case 1900:
        s = "VC++ 14.0 (Visual C++ 2015)";
        break;
    default:
        s = "Unkonw Visual C++ Edition)";
    }

#endif

    return s;
}
