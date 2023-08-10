// timestamp.h: interface for the performance class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_TIMESTAMP_H__B5633073_33E7_413F_8E76_8F794A9FC4CE__INCLUDED_)
#define AFX_TIMESTAMP_H__B5633073_33E7_413F_8E76_8F794A9FC4CE__INCLUDED_

#if (_MSC_VER < 1800)  && defined _MSC_VER
	#include <wchar.h>
    #include "3rd/msinttypes/inttypes.h"
    #include "3rd/msinttypes/stdint.h"
#else
    #include <stdint.h>
    #include <inttypes.h>
#endif

uint64_t get_timestamp_us();

#endif // !defined(AFX_TIMESTAMP_H__B5633073_33E7_413F_8E76_8F794A9FC4CE__INCLUDED_)
