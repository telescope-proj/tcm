#ifndef _TCM_COMPAT_THREADLOCAL_H_
#define _TCM_COMPAT_THREADLOCAL_H_

#include "compat/tcmc_os.h"

#if TCM_OS_IS_WINDOWS
    #define tcm_thrlocal __declspec(thread)
#elif TCM_OS_IS_LINUX
    #define tcm_thrlocal __thread
#endif

#endif