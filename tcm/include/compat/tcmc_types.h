#ifndef _TCM_COMPAT_TYPES_H_
#define _TCM_COMPAT_TYPES_H_

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#endif