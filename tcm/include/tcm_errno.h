#ifndef _TCM_ERRNO_H_
#define _TCM_ERRNO_H_

#include <compat/tcmc_stable_errno.h>

int tcm_err_to_sys(unsigned int tcm_errno);

int tcm_sys_to_err(unsigned int sys_errno);

#endif