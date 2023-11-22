#ifndef TCM_EXCEPTION_H_
#define TCM_EXCEPTION_H_ 
 
#include <rdma/fi_errno.h>
#include <errno.h>
#include <string.h>
#include <exception>
#include <stdio.h>
#include <stdlib.h>

// Hacky, but if you have >9,999,999 lines of code in a single file, well...
namespace tcm_internal {
    static inline int get_int_len(unsigned int val) {
        if (val >= 1000000)
            return 7;
        if (val >= 100000)
            return 6;
        if (val >= 10000)
            return 5;
        if (val >= 1000)
            return 4;
        if (val >= 100)
            return 3;
        if (val >= 10)
            return 2;
        return 1;
    }
}

class tcm_exception : public std::exception {

    int          retcode;
    const char * err_str;
    const char * file;
    unsigned int line;

public:

    tcm_exception(int ret, const char * info) noexcept {
        this->retcode = ret;
        this->err_str = info;
        this->file    = 0;
        this->line    = 0;
    }

    tcm_exception(int ret, const char * file, unsigned int line, 
                  const char * info) noexcept {
        this->retcode = ret;
        this->err_str = info;
        this->file    = file;
        this->line    = line;
    }

    int return_code() noexcept {
        return this->retcode;
    }

    const char * what() noexcept {
        return this->err_str;
    }

    const char * err_desc() noexcept {
        if (this->retcode >= FI_ERRNO_OFFSET)
            return fi_strerror(this->retcode);
        return strerror(this->retcode);
    }

    char * full_desc() noexcept {
        const char * desc = this->err_desc();
        size_t len = 8;
        if (this->file && this->line)
            len += strlen(this->file) + tcm_internal::get_int_len(this->line);
        if (this->err_str)
            len += strlen(this->err_str);
        if (desc)
            len += strlen(desc);
        char * out = (char *) malloc(len);
        if (!out)
            return nullptr;
        if (this->file && this->line) {
            snprintf(out, len - 1, "[%s:%d] %s: %s",
                    this->file,
                    this->line,
                    this->err_str, 
                    desc ? desc : "");
        }
        else if (desc) {
            snprintf(out, len - 1, "%s: %s", this->err_str, desc);
        }
        else {
            snprintf(out, len - 1, "%s", this->err_str);
        }
        out[len - 1] = '\0';
        return out;
    }

};

#endif