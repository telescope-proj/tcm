#ifndef TCM_EXCEPTION_H_
#define TCM_EXCEPTION_H_

#include <errno.h>
#include <exception>
#include <rdma/fi_errno.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

class tcm_exception : public std::exception {

    int          retcode;
    const char * err_str;
    std::string  err_dyn_str;
    bool         dyn_str;
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
        dyn_str       = false;
    }

    tcm_exception(int ret, std::string & info, const char * file = 0,
                  unsigned int line = 0) {
        this->retcode     = ret;
        this->err_dyn_str = info;
        this->file        = file;
        this->line        = line;
        dyn_str           = true;
    }

    tcm_exception(int ret, std::stringstream & info, const char * file = 0,
                  unsigned int line = 0) {
        this->retcode     = ret;
        this->err_dyn_str = info.str();
        this->file        = file;
        this->line        = line;
    }

    int return_code() noexcept { return this->retcode; }

    const char * what() noexcept {
        if (this->dyn_str)
            return this->err_dyn_str.c_str();
        return this->err_str;
    }

    const char * err_desc() noexcept {
        if (this->retcode >= FI_ERRNO_OFFSET)
            return fi_strerror(this->retcode);
        return strerror(this->retcode);
    }

    std::string full_desc() {
        std::stringstream out;
        if (this->file) {
            out << "[" << this->file;
            if (this->line)
                out << ":" << std::to_string(this->line);
            out << "] ";
        }
        if (this->retcode)
            out << this->err_desc() << ": " << this->err_str;
        else
            out << this->err_str;
        return out.str();
    }
};

#endif