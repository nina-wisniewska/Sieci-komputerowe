#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "err.h"

void syserr(const char* fmt, ...) {
    va_list fmt_args;
    int org_errno = errno;

    fprintf(stderr, "ERROR ");

    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    fprintf(stderr, " (%d; %s)\n", org_errno, strerror(org_errno));
    exit(1);
}

void fatal(const char* fmt, ...) {
    va_list fmt_args;

    fprintf(stderr, "ERROR ");

    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    fprintf(stderr, "\n");
    exit(1);
}

void error_msg(const char* buffer, uint8_t length) {
    
    if (length >= 10) {
        length = 10;
    }
    fprintf(stderr, "ERROR MSG ");
    for (uint8_t i = 0; i < length; i++) {
        fprintf(stderr, "%02x", buffer[i]);
    }
    fprintf(stderr, "\n");
}
