#ifndef MIM_ERR_H
#define MIM_ERR_H

#include <stdnoreturn.h>

// Print information about a system error and quits.
void syserr(const char* fmt, ...);

// Print information about an error and quits.
void fatal(const char* fmt, ...);

// Print error message
void error_msg(const char* buffer, uint8_t length);

#endif
