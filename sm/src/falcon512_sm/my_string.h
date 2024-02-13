#ifndef __MYSTRING_H__
#define __MYSTRING_H__

#include <stddef.h>
//#include "fixedint.h"
#include <stdint.h>

void* my_memcpy(void* dest, const void* src, size_t len);

void* my_memset(void* dest, int byte, size_t len);

void* my_memmove(void *dest, void const *src, size_t count);

unsigned int my_strlen(const char *s);

int my_strncmp( const char * s1, const char * s2, size_t n );

char* my_strncpy(char* destination, const char* source, size_t num);

int my_memcmp (const void *str1, const void *str2, size_t count);

#endif
