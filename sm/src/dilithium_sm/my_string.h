#ifndef __MYSTRING_H__
#define __MYSTRING_H__

#include <stddef.h>
#include <stdint.h>

void* my_memcpy(void* dest, const void* src, size_t len);

void* my_memset(void* dest, int byte, size_t len);

void* my_memmove(void *dest, void const *src, size_t count);

#endif
