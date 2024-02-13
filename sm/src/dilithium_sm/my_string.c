#include "my_string.h"

void* my_memcpy(void* dest, const void* src, size_t len)
{
  const char* s = src;
  char *d = dest;

  if ((((uintptr_t)dest | (uintptr_t)src) & (sizeof(uintptr_t)-1)) == 0) {
    while ((void*)d < (dest + len - (sizeof(uintptr_t)-1))) {
      *(uintptr_t*)d = *(const uintptr_t*)s;
      d += sizeof(uintptr_t);
      s += sizeof(uintptr_t);
    }
  }

  while (d < (char*)(dest + len))
    *d++ = *s++;

  return dest;
}

void* my_memset(void* dest, int byte, size_t len)
{
  if ((((uintptr_t)dest | len) & (sizeof(uintptr_t)-1)) == 0) {
    uintptr_t word = byte & 0xFF;
    word |= word << 8;
    word |= word << 16;
    word |= word << 16 << 16;

    uintptr_t *d = dest;
    while (d < (uintptr_t*)(dest + len))
      *d++ = word;
  } else {
    char *d = dest;
    while (d < (char*)(dest + len))
      *d++ = byte;
  }
  return dest;
}


void* my_memmove(void *dest, void const *src, size_t count)
{
  if (src == dest) return dest;
  int reverse = 0;
  char const *const se = src + count;
  for (char const *sp = src; sp < se; ++sp) {
    if (sp == dest) {
      reverse = 1;
      break;
    }
  }
  if (reverse) {
    char *dp = dest + count - 1;
    char const *sp = src + count - 1;
    for (; sp >= (char const*) src; --sp, --dp) *dp = *sp;
  } else {
    char *dp = dest;
    char const *sp = src;
    for (; sp < se; ++sp, ++dp) *dp = *sp;
  }
  return dest;
}