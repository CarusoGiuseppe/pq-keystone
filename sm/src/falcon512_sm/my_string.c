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

unsigned int my_strlen(const char *s)
{
    unsigned int count = 0;
    while(*s!='\0')
    {
        count++;
        s++;
    }
    return count;
}

int my_strncmp( const char * s1, const char * s2, size_t n )
{
    while ( n && *s1 && ( *s1 == *s2 ) )
    {
        ++s1;
        ++s2;
        --n;
    }
    if ( n == 0 )
    {
        return 0;
    }
    else
    {
        return ( *(unsigned char *)s1 - *(unsigned char *)s2 );
    }
}

// Function to implement `my_strncpy()` function
char* my_strncpy(char* destination, const char* source, size_t num)
{
    // return if no memory is allocated to the destination
    if (destination == NULL) {
        return NULL;
    }
 
    // take a pointer pointing to the beginning of the destination string
    char* ptr = destination;
 
    // copy first `num` characters of C-string pointed by source
    // into the array pointed by destination
    while (*source && num--)
    {
        *destination = *source;
        destination++;
        source++;
    }
 
    // null terminate destination string
    *destination = '\0';
 
    // the destination is returned by standard `my_strncpy()`
    return ptr;
}

int
my_memcmp (const void *str1, const void *str2, size_t count)
{
    const unsigned char *s1 = (const unsigned char*)str1;
    const unsigned char *s2 = (const unsigned char*)str2;

  while (count-- > 0)
    {
      if (*s1++ != *s2++)
    return s1[-1] < s2[-1] ? -1 : 1;
    }
  return 0;
}