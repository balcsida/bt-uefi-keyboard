/** @file
  The small part of the C library NimBLE needs, on top of EDK2 libraries:
  memory and string functions, malloc family, and a printf-style formatter
  with standard C semantics (for NimBLE's log lines and ble_uuid_to_str).

  SPDX-License-Identifier: MIT OR Apache-2.0
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

STATIC_ASSERT (sizeof (long) == 8, "inttypes.h assumes LP64 (X64)");

/*
 * Memory and strings
 */

void *
memcpy (void *dst, const void *src, size_t n)
{
  return (n != 0) ? CopyMem (dst, src, n) : dst;
}

void *
memmove (void *dst, const void *src, size_t n)
{
  return (n != 0) ? CopyMem (dst, src, n) : dst;
}

void *
memset (void *dst, int c, size_t n)
{
  return (n != 0) ? SetMem (dst, n, (UINT8)c) : dst;
}

int
memcmp (const void *a, const void *b, size_t n)
{
  return (n != 0) ? (int)CompareMem (a, b, n) : 0;
}

void *
memchr (const void *s, int c, size_t n)
{
  const unsigned char  *p;

  for (p = s; n != 0; p++, n--) {
    if (*p == (unsigned char)c) {
      return (void *)p;
    }
  }

  return NULL;
}

size_t
strlen (const char *s)
{
  size_t  n;

  for (n = 0; s[n] != '\0'; n++) {
  }

  return n;
}

size_t
strnlen (const char *s, size_t max)
{
  size_t  n;

  for (n = 0; n < max && s[n] != '\0'; n++) {
  }

  return n;
}

int
strcmp (const char *a, const char *b)
{
  while (*a != '\0' && *a == *b) {
    a++;
    b++;
  }

  return (unsigned char)*a - (unsigned char)*b;
}

int
strncmp (const char *a, const char *b, size_t n)
{
  for ( ; n != 0; a++, b++, n--) {
    if (*a != *b || *a == '\0') {
      return (unsigned char)*a - (unsigned char)*b;
    }
  }

  return 0;
}

char *
strcpy (char *dst, const char *src)
{
  char  *d;

  for (d = dst; (*d = *src) != '\0'; d++, src++) {
  }

  return dst;
}

char *
strncpy (char *dst, const char *src, size_t n)
{
  size_t  i;

  for (i = 0; i < n && src[i] != '\0'; i++) {
    dst[i] = src[i];
  }

  for ( ; i < n; i++) {
    dst[i] = '\0';
  }

  return dst;
}

char *
strcat (char *dst, const char *src)
{
  strcpy (dst + strlen (dst), src);
  return dst;
}

char *
strncat (char *dst, const char *src, size_t n)
{
  char  *d;

  d = dst + strlen (dst);
  while (n != 0 && *src != '\0') {
    *d++ = *src++;
    n--;
  }

  *d = '\0';
  return dst;
}

char *
strchr (const char *s, int c)
{
  for ( ; ; s++) {
    if (*s == (char)c) {
      return (char *)s;
    }

    if (*s == '\0') {
      return NULL;
    }
  }
}

/*
 * Heap: pool allocations with a small header so realloc knows the old size.
 */

typedef struct {
  size_t    Size;
  size_t    Reserved;   // keeps the user pointer 16-byte aligned relative to the header
} ALLOC_HEADER;

void *
malloc (size_t size)
{
  ALLOC_HEADER  *Header;

  if (size > SIZE_MAX - sizeof (ALLOC_HEADER)) {
    return NULL;
  }

  Header = AllocatePool (sizeof (ALLOC_HEADER) + size);
  if (Header == NULL) {
    return NULL;
  }

  Header->Size = size;
  return Header + 1;
}

void *
calloc (size_t count, size_t size)
{
  void  *Ptr;

  if ((size != 0) && (count > SIZE_MAX / size)) {
    return NULL;
  }

  Ptr = malloc (count * size);
  if (Ptr != NULL) {
    ZeroMem (Ptr, count * size);
  }

  return Ptr;
}

void
free (void *ptr)
{
  if (ptr != NULL) {
    FreePool ((ALLOC_HEADER *)ptr - 1);
  }
}

void *
realloc (void *ptr, size_t size)
{
  void    *New;
  size_t  Old;

  if (ptr == NULL) {
    return malloc (size);
  }

  if (size == 0) {
    free (ptr);
    return NULL;
  }

  New = malloc (size);
  if (New == NULL) {
    return NULL;
  }

  Old = ((ALLOC_HEADER *)ptr - 1)->Size;
  CopyMem (New, ptr, MIN (Old, size));
  free (ptr);
  return New;
}

int
abs (int value)
{
  return (value < 0) ? -value : value;
}

/*
 * printf family (standard C conversions: d i u x X o c s p %, flags - 0 + space #,
 * width and precision incl. *, length hh h l ll z j t).
 */

typedef struct {
  char    *Buf;
  size_t  Size;
  size_t  Len;
} FMT_OUT;

STATIC
VOID
OutChar (
  FMT_OUT  *Out,
  char     Ch
  )
{
  if (Out->Len + 1 < Out->Size) {
    Out->Buf[Out->Len] = Ch;
  }

  Out->Len++;
}

STATIC
VOID
OutRepeat (
  FMT_OUT  *Out,
  char     Ch,
  int      Count
  )
{
  while (Count-- > 0) {
    OutChar (Out, Ch);
  }
}

int
vsnprintf (char *buf, size_t size, const char *fmt, va_list ap)
{
  FMT_OUT             Out;
  int                 Left, Zero, Plus, Space, Alt;
  int                 Width, Prec, Length;
  char                Conv;
  char                Digits[24];
  int                 NumDigits;
  const char          *Str;
  int                 StrLen;
  char                Sign;
  const char          *Prefix;
  int                 PrefixLen;
  unsigned long long  Value;
  long long           SValue;
  unsigned            Base;
  int                 Upper;
  int                 Body;
  int                 Pad;

  Out.Buf  = buf;
  Out.Size = size;
  Out.Len  = 0;

  for ( ; *fmt != '\0'; fmt++) {
    if (*fmt != '%') {
      OutChar (&Out, *fmt);
      continue;
    }

    fmt++;
    Left = Zero = Plus = Space = Alt = 0;
    for ( ; ; fmt++) {
      if (*fmt == '-') {
        Left = 1;
      } else if (*fmt == '0') {
        Zero = 1;
      } else if (*fmt == '+') {
        Plus = 1;
      } else if (*fmt == ' ') {
        Space = 1;
      } else if (*fmt == '#') {
        Alt = 1;
      } else {
        break;
      }
    }

    Width = 0;
    if (*fmt == '*') {
      Width = va_arg (ap, int);
      if (Width < 0) {
        Left  = 1;
        Width = -Width;
      }

      fmt++;
    } else {
      while (*fmt >= '0' && *fmt <= '9') {
        Width = Width * 10 + (*fmt++ - '0');
      }
    }

    Prec = -1;
    if (*fmt == '.') {
      fmt++;
      Prec = 0;
      if (*fmt == '*') {
        Prec = va_arg (ap, int);
        fmt++;
      } else {
        while (*fmt >= '0' && *fmt <= '9') {
          Prec = Prec * 10 + (*fmt++ - '0');
        }
      }
    }

    //
    // 0 int, 1 long, 2 long long, 3 size_t, 4 intmax_t, 5 ptrdiff_t, -1 short, -2 char
    //
    Length = 0;
    if (*fmt == 'h') {
      Length = -1;
      if (*++fmt == 'h') {
        Length = -2;
        fmt++;
      }
    } else if (*fmt == 'l') {
      Length = 1;
      if (*++fmt == 'l') {
        Length = 2;
        fmt++;
      }
    } else if (*fmt == 'z') {
      Length = 3;
      fmt++;
    } else if (*fmt == 'j') {
      Length = 4;
      fmt++;
    } else if (*fmt == 't') {
      Length = 5;
      fmt++;
    }

    Conv = *fmt;
    if (Conv == '\0') {
      break;
    }

    Sign      = 0;
    Prefix    = "";
    PrefixLen = 0;
    Upper     = 0;
    Base      = 10;

    switch (Conv) {
      case '%':
        OutChar (&Out, '%');
        continue;

      case 'c':
        Digits[0] = (char)va_arg (ap, int);
        Str       = Digits;
        StrLen    = 1;
        goto EmitString;

      case 's':
        Str = va_arg (ap, const char *);
        if (Str == NULL) {
          Str = "(null)";
        }

        StrLen = (int)((Prec >= 0) ? strnlen (Str, (size_t)Prec) : strlen (Str));
EmitString:
        Pad = Width - StrLen;
        if (!Left) {
          OutRepeat (&Out, ' ', Pad);
        }

        while (StrLen-- > 0) {
          OutChar (&Out, *Str++);
        }

        if (Left) {
          OutRepeat (&Out, ' ', Pad);
        }

        continue;

      case 'd':
      case 'i':
        switch (Length) {
          case 1:  SValue = va_arg (ap, long);
            break;
          case 2:  SValue = va_arg (ap, long long);
            break;
          case 3:  SValue = (long long)va_arg (ap, size_t);
            break;
          case 4:  SValue = va_arg (ap, intmax_t);
            break;
          case 5:  SValue = va_arg (ap, ptrdiff_t);
            break;
          case -1: SValue = (short)va_arg (ap, int);
            break;
          case -2: SValue = (signed char)va_arg (ap, int);
            break;
          default: SValue = va_arg (ap, int);
            break;
        }

        if (SValue < 0) {
          Sign  = '-';
          Value = 0ULL - (unsigned long long)SValue;
        } else {
          Value = (unsigned long long)SValue;
          if (Plus) {
            Sign = '+';
          } else if (Space) {
            Sign = ' ';
          }
        }

        break;

      case 'u':
      case 'x':
      case 'X':
      case 'o':
        switch (Length) {
          case 1:  Value = va_arg (ap, unsigned long);
            break;
          case 2:  Value = va_arg (ap, unsigned long long);
            break;
          case 3:  Value = va_arg (ap, size_t);
            break;
          case 4:  Value = va_arg (ap, uintmax_t);
            break;
          case 5:  Value = (unsigned long long)va_arg (ap, ptrdiff_t);
            break;
          case -1: Value = (unsigned short)va_arg (ap, unsigned int);
            break;
          case -2: Value = (unsigned char)va_arg (ap, unsigned int);
            break;
          default: Value = va_arg (ap, unsigned int);
            break;
        }

        if ((Conv == 'x') || (Conv == 'X')) {
          Base  = 16;
          Upper = (Conv == 'X');
          if (Alt && (Value != 0)) {
            Prefix    = Upper ? "0X" : "0x";
            PrefixLen = 2;
          }
        } else if (Conv == 'o') {
          Base = 8;
          if (Alt) {
            Prefix    = "0";
            PrefixLen = 1;
          }
        }

        break;

      case 'p':
        Value     = (uintptr_t)va_arg (ap, void *);
        Base      = 16;
        Prefix    = "0x";
        PrefixLen = 2;
        break;

      default:
        OutChar (&Out, '%');
        OutChar (&Out, Conv);
        continue;
    }

    //
    // Number: digits, precision zeros, sign/prefix, width padding.
    //
    NumDigits = 0;
    while (Value != 0) {
      Digits[NumDigits++] = (Upper ? "0123456789ABCDEF" : "0123456789abcdef")[Value % Base];
      Value              /= Base;
    }

    if ((NumDigits == 0) && (Prec != 0)) {
      Digits[NumDigits++] = '0';
    }

    Body = (Prec > NumDigits) ? Prec : NumDigits;
    Pad  = Width - Body - PrefixLen - (Sign ? 1 : 0);

    if (!Left && !(Zero && (Prec < 0))) {
      OutRepeat (&Out, ' ', Pad);
    }

    if (Sign) {
      OutChar (&Out, Sign);
    }

    for (Str = Prefix; *Str != '\0'; Str++) {
      OutChar (&Out, *Str);
    }

    if (!Left && Zero && (Prec < 0)) {
      OutRepeat (&Out, '0', Pad);
    }

    OutRepeat (&Out, '0', Body - NumDigits);
    while (NumDigits > 0) {
      OutChar (&Out, Digits[--NumDigits]);
    }

    if (Left) {
      OutRepeat (&Out, ' ', Pad);
    }
  }

  if (size != 0) {
    Out.Buf[(Out.Len < size) ? Out.Len : size - 1] = '\0';
  }

  return (int)Out.Len;
}

int
snprintf (char *buf, size_t size, const char *fmt, ...)
{
  va_list  ap;
  int      n;

  va_start (ap, fmt);
  n = vsnprintf (buf, size, fmt, ap);
  va_end (ap);
  return n;
}

int
sprintf (char *buf, const char *fmt, ...)
{
  va_list  ap;
  int      n;

  va_start (ap, fmt);
  n = vsnprintf (buf, SIZE_MAX, fmt, ap);
  va_end (ap);
  return n;
}
