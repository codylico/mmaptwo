/*
 * \file mmaptwo.c
 * \brief Memory-mapped files
 * \author Cody Licorish (svgmovement@gmail.com)
 */
#define MMAPTWO_WIN32_DLL_INTERNAL
#define _POSIX_C_SOURCE 200809L
#include "mmaptwo.h"
#include <stdlib.h>

#ifndef MMAPTWO_MAX_CACHE
#  define MMAPTWO_MAX_CACHE 1048576
#endif /*MMAPTWO_MAX_CACHE*/

struct mmaptwo_mode_tag {
  char mode;
  char end;
  char privy;
  char bequeath;
};

/**
 * \brief Extract a mmaptwo mode tag from a mode text.
 * \param mmode the value to parse
 * \return a mmaptwo mode tag
 */
static struct mmaptwo_mode_tag mmaptwo_mode_parse(char const* mmode);

#define MMAPTWO_OS_UNIX 1
#define MMAPTWO_OS_WIN32 2

/*
 * inspired by https://stackoverflow.com/a/30971057
 * and https://stackoverflow.com/a/11351171
 */
#ifndef MMAPTWO_OS
#  if (defined _WIN32)
#    define MMAPTWO_OS MMAPTWO_OS_WIN32
#  elif (defined __unix__) || (defined(__APPLE__)&&defined(__MACH__))
#    define MMAPTWO_OS MMAPTWO_OS_UNIX
#  else
#    define MMAPTWO_OS 0
#  endif
#endif /*MMAPTWO_OS*/

#if MMAPTWO_OS == MMAPTWO_OS_UNIX
#  include <unistd.h>
#if (defined __STDC_VERSION__) && (__STDC_VERSION__ >= 199501L)
#  include <wchar.h>
#  include <string.h>
#endif /*__STDC_VERSION__*/
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <errno.h>

struct mmaptwo_unix {
  struct mmaptwo_i base;
  size_t len;
  size_t offnum;
  int fd;
  struct mmaptwo_mode_tag mt;
};

struct mmaptwo_page_unix {
  struct mmaptwo_page_i base;
  void* ptr;
  size_t len;
  size_t shift;
  size_t offnum;
};

/**
 * \brief Convert a wide string to a multibyte string.
 * \param nm the string to convert
 * \return a multibyte string on success, NULL otherwise
 */
static char* mmaptwo_wctomb(wchar_t const* nm);

/**
 * \brief Convert a mmaptwo mode text to a POSIX `open` flag.
 * \param mmode the value to convert
 * \return an `open` flag on success, zero otherwise
 */
static int mmaptwo_mode_rw_cvt(int mmode);

/**
 * \brief Convert a mmaptwo mode text to a POSIX `mmap` protection flag.
 * \param mmode the value to convert
 * \return an `mmap` protection flag on success, zero otherwise
 */
static int mmaptwo_mode_prot_cvt(int mmode);

/**
 * \brief Convert a mmaptwo mode text to a POSIX `mmap` others' flag.
 * \param mprivy the private flag to convert
 * \return an `mmap` others' flag on success, zero otherwise
 */
static int mmaptwo_mode_flag_cvt(int mprivy);

/**
 * \brief Fetch a file size from a file descriptor.
 * \param fd target file descriptor
 * \return a file size, or zero on failure
 */
static size_t mmaptwo_file_size_e(int fd);

/**
 * \brief Finish preparing a memory map interface.
 * \param fd file descriptor
 * \param mmode mode text
 * \param sz size of range to map
 * \param off offset from start of file
 * \return an interface on success, NULL otherwise
 */
static struct mmaptwo_i* mmaptwo_open_rest
  (int fd, struct mmaptwo_mode_tag const mmode, size_t sz, size_t off);
#elif MMAPTWO_OS == MMAPTWO_OS_WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <limits.h>
#  include <errno.h>

struct mmaptwo_win32 {
  struct mmaptwo_i base;
  size_t len;
  size_t shift;
  HANDLE fmd;
  HANDLE fd;
  size_t offnum;
  struct mmaptwo_mode_tag mt;
};

struct mmaptwo_page_win32 {
  struct mmaptwo_page_i base;
  void* ptr;
  size_t len;
  size_t shift;
  size_t offnum;
};

/**
 * \brief Convert a mmaptwo mode text to a `CreateFile.` desired access flag.
 * \param mmode the value to convert
 * \return an `CreateFile.` desired access flag on success, zero otherwise
 */
static DWORD mmaptwo_mode_rw_cvt(int mmode);

/**
 * \brief Convert a mmaptwo mode text to a `CreateFile.`
 *   creation disposition.
 * \param mmode the value to convert
 * \return a `CreateFile.` creation disposition on success, zero otherwise
 */
static DWORD mode_disposition_cvt(int mmode);

/**
 * \brief Convert UTF-8 encoded text to UTF-16 LE text.
 * \param nm file name encoded in UTF-8
 * \param out output string
 * \param outlen output length
 * \return an errno code
 */
static int mmaptwo_u8towc_shim
  (unsigned char const* nm, wchar_t* out, size_t* outlen);

/**
 * \brief Convert UTF-8 encoded text to UTF-16 LE text.
 * \param nm file name encoded in UTF-8
 * \return a wide string on success, NULL otherwise
 */
static wchar_t* mmaptwo_u8towc(unsigned char const* nm);

/**
 * \brief Finish preparing a memory map interface.
 * \param fd file handle
 * \param mmode mode text
 * \param sz size of range to map
 * \param off offset from start of file
 * \return an interface on success, NULL otherwise
 */
static struct mmaptwo_i* mmaptwo_open_rest
  (HANDLE fd, struct mmaptwo_mode_tag const mmode, size_t sz, size_t off);

/**
 * \brief Fetch a file size from a file descriptor.
 * \param fd target file handle
 * \return a file size, or zero on failure
 */
static size_t mmaptwo_file_size_e(HANDLE fd);

/**
 * \brief Convert a mmaptwo mode text to a
 *   `CreateFileMapping.` protection flag.
 * \param mmode the value to convert
 * \return a `CreateFileMapping.` protection flag on success, zero otherwise
 */
static DWORD mmaptwo_mode_prot_cvt(int mmode);

/**
 * \brief Convert a mmaptwo mode text to a `MapViewOfFile`
 *   desired access flag.
 * \param mmode the value to convert
 * \return a `MapViewOfFile` desired access flag on success, zero otherwise
 */
static DWORD mmaptwo_mode_access_cvt(struct mmaptwo_mode_tag const mt);
#endif /*MMAPTWO_OS*/

/**
 * \brief Destructor; closes the file and frees the space.
 * \param m map instance
 */
static void mmaptwo_mmt_dtor(struct mmaptwo_i* m);

/**
 * \brief Destructor; closes the page and frees the space.
 * \param p page instance
 */
static void mmaptwo_mmtp_dtor(struct mmaptwo_page_i* p);

/**
 * \brief Acquire a page of the space.
 * \param m map instance
 * \param sz size of page instance to request
 * \param off offset of page from start of map instance
 * \return pointer to page instance on success, NULL otherwise
 */
static struct mmaptwo_page_i* mmaptwo_mmt_acquire
  (struct mmaptwo_i* m, size_t sz, size_t off);

/**
 * \brief Check the length of the mappable area.
 * \param m map instance
 * \return the length of the mapped region exposed by this interface
 */
static size_t mmaptwo_mmt_length(struct mmaptwo_i const* m);

/**
 * \brief Check the length of the mapped area.
 * \param p page instance
 * \return the length of the mapped region exposed by this interface
 */
static size_t mmaptwo_mmtp_length(struct mmaptwo_page_i const* p);

/**
 * \brief Check the offset of the mappable area.
 * \param m map instance
 * \return the offset of the mappable exposed by this interface, from start
 *   of file
 */
static size_t mmaptwo_mmt_offset(struct mmaptwo_i const* m);

/**
 * \brief Check the offset of the mapped area.
 * \param p page instance
 * \return the offset of the mapped region exposed by this interface,
 *   from start of mappable
 */
static size_t mmaptwo_mmtp_offset(struct mmaptwo_page_i const* p);

/**
 * \brief Get the start of the mapped area.
 * \param p page instance
 * \return a pointer to the start of the requested mapped area
 */
static void* mmaptwo_mmtp_get(struct mmaptwo_page_i* p);

/**
 * \brief Get the start of the mapped area.
 * \param p page instance
 * \return a pointer to the start of the requested mapped area
 */
static void const* mmaptwo_mmtp_getconst(struct mmaptwo_page_i const* p);


/* BEGIN static functions */
struct mmaptwo_mode_tag mmaptwo_mode_parse(char const* mmode) {
  struct mmaptwo_mode_tag out = { 0, 0, 0, 0 };
  int i;
  for (i = 0; i < 8; ++i) {
    switch (mmode[i]) {
    case 0: /* NUL termination */
      return out;
    case mmaptwo_mode_write:
      out.mode = mmaptwo_mode_write;
      break;
    case mmaptwo_mode_read:
      out.mode = mmaptwo_mode_read;
      break;
    case mmaptwo_mode_end:
      out.end = mmaptwo_mode_end;
      break;
    case mmaptwo_mode_private:
      out.privy = mmaptwo_mode_private;
      break;
    case mmaptwo_mode_bequeath:
      out.bequeath = mmaptwo_mode_bequeath;
      break;
    }
  }
  return out;
}

#if MMAPTWO_OS == MMAPTWO_OS_UNIX
char* mmaptwo_wctomb(wchar_t const* nm) {
#if (defined __STDC_VERSION__) && (__STDC_VERSION__ >= 199409L)
  /* use multibyte conversion */
  size_t ns;
  char* out;
  /* try the length */{
    mbstate_t mbs;
    wchar_t const* test_nm = nm;
    memset(&mbs, 0, sizeof(mbs));
    ns = wcsrtombs(NULL, &test_nm, 0, &mbs);
  }
  if (ns == (size_t)(-1)
  ||  ns == ~((size_t)0))
  {
    /* conversion error caused by bad sequence, so */return NULL;
  }
  out = calloc(ns+1, sizeof(char));
  if (out) {
    mbstate_t mbs;
    wchar_t const* test_nm = nm;
    memset(&mbs, 0, sizeof(mbs));
    wcsrtombs(out, &test_nm, ns+1, &mbs);
    out[ns] = 0;
  }
  return out;
#else
  /* no thread-safe version, so give up */
  return NULL;
#endif /*__STDC_VERSION__*/
}

int mmaptwo_mode_rw_cvt(int mmode) {
#if (defined O_CLOEXEC)
  int const fast_no_bequeath = (int)(O_CLOEXEC);
#else
  int const fast_no_bequeath = 0;
#endif /*O_CLOEXEC*/
  switch (mmode) {
  case mmaptwo_mode_write:
    return O_RDWR|fast_no_bequeath;
  case mmaptwo_mode_read:
    return O_RDONLY|fast_no_bequeath;
  default:
    return 0;
  }
}

int mmaptwo_mode_prot_cvt(int mmode) {
  switch (mmode) {
  case mmaptwo_mode_write:
    return PROT_WRITE|PROT_READ;
  case mmaptwo_mode_read:
    return PROT_READ;
  default:
    return 0;
  }
}

int mmaptwo_mode_flag_cvt(int mprivy) {
  return mprivy ? MAP_PRIVATE : MAP_SHARED;
}

size_t mmaptwo_file_size_e(int fd) {
  struct stat fsi;
  memset(&fsi, 0, sizeof(fsi));
  /* stat pull */{
    int const res = fstat(fd, &fsi);
    if (res != 0) {
      return 0u;
    } else return (size_t)(fsi.st_size);
  }
}

struct mmaptwo_i* mmaptwo_open_rest
  (int fd, struct mmaptwo_mode_tag const mt, size_t sz, size_t off)
{
  struct mmaptwo_unix *const out = calloc(1, sizeof(struct mmaptwo_unix));
  if (out == NULL) {
    close(fd);
    return NULL;
  }
  /* assign the close-on-exec flag */{
    int const old_flags = fcntl(fd, F_GETFD);
    int bequeath_break = 0;
    if (old_flags < 0) {
      bequeath_break = 1;
    } else if (mt.bequeath) {
      bequeath_break = (fcntl(fd, F_SETFD, old_flags&(~FD_CLOEXEC)) < 0);
    } else {
      bequeath_break = (fcntl(fd, F_SETFD, old_flags|FD_CLOEXEC) < 0);
    }
    if (bequeath_break) {
      close(fd);
      free(out);
      return NULL;
    }
  }
  if (mt.end) /* fix map size */{
    size_t const xsz = mmaptwo_file_size_e(fd);
    if (xsz < off)
      sz = 0 /*to fail*/;
    else sz = xsz-off;
  }
  if (sz == 0)/* then fail */ {
    close(fd);
    free(out);
    errno = EDOM;
    return NULL;
  }
  /* initialize the interface */{
    out->len = sz;
    out->fd = fd;
    out->offnum = off;
    out->mt = mt;
    out->base.mmt_dtor = &mmaptwo_mmt_dtor;
    out->base.mmt_acquire = &mmaptwo_mmt_acquire;
    out->base.mmt_offset = &mmaptwo_mmt_offset;
    out->base.mmt_length = &mmaptwo_mmt_length;
  }
  return (struct mmaptwo_i*)out;
}

void mmaptwo_mmt_dtor(struct mmaptwo_i* m) {
  struct mmaptwo_unix* const mu = (struct mmaptwo_unix*)m;
  close(mu->fd);
  mu->fd = -1;
  free(mu);
  return;
}

void mmaptwo_mmtp_dtor(struct mmaptwo_page_i* p) {
  struct mmaptwo_page_unix* const pu = (struct mmaptwo_page_unix*)p;
  munmap(pu->ptr, pu->len);
  pu->ptr = NULL;
  free(pu);
  return;
}

void* mmaptwo_mmtp_get(struct mmaptwo_page_i* p) {
  struct mmaptwo_page_unix* const pu = (struct mmaptwo_page_unix*)p;
  return pu->ptr+pu->shift;
}
void const* mmaptwo_mmtp_getconst(struct mmaptwo_page_i const* p) {
  struct mmaptwo_page_unix const* const pu =
    (struct mmaptwo_page_unix const*)p;
  return pu->ptr+pu->shift;
}

struct mmaptwo_page_i* mmaptwo_mmt_acquire
  (struct mmaptwo_i* m, size_t sz, size_t pre_off)
{
  struct mmaptwo_unix* const mu = (struct mmaptwo_unix*)m;
  size_t off;
  struct mmaptwo_page_unix* out;
  size_t fullsize;
  size_t fullshift;
  void *ptr;
  off_t fulloff;
  /* repair input size and offset */{
    if (pre_off > mu->len
    ||  sz > mu->len - pre_off
    ||  sz == 0u)
    {
      errno = EDOM;
      return NULL;
    }
    off = pre_off + mu->offnum;
  }
  out = calloc(1,sizeof(struct mmaptwo_page_unix));
  if (out == NULL) {
    /* give up, and */return NULL;
  }
  /* fix to page sizes */{
    long const psize = sysconf(_SC_PAGE_SIZE);
    fullsize = sz;
    if (psize > 0) {
      /* adjust the offset */
      fullshift = off%((unsigned long)psize);
      fulloff = (off_t)(off-fullshift);
      if (fullshift >= ((~(size_t)0u)-sz)) {
        /* range fix failure */
        free(out);
        errno = ERANGE;
        return NULL;
      } else fullsize += fullshift;
    } else fulloff = (off_t)off;
  }
  ptr = mmap(NULL, fullsize, mmaptwo_mode_prot_cvt(mu->mt.mode),
       mmaptwo_mode_flag_cvt(mu->mt.privy), mu->fd, fulloff);
  if (ptr == NULL) {
    free(out);
    return NULL;
  }
  /* initialize the interface */{
    out->ptr = ptr;
    out->len = fullsize;
    out->shift = fullshift;
    out->offnum = pre_off;
    out->base.mmtp_dtor = &mmaptwo_mmtp_dtor;
    out->base.mmtp_get = &mmaptwo_mmtp_get;
    out->base.mmtp_getconst = &mmaptwo_mmtp_getconst;
    out->base.mmtp_offset = &mmaptwo_mmtp_offset;
    out->base.mmtp_length = &mmaptwo_mmtp_length;
  }
  return (struct mmaptwo_page_i*)out;
}

size_t mmaptwo_mmt_length(struct mmaptwo_i const* m) {
  struct mmaptwo_unix const* const mu = (struct mmaptwo_unix const*)m;
  return mu->len;
}

size_t mmaptwo_mmtp_length(struct mmaptwo_page_i const* p) {
  struct mmaptwo_page_unix const* const pu =
    (struct mmaptwo_page_unix const*)p;
  return pu->len-pu->shift;
}

size_t mmaptwo_mmt_offset(struct mmaptwo_i const* m) {
  struct mmaptwo_unix const* const mu = (struct mmaptwo_unix const*)m;
  return mu->offnum;
}

size_t mmaptwo_mmtp_offset(struct mmaptwo_page_i const* p) {
  struct mmaptwo_page_unix const* const pu =
    (struct mmaptwo_page_unix const*)p;
  return pu->offnum;
}
#elif MMAPTWO_OS == MMAPTWO_OS_WIN32
DWORD mmaptwo_mode_rw_cvt(int mmode) {
  switch (mmode) {
  case mmaptwo_mode_write:
    return GENERIC_READ|GENERIC_WRITE;
  case mmaptwo_mode_read:
    return GENERIC_READ;
  default:
    return 0;
  }
}

DWORD mmaptwo_mode_disposition_cvt(int mmode) {
  switch (mmode) {
  case mmaptwo_mode_write:
    return OPEN_ALWAYS;
  case mmaptwo_mode_read:
    return OPEN_EXISTING;
  default:
    return 0;
  }
}

int mmaptwo_u8towc_shim
  (unsigned char const* nm, wchar_t* out, size_t* outlen)
{
  size_t n = 0;
  unsigned char const* p;
  static size_t const sz_max = UINT_MAX/2u-4u;
  for (p = nm; *p && n < sz_max; ++p) {
    unsigned char const v = *p;
    if (n >= sz_max) {
      return ERANGE;
    }
    if (v < 0x80) {
      /* Latin-1 compatibility */
      if (out != NULL) {
        out[n] = v;
      }
      n += 1;
    } else if (v < 0xC0) {
      return EILSEQ;
    } else if (v < 0xE0) {
      /* check extension codes */
      unsigned int i;
      unsigned long int qv = v&31;
      for (i = 0; i < 1; ++i) {
        unsigned char const v1 = *(p+i);
        if (v1 < 0x80 || v1 >= 0xC0) {
          return EILSEQ;
        } else qv = (qv<<6)|(v1&63);
      }
      if (out != NULL) {
        out[n] = (wchar_t)qv;
      }
      n += 1;
      p += 1;
    } else if (v < 0xF0) {
      /* check extension codes */
      unsigned int i;
      unsigned long int qv = v&15;
      for (i = 0; i < 2; ++i) {
        unsigned char const v1 = *(p+i);
        if (v1 < 0x80 || v1 >= 0xC0) {
          return EILSEQ;
        } else qv = (qv<<6)|(v1&63);
      }
      if (out != NULL) {
        out[n] = (wchar_t)qv;
      }
      n += 1;
      p += 2;
    } else if (v < 0xF8) {
      /* check extension codes */
      unsigned int i;
      unsigned long int qv = v&3;
      for (i = 0; i < 3; ++i) {
        unsigned char const v1 = *(p+i);
        if (v1 < 0x80 || v1 >= 0xC0) {
          return EILSEQ;
        } else qv = (qv<<6)|(v1&63);
      }
      if (qv >= 0x10FFFFL) {
        return EILSEQ;
      }
      if (out != NULL) {
        qv -= 0x10000;
        out[n] = (wchar_t)(0xD800 | ((qv>>10)&1023));
        out[n+1] = (wchar_t)(0xDC00 | (qv&1023));
      }
      n += 2;
      p += 3;
    } else {
      return EILSEQ; /* since beyond U+1FFFFF, no valid UTF-16 encoding */
    }
  }
  (*outlen) = n;
  return 0;
}

wchar_t* mmaptwo_u8towc(unsigned char const* nm) {
  /* use in-house wide character conversion */
  size_t ns;
  wchar_t* out;
  /* try the length */{
    int err = mmaptwo_u8towc_shim(nm, NULL, &ns);
    if (err != 0) {
      /* conversion error caused by bad sequence, so */return NULL;
    }
  }
  out = (wchar_t*)calloc(ns+1, sizeof(wchar_t));
  if (out != NULL) {
    mmaptwo_u8towc_shim(nm, out, &ns);
    out[ns] = 0;
  }
  return out;
}

size_t mmaptwo_file_size_e(HANDLE fd) {
  LARGE_INTEGER sz;
  BOOL res = GetFileSizeEx(fd, &sz);
  if (res) {
#if (defined ULLONG_MAX)
    return (size_t)sz.QuadPart;
#else
    return (size_t)((sz.u.LowPart)|(sz.u.HighPart<<32));
#endif /*ULLONG_MAX*/
  } else return 0u;
}

DWORD mmaptwo_mode_prot_cvt(int mmode) {
  switch (mmode) {
  case mmaptwo_mode_write:
    return PAGE_READWRITE;
  case mmaptwo_mode_read:
    return PAGE_READONLY;
  default:
    return 0;
  }
}

DWORD mmaptwo_mode_access_cvt(struct mmaptwo_mode_tag const mt) {
  DWORD flags = 0;
  switch (mt.mode) {
  case mmaptwo_mode_write:
    flags = FILE_MAP_READ|FILE_MAP_WRITE;
    break;
  case mmaptwo_mode_read:
    flags = FILE_MAP_READ;
    break;
  default:
    return 0;
  }
  if (mt.privy) {
    flags |= FILE_MAP_COPY;
  }
  return flags;
}

struct mmaptwo_i* mmaptwo_open_rest
  (HANDLE fd, struct mmaptwo_mode_tag const mt, size_t sz, size_t off)
{
  /*
   * based on
   * https://docs.microsoft.com/en-us/windows/win32/memory/
   *   creating-a-view-within-a-file
   */
  struct mmaptwo_win32 *const out = calloc(1, sizeof(struct mmaptwo_win32));
  void *ptr;
  size_t fullsize;
  size_t fullshift;
  size_t fulloff;
  size_t extended_size;
  size_t const size_clamp = mmaptwo_file_size_e(fd);
  HANDLE fmd;
  SECURITY_ATTRIBUTES cfmsa;
  if (out == NULL) {
    CloseHandle(fd);
    return NULL;
  }
  if (mt.end) /* fix map size */{
    size_t const xsz = size_clamp;
    if (xsz < off) {
      /* reject non-ending zero parameter */
      CloseHandle(fd);
      free(out);
      return NULL;
    } else sz = xsz-off;
  } else if (sz == 0) {
    /* reject non-ending zero parameter */
    CloseHandle(fd);
    free(out);
    return NULL;
  }
  /* fix to allocation granularity */{
    DWORD psize;
    /* get the allocation granularity */{
      SYSTEM_INFO s_info;
      GetSystemInfo(&s_info);
      psize = s_info.dwAllocationGranularity;
    }
    fullsize = sz;
    if (psize > 0) {
      /* adjust the offset */
      fullshift = off;
      fulloff = (off-fullshift);
      if (fullshift >= ((~(size_t)0u)-sz)) {
        /* range fix failure */
        CloseHandle(fd);
        free(out);
        errno = ERANGE;
        return NULL;
      } else fullsize += fullshift;
      /* adjust the size */{
        size_t size_shift = (fullsize % psize);
        if (size_shift > 0) {
          extended_size = fullsize + (psize - size_shift);
        } else extended_size = fullsize;
      }
    } else {
      fulloff = off;
      extended_size = sz;
    }
  }
  /* prepare the security attributes */{
    memset(&cfmsa, 0, sizeof(cfmsa));
    cfmsa.nLength = sizeof(cfmsa);
    cfmsa.lpSecurityDescriptor = NULL;
    cfmsa.bInheritHandle = (BOOL)(mt.bequeath ? TRUE : FALSE);
  }
  /* check for potential overflow */{
    if (fulloff >= ((~(size_t)0u)-extended_size)) {
      /* range fix failure */
      CloseHandle(fd);
      free(out);
      errno = ERANGE;
      return NULL;
    }
  }
  /* create the file mapping object */{
    /*
     * clamp size to end of file;
     * based on https://stackoverflow.com/a/46014637
     */
    size_t const fullextent = size_clamp > extended_size+fulloff
        ? extended_size + fulloff
        : size_clamp;
    fmd = CreateFileMappingA(
        fd, /*hFile*/
        &cfmsa, /*lpFileMappingAttributes*/
        mmaptwo_mode_prot_cvt(mt.mode), /*flProtect*/
        (DWORD)((fullextent>>32)&0xFFffFFff), /*dwMaximumSizeHigh*/
        (DWORD)(fullextent&0xFFffFFff), /*dwMaximumSizeLow*/
        NULL /*lpName*/
      );
  }
  if (fmd == NULL) {
    /* file mapping failed */
    CloseHandle(fd);
    free(out);
    return NULL;
  }
  /* initialize the interface */{
    out->len = fullsize;
    out->fd = fd;
    out->fmd = fmd;
    out->shift = fullshift;
    out->offnum = off;
    out->mt = mt;
    out->base.mmt_dtor = &mmaptwo_mmt_dtor;
    out->base.mmt_acquire = &mmaptwo_mmt_acquire;
    out->base.mmt_offset = &mmaptwo_mmt_offset;
    out->base.mmt_length = &mmaptwo_mmt_length;
  }
  return (struct mmaptwo_i*)out;
}

struct mmaptwo_page_i* mmaptwo_mmt_acquire
  (struct mmaptwo_i* m, size_t sz, size_t pre_off)
{
  struct mmaptwo_win32* const mu = (struct mmaptwo_win32*)m;
  struct mmaptwo_page_win32* out;
  size_t fullsize;
  size_t off;
  size_t fullshift;
  void *ptr;
  size_t fulloff;
  out = calloc(1, sizeof(struct mmaptwo_page_win32));
  if (out == NULL) {
    return NULL;
  }
  /* repair input size and offset */{
    size_t const shifted_len = mu->len - mu->shift;
    if (pre_off > shifted_len
    ||  sz > shifted_len - pre_off
    ||  sz == 0u)
    {
      errno = EDOM;
      return NULL;
    }
    off = pre_off + mu->offnum;
  }
  /* compute new offsets */{
    DWORD psize;
    /* get the allocation granularity */{
      SYSTEM_INFO s_info;
      GetSystemInfo(&s_info);
      psize = s_info.dwAllocationGranularity;
    }
    fullsize = sz;
    if (psize > 0) {
      /* adjust the offset */
      fullshift = off%psize;
      fulloff = (off-fullshift);
      if (fullshift >= ((~(size_t)0u)-sz)) {
        /* range fix failure */
        free(out);
        errno = ERANGE;
        return NULL;
      } else fullsize += fullshift;
    } else {
      fulloff = off;
    }
  }
  /* adjust backward to file-mapping object */{
    fulloff -= (mu->offnum - mu->shift);
  }
  ptr = MapViewOfFile(
      mu->fmd, /*hFileMappingObject*/
      mmaptwo_mode_access_cvt(mu->mt), /*dwDesiredAccess*/
      (DWORD)((fulloff>>32)&0xFFffFFff), /* dwFileOffsetHigh */
      (DWORD)(fulloff&0xFFffFFff), /* dwFileOffsetLow */
      (SIZE_T)(fullsize) /* dwNumberOfBytesToMap */
    );
  if (ptr == NULL) {
    free(out);
    return NULL;
  }
  /* initialize the interface */{
    out->ptr = ptr;
    out->len = fullsize;
    out->offnum = pre_off;
    out->shift = fullshift;
    out->base.mmtp_dtor = &mmaptwo_mmtp_dtor;
    out->base.mmtp_get = &mmaptwo_mmtp_get;
    out->base.mmtp_getconst = &mmaptwo_mmtp_getconst;
    out->base.mmtp_length = &mmaptwo_mmtp_length;
    out->base.mmtp_offset = &mmaptwo_mmtp_offset;
  }
  return (struct mmaptwo_page_i*)out;
}

void mmaptwo_mmtp_dtor(struct mmaptwo_page_i* m) {
  struct mmaptwo_page_win32* const mu = (struct mmaptwo_page_win32*)m;
  UnmapViewOfFile(mu->ptr);
  mu->ptr = NULL;
  free(mu);
  return;
}

void mmaptwo_mmt_dtor(struct mmaptwo_i* m) {
  struct mmaptwo_win32* const mu = (struct mmaptwo_win32*)m;
  CloseHandle(mu->fmd);
  mu->fmd = NULL;
  CloseHandle(mu->fd);
  mu->fd = NULL;
  free(mu);
  return;
}

size_t mmaptwo_mmt_offset(struct mmaptwo_i const* m) {
  struct mmaptwo_win32* const mu = (struct mmaptwo_win32*)m;
  return mu->offnum;
}
size_t mmaptwo_mmtp_offset(struct mmaptwo_page_i const* m) {
  struct mmaptwo_page_win32* const mu = (struct mmaptwo_page_win32*)m;
  return mu->offnum;
}

size_t mmaptwo_mmt_length(struct mmaptwo_i const* m) {
  struct mmaptwo_win32* const mu = (struct mmaptwo_win32*)m;
  return mu->len-mu->shift;
}
size_t mmaptwo_mmtp_length(struct mmaptwo_page_i const* m) {
  struct mmaptwo_page_win32* const mu = (struct mmaptwo_page_win32*)m;
  return mu->len-mu->shift;
}

void* mmaptwo_mmtp_get(struct mmaptwo_page_i* p) {
  struct mmaptwo_page_win32* const pu = (struct mmaptwo_page_win32*)p;
  return pu->ptr+pu->shift;
}
void const* mmaptwo_mmtp_getconst(struct mmaptwo_page_i const* p) {
  struct mmaptwo_page_win32 const* const pu =
    (struct mmaptwo_page_win32 const*)p;
  return pu->ptr+pu->shift;
}
#endif /*MMAPTWO_OS*/
/* END   static functions */

/* BEGIN configuration functions */
int mmaptwo_get_os(void) {
  return (int)(MMAPTWO_OS);
}

int mmaptwo_check_bequeath_stop(void) {
#if MMAPTWO_OS == MMAPTWO_OS_UNIX
#  if (defined O_CLOEXEC)
  return 1;
#  else
  return 0;
#  endif /*O_CLOEXEC*/
#elif MMAPTWO_OS == MMAPTWO_OS_WIN32
  return 1;
#else
  return -1;
#endif /*MMAPTWO_OS*/
}

size_t mmaptwo_get_page_size(void) {
#if MMAPTWO_OS == MMAPTWO_OS_UNIX
  return (size_t)(sysconf(_SC_PAGE_SIZE));
#elif MMAPTWO_OS == MMAPTWO_OS_WIN32
  SYSTEM_INFO s_info;
  GetSystemInfo(&s_info);
  return (size_t)(s_info.dwAllocationGranularity);
#else
  return 1;
#endif /*MMAPTWO_OS*/
}
/* END   configuration functions */

/* BEGIN helper functions */
void mmaptwo_page_close(struct mmaptwo_page_i* p) {
  if (p != NULL) {
    (*p).mmtp_dtor(p);
  }
  return;
}

void* mmaptwo_page_get(struct mmaptwo_page_i* p) {
  return (*p).mmtp_get(p);
}

void const* mmaptwo_page_get_const(struct mmaptwo_page_i const* p) {
  return (*p).mmtp_getconst(p);
}

size_t mmaptwo_page_length(struct mmaptwo_page_i const* p) {
  return (*p).mmtp_length(p);
}

size_t mmaptwo_page_offset(struct mmaptwo_page_i const* p) {
  return (*p).mmtp_offset(p);
}

void mmaptwo_close(struct mmaptwo_i* m) {
  if (m != NULL) {
    (*m).mmt_dtor(m);
  }
  return;
}

struct mmaptwo_page_i* mmaptwo_acquire
  (struct mmaptwo_i* m, size_t siz, size_t off)
{
  return (*m).mmt_acquire(m, siz, off);
}

size_t mmaptwo_length(struct mmaptwo_i const* m) {
  return (*m).mmt_length(m);
}

size_t mmaptwo_offset(struct mmaptwo_i const* m) {
  return (*m).mmt_offset(m);
}
/* END   helper functions */

/* BEGIN open functions */
#if MMAPTWO_OS == MMAPTWO_OS_UNIX
struct mmaptwo_i* mmaptwo_open
  (char const* nm, char const* mode, size_t sz, size_t off)
{
  int fd;
  struct mmaptwo_mode_tag const mt = mmaptwo_mode_parse(mode);
  fd = open(nm, mmaptwo_mode_rw_cvt(mt.mode));
  if (fd == -1) {
    /* can't open file, so */return NULL;
  }
  return mmaptwo_open_rest(fd, mt, sz, off);
}

struct mmaptwo_i* mmaptwo_u8open
  (unsigned char const* nm, char const* mode, size_t sz, size_t off)
{
  int fd;
  struct mmaptwo_mode_tag const mt = mmaptwo_mode_parse(mode);
  fd = open((char const*)nm, mmaptwo_mode_rw_cvt(mt.mode));
  if (fd == -1) {
    /* can't open file, so */return NULL;
  }
  return mmaptwo_open_rest(fd, mt, sz, off);
}

struct mmaptwo_i* mmaptwo_wopen
  (wchar_t const* nm, char const* mode, size_t sz, size_t off)
{
  int fd;
  struct mmaptwo_mode_tag const mt = mmaptwo_mode_parse(mode);
  char* const mbfn = mmaptwo_wctomb(nm);
  if (mbfn == NULL) {
    /* conversion failure, so give up */
    free(mbfn);
    return NULL;
  }
  fd = open(mbfn, mmaptwo_mode_rw_cvt(mt.mode));
  free(mbfn);
  if (fd == -1) {
    /* can't open file, so */return NULL;
  }
  return mmaptwo_open_rest(fd, mt, sz, off);
}
#elif MMAPTWO_OS == MMAPTWO_OS_WIN32
struct mmaptwo_i* mmaptwo_open
  (char const* nm, char const* mode, size_t sz, size_t off)
{
  HANDLE fd;
  struct mmaptwo_mode_tag const mt = mmaptwo_mode_parse(mode);
  SECURITY_ATTRIBUTES cfsa;
  memset(&cfsa, 0, sizeof(cfsa));
  cfsa.nLength = sizeof(cfsa);
  cfsa.lpSecurityDescriptor = NULL;
  cfsa.bInheritHandle = (BOOL)(mt.bequeath ? TRUE : FALSE);
  fd = CreateFileA(
      nm, mmaptwo_mode_rw_cvt(mt.mode),
      FILE_SHARE_READ|FILE_SHARE_WRITE,
      &cfsa,
      mmaptwo_mode_disposition_cvt(mt.mode),
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (fd == INVALID_HANDLE_VALUE) {
    /* can't open file, so */return NULL;
  }
  return mmaptwo_open_rest(fd, mt, sz, off);
}

struct mmaptwo_i* mmaptwo_u8open
  (unsigned char const* nm, char const* mode, size_t sz, size_t off)
{
  HANDLE fd;
  struct mmaptwo_mode_tag const mt = mmaptwo_mode_parse(mode);
  wchar_t* const wcfn = mmaptwo_u8towc(nm);
  SECURITY_ATTRIBUTES cfsa;
  memset(&cfsa, 0, sizeof(cfsa));
  cfsa.nLength = sizeof(cfsa);
  cfsa.lpSecurityDescriptor = NULL;
  cfsa.bInheritHandle = (BOOL)(mt.bequeath ? TRUE : FALSE);
  if (wcfn == NULL) {
    /* conversion failure, so give up */
    return NULL;
  }
  fd = CreateFileW(
      wcfn, mmaptwo_mode_rw_cvt(mt.mode),
      FILE_SHARE_READ|FILE_SHARE_WRITE,
      &cfsa,
      mmaptwo_mode_disposition_cvt(mt.mode),
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  free(wcfn);
  if (fd == INVALID_HANDLE_VALUE) {
    /* can't open file, so */return NULL;
  }
  return mmaptwo_open_rest(fd, mt, sz, off);
}

struct mmaptwo_i* mmaptwo_wopen
  (wchar_t const* nm, char const* mode, size_t sz, size_t off)
{
  HANDLE fd;
  struct mmaptwo_mode_tag const mt = mmaptwo_mode_parse(mode);
  SECURITY_ATTRIBUTES cfsa;
  memset(&cfsa, 0, sizeof(cfsa));
  cfsa.nLength = sizeof(cfsa);
  cfsa.lpSecurityDescriptor = NULL;
  cfsa.bInheritHandle = (BOOL)(mt.bequeath ? TRUE : FALSE);
  fd = CreateFileW(
      nm, mmaptwo_mode_rw_cvt(mt.mode),
      FILE_SHARE_READ|FILE_SHARE_WRITE,
      &cfsa,
      mmaptwo_mode_disposition_cvt(mt.mode),
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (fd == INVALID_HANDLE_VALUE) {
    /* can't open file, so */return NULL;
  }
  return mmaptwo_open_rest(fd, mt, sz, off);
}
#else
struct mmaptwo_i* mmaptwo_open
  (char const* nm, char const* mode, size_t sz, size_t off)
{
  /* no-op */
  return NULL;
}

struct mmaptwo_i* mmaptwo_u8open
  (unsigned char const* nm, char const* mode, size_t sz, size_t off)
{
  /* no-op */
  return NULL;
}

struct mmaptwo_i* mmaptwo_wopen
  (wchar_t const* nm, char const* mode, size_t sz, size_t off)
{
  /* no-op */
  return NULL;
}
#endif /*MMAPTWO_ON_UNIX*/
/* END   open functions */

