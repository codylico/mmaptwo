/*
 * \file mmaptwo.h
 * \brief Memory-mapped files
 * \author Cody Licorish (svgmovement@gmail.com)
 */
#ifndef hg_MMapTwo_mmapTwo_H_
#define hg_MMapTwo_mmapTwo_H_

#include <stddef.h>

#ifdef MMAPTWO_WIN32_DLL
#  ifdef MMAPTWO_WIN32_DLL_INTERNAL
#    define MMAPTWO_API __declspec(dllexport)
#  else
#    define MMAPTWO_API __declspec(dllimport)
#  endif /*MMAPTWO_DLL_INTERNAL*/
#else
#  define MMAPTWO_API
#endif /*MMAPTWO_WIN32_DLL*/

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief Operating system identifier.
 */
enum mmaptwo_os {
  mmaptwo_os_none = 0,
  mmaptwo_os_unix = 1,
  mmaptwo_os_win32 = 2
};

/**
 * \brief File memory access modes.
 */
enum mmaptwo_mode {
  /**
   * \brief Open for reading only.
   */
  mmaptwo_mode_read = 0x72,
  /**
   * \brief Open for reading and writing.
   */
  mmaptwo_mode_write = 0x77,
  /**
   * \brief Map until end of file.
   * \note When this parameter is active, the open functions
   *   \link mmaptwo_open \endlink, \link mmaptwo_u8open \endlink and
   *   \link mmaptwo_wopen \endlink will ignore the size parameter.
   */
  mmaptwo_mode_end = 0x65,
  /**
   * \brief Make a private mapping.
   * \note Changes in pages remain private to the process.
   */
  mmaptwo_mode_private = 0x70,

  /**
   * \brief Allow child processes to inherit this mapping.
   * \note If not using bequeath, the caller of
   *   \link mmaptwo_open \endlink, \link mmaptwo_u8open \endlink or
   *   \link mmaptwo_wopen \endlink must give time for the function
   *   to return. Otherwise, the file descriptor of the mapped file
   *   may leak.
   */
  mmaptwo_mode_bequeath = 0x71
};

/**
 * \brief Memory reading part of memory-mapped input-output interface.
 */
struct mmaptwo_page_i {
  /**
   * \brief Destructor; closes the file and frees the space.
   * \param m map instance
   */
  void (*mmtp_dtor)(struct mmaptwo_page_i* m);
  /**
   * \brief Acquire a writable pointer to the space.
   * \param m map instance
   * \return pointer to space
   */
  void* (*mmtp_get)(struct mmaptwo_page_i* m);
  /**
   * \brief Acquire a pointer to the space.
   * \param m map instance
   * \return pointer to space
   */
  void const* (*mmtp_getconst)(struct mmaptwo_page_i const* m);
  /**
   * \brief Check the length of the mapped area.
   * \param m map instance
   * \return the length of the mapped region exposed by this interface
   */
  size_t (*mmtp_length)(struct mmaptwo_page_i const* m);
  /**
   * \brief Check the offset of the mappable area.
   * \param m map instance
   * \return the offset of the mappable region from start of the file
   *   exposed by this interface
   */
  size_t (*mmtp_offset)(struct mmaptwo_page_i const* m);
};


/**
 * \brief File acquisition part of memory-mapped input-output interface.
 */
struct mmaptwo_i {
  /**
   * \brief Destructor; closes the file.
   * \param m map instance
   * \note The destructor will not free any acquired pages!
   */
  void (*mmt_dtor)(struct mmaptwo_i* m);
  /**
   * \brief Acquire a page interface into the space.
   * \param m map instance
   * \param siz size of the map to acquire
   * \param off offset from start of mappable interface
   * \return pointer to a page interface on success, NULL otherwise
   */
  struct mmaptwo_page_i* (*mmt_acquire)
    (struct mmaptwo_i* m, size_t siz, size_t off);
  /**
   * \brief Check the length of the mapped area.
   * \param m map instance
   * \return the length of the mapped region exposed by this interface
   */
  size_t (*mmt_length)(struct mmaptwo_i const* m);
  /**
   * \brief Check the offset of the mappable area.
   * \param m map instance
   * \return the offset of the mappable region from start of the file
   *   exposed by this interface
   */
  size_t (*mmt_offset)(struct mmaptwo_i const* m);
};

/* BEGIN configurations */
/**
 * \brief Check the library's target backend.
 * \return a \link mmaptwo_os \endlink value
 */
MMAPTWO_API
int mmaptwo_get_os(void);

/**
 * \brief Check whether the library can handle possible race conditions
 *   involving file bequeath prevention. Such prevention may be necessary
 *   when starting child processes.
 * \return nonzero if file bequeath prevention is race-proof, zero
 *   otherwise
 */
MMAPTWO_API
int mmaptwo_check_bequeath_stop(void);

/**
 * \brief Check what this library thinks the page size is.
 * \return a page size
 * \note Users of this library should not need this value
 *   to use the library.
 */
MMAPTWO_API
size_t mmaptwo_get_page_size(void);
/* END   configurations */

/* BEGIN helper functions */
/**
 * \brief Closes the page and frees the space.
 * \param p page instance
 * \note The source map instance, which holds the file descriptor,
 *   remains unaffected by this function.
 */
MMAPTWO_API
void mmaptwo_page_close(struct mmaptwo_page_i* p);

/**
 * \brief Acquire a pointer to the space.
 * \param p page instance
 * \return pointer to space
 */
MMAPTWO_API
void* mmaptwo_page_get(struct mmaptwo_page_i* p);

/**
 * \brief Acquire a pointer to the space.
 * \param p page instance
 * \return pointer to space
 */
MMAPTWO_API
void const* mmaptwo_page_get_const(struct mmaptwo_page_i const* p);

/**
 * \brief Check the length of the mapped area.
 * \param p page instance
 * \return the length of the mapped region exposed by this interface
 */
MMAPTWO_API
size_t mmaptwo_page_length(struct mmaptwo_page_i const* p);

/**
 * \brief Check the offset of the mappable area.
 * \param p page instance
 * \return the offset of the mappable region from start of the
 *   source map instance
 */
MMAPTWO_API
size_t mmaptwo_page_offset(struct mmaptwo_page_i const* p);

/**
 * \brief Helper function closes the file.
 * \param m map instance
 * \note The destructor will not free any acquired pages!
 */
MMAPTWO_API
void mmaptwo_close(struct mmaptwo_i* m);

/**
 * \brief Helper function acquires file data.
 * \param m map instance
 * \param siz size of the map to acquire
 * \param off offset into the file data
 * \return pointer to page interface on success, NULL otherwise
 */
MMAPTWO_API
struct mmaptwo_page_i* mmaptwo_acquire
  (struct mmaptwo_i* m, size_t siz, size_t off);

/**
 * \brief Helper function to check the length of the map instance.
 * \param m map instance
 * \return the length of the map instance
 */
MMAPTWO_API
size_t mmaptwo_length(struct mmaptwo_i const* m);

/**
 * \brief Helper function to check the file-based offset of the space.
 * \param m map instance
 * \return the offset of the map instance from start of file
 */
MMAPTWO_API
size_t mmaptwo_offset(struct mmaptwo_i const* m);
/* END   helper functions */

/* BEGIN open functions */
/**
 * \brief Open a file using a narrow character name.
 * \param nm name of file to map
 * \param mode one of 'r' (for readonly) or 'w' (writeable),
 *   optionally followed by 'e' to extend map to end of file,
 *   optionally followed by 'p' to make write changes private
 * \param sz size in bytes of region to provide for mapping
 * \param off file offset of region to provide for mapping
 * \return an interface on success, `NULL` otherwise
 * \note On Windows, this function uses `CreateFileA` directly.
 * \note On Unix, this function uses the `open` system call directly.
 */
MMAPTWO_API
struct mmaptwo_i* mmaptwo_open
  (char const* nm, char const* mode, size_t sz, size_t off);

/**
 * \brief Open a file using a UTF-8 encoded name.
 * \param nm name of file to map
 * \brief mode one of 'r' (for readonly) or 'w' (writeable),
 *   optionally followed by 'e' to extend map to end of file,
 *   optionally followed by 'p' to make write changes private
 * \param sz size in bytes of region to provide for mapping
 * \param off file offset of region to provide for mapping
 * \return an interface on success, `NULL` otherwise
 * \note On Windows, this function re-encodes the `nm` parameter from
 *   UTF-8 to UTF-16, then uses `CreateFileW` on the result.
 * \note On Unix, this function uses the `open` system call directly.
 */
MMAPTWO_API
struct mmaptwo_i* mmaptwo_u8open
  (unsigned char const* nm, char const* mode, size_t sz, size_t off);

/**
 * \brief Open a file using a wide character name.
 * \param nm name of file to map
 * \brief mode one of 'r' (for readonly) or 'w' (writeable),
 *   optionally followed by 'e' to extend map to end of file,
 *   optionally followed by 'p' to make write changes private
 * \param sz size in bytes of region to provide for mapping
 * \param off file offset of region to provide for mapping
 * \return an interface on success, `NULL` otherwise
 * \note On Windows, this function uses `CreateFileW` directly.
 * \note On Unix, this function translates the wide string
 *   to a multibyte character string, then passes the result to
 *   the `open` system call. Use `setlocale` in advance if necessary.
 */
MMAPTWO_API
struct mmaptwo_i* mmaptwo_wopen
  (wchar_t const* nm, char const* mode, size_t sz, size_t off);
/* END   open functions */

#ifdef __cplusplus
};
#endif /*__cplusplus*/

#endif /*hg_MMapTwo_mmapTwo_H_*/

