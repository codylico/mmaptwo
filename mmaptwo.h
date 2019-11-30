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
  mmaptwo_mode_read = 0x72,
  mmaptwo_mode_write = 0x77,
  mmaptwo_mode_end = 0x65,
  mmaptwo_mode_private = 0x70,

  /**
   * \note If not using bequeath, the caller of
   *   \link mmaptwo::open \endlink, \link mmaptwo::u8open \endlink or
   *   \link mmaptwo::wopen \endlink must give time for the function
   *   to return. Otherwise, the file descriptor of the mapped file
   *   may leak.
   */
  mmaptwo_mode_bequeath = 0x71
};

/**
 * \brief Memory-mapped input-output interface.
 */
struct mmaptwo_i {
  /**
   * \brief Destructor; closes the file and frees the space.
   * \param m map instance
   */
  void (*mmi_dtor)(struct mmaptwo_i* m);
  /**
   * \brief Acquire a lock to the space.
   * \param m map instance
   * \return pointer to locked space on success, NULL otherwise
   */
  void* (*mmi_acquire)(struct mmaptwo_i* m);
  /**
   * \brief Release a lock of the space.
   * \param m map instance
   * \param p pointer of region to release
   */
  void (*mmi_release)(struct mmaptwo_i* m, void* p);
  /**
   * \brief Check the length of the mapped area.
   * \param m map instance
   * \return the length of the mapped region exposed by this interface
   */
  size_t (*mmi_length)(struct mmaptwo_i const* m);
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
/* END   configurations */

/* BEGIN helper functions */
/**
 * \brief Helper function closes the file.
 * \param m map instance
 */
MMAPTWO_API
void mmaptwo_close(struct mmaptwo_i* m);

/**
 * \brief Helper function acquires file data.
 * \param m map instance
 * \return pointer to locked space on success, NULL otherwise
 */
MMAPTWO_API
void* mmaptwo_acquire(struct mmaptwo_i* m);

/**
 * \brief Helper function to release a lock of the space.
 * \param m map instance
 * \param p pointer of region to release
 */
MMAPTWO_API
void mmaptwo_release(struct mmaptwo_i* m, void* p);

/**
 * \brief Helper function to check the length of the space.
 * \param m map instance
 * \return the length of the space
 */
MMAPTWO_API
size_t mmaptwo_length(struct mmaptwo_i const* m);
/* END   helper functions */

/* BEGIN open functions */
/**
 * \brief Open a file using a narrow character name.
 * \param nm name of file to map
 * \param mode one of 'r' (for readonly) or 'w' (writeable),
 *   optionally followed by 'e' to extend map to end of file,
 *   optionally followed by 'p' to make write changes private
 * \param sz size in bytes of region to map
 * \param off file offset of region to map
 * \return an interface on success, NULL otherwise
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
 * \param sz size in bytes of region to map
 * \param off file offset of region to map
 * \return an interface on success, NULL otherwise
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
 * \param sz size in bytes of region to map
 * \param off file offset of region to map
 * \return an interface on success, NULL otherwise
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

