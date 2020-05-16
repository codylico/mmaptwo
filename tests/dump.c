
#include "../mmaptwo.h"
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>

int main(int argc, char **argv) {
  struct mmaptwo_i* mi;
  struct mmaptwo_page_i* pager;
  char const* fname;
  if (argc < 5) {
    fputs("usage: dump (file) (mode) (length) (offset) [...]\n"
        "optional arguments [...]:\n"
        "  [sublen] [suboff]\n"
        "        Length and offset for page. Defaults\n"
        "        to full extent of mappable.", stderr);
    return EXIT_FAILURE;
  }
  fname = argv[1];
  mmaptwo_set_errno(0);
  mi = mmaptwo_open(fname, argv[2],
    (size_t)strtoul(argv[3],NULL,0),
    (size_t)strtoul(argv[4],NULL,0));
  if (mi == NULL) {
    fprintf(stderr, "failed to open file '%s':\n\t%s\n", fname,
      strerror(mmaptwo_get_errno()));
    return EXIT_FAILURE;
  } else {
    size_t sub_len = (argc>5)
      ? (size_t)strtoul(argv[5],NULL,0)
      : mmaptwo_length(mi);
    size_t sub_off = (argc>6)
      ? (size_t)strtoul(argv[6],NULL,0)
      : 0;
    mmaptwo_set_errno(0);
    pager = mmaptwo_acquire(mi, sub_len, sub_off);
  }
  if (pager == NULL) {
    fprintf(stderr, "failed to map file '%s':\n\t%s\n", fname,
      strerror(mmaptwo_get_errno()));
    mmaptwo_close(mi);
    return EXIT_FAILURE;
  } else {
    /* output the data */{
      size_t len = mmaptwo_page_length(pager);
      size_t const off = mmaptwo_page_offset(pager);
      unsigned char* bytes = (unsigned char*)mmaptwo_page_get(pager);
      if (bytes != NULL) {
        size_t i;
        if (len >= UINT_MAX-32)
          len = UINT_MAX-32;
        for (i = 0; i < len; i+=16) {
          size_t j = 0;
          fprintf(stdout, "%s%4lx:", i?"\n":"",
             (long unsigned int)(i+off));
          for (j = 0; j < 16; ++j) {
            if (j%4 == 0) {
              fputs(" ", stdout);
            }
            if (j < len-i)
              fprintf(stdout, "%02x", (unsigned int)(bytes[i+j]));
            else fputs("  ", stdout);
          }
          fputs(" | ", stdout);
          for (j = 0; j < 16; ++j) {
            if (j < len-i) {
              int ch = bytes[i+j];
              fprintf(stdout, "%c", isprint(ch) ? ch : '.');
            } else fputs(" ", stdout);
          }
        }
        fputs("\n", stdout);
      } else {
        fprintf(stderr, "mapped file '%s' gives no bytes?\n", fname);
      }
    }
    mmaptwo_page_close(pager);
  }
  mmaptwo_close(mi);
  return EXIT_SUCCESS;
}

