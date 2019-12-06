
#include "../mmaptwo.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  printf("check bequeath stop: %s\n",
    mmaptwo_check_bequeath_stop()?"true":"false");
  printf("page size: %lu\n",
    (long unsigned int)mmaptwo_get_page_size());
  return EXIT_SUCCESS;
}

