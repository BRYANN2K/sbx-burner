/* File-input driver for AFL++: ./record_afl <input-file> */
#include <stdio.h>
#include <stdlib.h>

#include "record.h"

int main(int argc, char **argv) {
  static uint8_t buf[4096];
  struct lab_summary summary;
  FILE *fh;
  size_t n;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
    return 2;
  }
  fh = fopen(argv[1], "rb");
  if (fh == NULL) {
    perror("fopen");
    return 2;
  }
  n = fread(buf, 1, sizeof(buf), fh);
  fclose(fh);
  if (lab_parse_records(buf, n, &summary) != 0) {
    return 1;
  }
  printf("records=%u name_len=%u checksum=%u\n", summary.records, summary.name_len, summary.checksum);
  return 0;
}
