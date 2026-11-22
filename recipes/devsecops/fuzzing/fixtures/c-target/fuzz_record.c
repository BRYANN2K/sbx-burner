/* libFuzzer harness: clang -g -O1 -fsanitize=fuzzer,address fuzz_record.c record.c */
#include <stddef.h>
#include <stdint.h>

#include "record.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct lab_summary summary;
  lab_parse_records(data, size, &summary);
  return 0;
}
