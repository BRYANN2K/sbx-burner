/* Tiny length-prefixed record parser. Lab fixture for devsecops/fuzzing.
 * It contains one intentional, harmless bug. Do not reuse this code. */
#ifndef LAB_RECORD_H
#define LAB_RECORD_H

#include <stddef.h>
#include <stdint.h>

#define LAB_NAME_MAX 16

struct lab_summary {
  unsigned records;
  unsigned name_len;
  uint32_t checksum;
};

/* Input: "LR", then records of [type:1][length:1][payload:length].
 * Type 1 is a name, type 2 is data, anything else is skipped.
 * Returns 0 on success, -1 on malformed input. */
int lab_parse_records(const uint8_t *data, size_t len, struct lab_summary *out);

#endif
