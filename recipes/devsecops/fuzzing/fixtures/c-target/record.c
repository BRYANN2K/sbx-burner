#include "record.h"

#include <string.h>

int lab_parse_records(const uint8_t *data, size_t len, struct lab_summary *out) {
  char name[LAB_NAME_MAX];
  size_t pos = 2;

  memset(out, 0, sizeof(*out));
  if (len < 2 || data[0] != 'L' || data[1] != 'R') {
    return -1;
  }
  while (pos + 2 <= len) {
    uint8_t type = data[pos];
    size_t rlen = data[pos + 1];
    pos += 2;
    if (rlen > len - pos) {
      return -1; /* truncated record */
    }
    if (type == 1) {
      /* Intentional bug: the check should be `rlen >= sizeof(name)`.
       * A 16-byte name passes, and the terminator lands one byte past
       * the buffer. */
      if (rlen > sizeof(name)) {
        return -1;
      }
      memcpy(name, data + pos, rlen);
      name[rlen] = '\0';
      out->name_len = (unsigned)strlen(name);
    } else if (type == 2) {
      for (size_t i = 0; i < rlen; i++) {
        out->checksum = out->checksum * 31u + data[pos + i];
      }
    }
    pos += rlen;
    out->records++;
  }
  return pos == len ? 0 : -1;
}
