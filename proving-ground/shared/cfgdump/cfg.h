#ifndef CFG_H
#define CFG_H

#include <stddef.h>
#include <stdint.h>

enum { CFG_OK = 0, CFG_BAD_MAGIC, CFG_TRUNCATED, CFG_UNKNOWN_TAG };

struct cfg {
    char name[24];
    char note[64];
    uint16_t port;
};

/* Parses a CFG1 record file: "CFG1" then (tag, length, value) records. */
int cfg_parse(const uint8_t *buf, size_t size, struct cfg *out);
int cfg_set_note(struct cfg *out, const uint8_t *val, uint8_t len);
void cfg_report(int code);

#endif
