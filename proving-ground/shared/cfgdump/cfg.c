#include <stdio.h>
#include <string.h>

#include "cfg.h"

static const char *const kMessages[] = {
    "ok\n",
    "bad magic\n",
    "truncated record\n",
    "unknown tag\n",
};

void cfg_report(int code)
{
    if (code < 0 || code >= (int)(sizeof kMessages / sizeof kMessages[0]))
        code = CFG_UNKNOWN_TAG;
    fprintf(stderr, kMessages[code]);
}

static int apply_record(uint8_t tag, const uint8_t *val, uint8_t len, struct cfg *out)
{
    char text[32];

    switch (tag) {
    case 'N':
        memcpy(text, val, len);
        snprintf(out->name, sizeof out->name, "%.*s", (int)len, text);
        return CFG_OK;
    case 'C':
        return cfg_set_note(out, val, len);
    case 'P':
        if (len != 2)
            return CFG_TRUNCATED;
        out->port = (uint16_t)((val[0] << 8) | val[1]);
        return CFG_OK;
    default:
        return CFG_UNKNOWN_TAG;
    }
}

int cfg_parse(const uint8_t *buf, size_t size, struct cfg *out)
{
    size_t off = 4;

    memset(out, 0, sizeof *out);
    if (size < 4 || memcmp(buf, "CFG1", 4) != 0)
        return CFG_BAD_MAGIC;
    while (off + 2 <= size) {
        uint8_t tag = buf[off];
        uint8_t len = buf[off + 1];
        int rc;

        off += 2;
        if (len > size - off)
            return CFG_TRUNCATED;
        rc = apply_record(tag, buf + off, len, out);
        if (rc != CFG_OK)
            return rc;
        off += len;
    }
    return off == size ? CFG_OK : CFG_TRUNCATED;
}
