#include <string.h>

#include "cfg.h"

int cfg_set_note(struct cfg *out, const uint8_t *val, uint8_t len)
{
    if (len >= sizeof out->note)
        return CFG_TRUNCATED;
    memcpy(out->note, val, len);
    out->note[len] = '\0';
    return CFG_OK;
}
