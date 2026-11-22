#include "cfg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct cfg cfg;

    cfg_parse(data, size, &cfg);
    return 0;
}
