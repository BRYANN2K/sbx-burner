#include <stdio.h>

#include "cfg.h"

int main(int argc, char **argv)
{
    static uint8_t buf[4096];
    struct cfg cfg;
    size_t n;
    FILE *f;
    int rc;

    if (argc != 2) {
        fprintf(stderr, "usage: cfgdump <file.cfg>\n");
        return 2;
    }
    f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 2;
    }
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);

    rc = cfg_parse(buf, n, &cfg);
    cfg_report(rc);
    if (rc == CFG_OK)
        printf("name=%s port=%u note=%s\n", cfg.name, (unsigned)cfg.port, cfg.note);
    return rc == CFG_OK ? 0 : 1;
}
