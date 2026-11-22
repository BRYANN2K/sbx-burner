CC ?= cc
CFLAGS ?= -O0 -fstack-protector-strong
SRC = cfg.c note.c

cfgdump: main.c $(SRC) cfg.h
	$(CC) $(CFLAGS) -o $@ main.c $(SRC)

fuzz_cfg: fuzz_cfg.c $(SRC) cfg.h
	clang -g -O1 -fsanitize=fuzzer,address,undefined -o $@ fuzz_cfg.c $(SRC)

clean:
	rm -f cfgdump fuzz_cfg

.PHONY: clean
