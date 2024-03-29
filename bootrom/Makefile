
# We override some of the variables that we get from the Buildroot
# infrastructure here. Specifically, we don't want to use the provided
# CFLAGS since these assume that the build target isn't firmware-like
# (i.e. we want nostdlib, nostartfiles, etc).

override CFLAGS := \
	-mcmodel=medany -mabi=lp64d \
	-nostdlib -nostartfiles -fno-common -std=gnu11 \
	-static \
	-fPIC \
	-O1 -Wall
O ?=.

# ^ consider taking out -g -Og and putting in -O2

bootloaders=\
	$(O)/bootrom.elf \
	$(O)/bootrom.bin

.PHONY: all
all: $(bootloaders)

.PHONY: clean
clean:
	rm -f $(bootloaders)

bootrom_sources = \
	./bootloader.S \
	./bootloader.c \
	./sha3/*.c \
	./x509custom/*.c \
	./falcon512/*.c #\
	./dilithium/*.c \
	./ed25519/*.c 


%.elf: $(bootrom_sources) bootloader.lds
	$(CC) $(CFLAGS) -I./ -L . -T bootloader.lds -o $@ $(bootrom_sources)

%.bin: %.elf
	$(OBJCOPY) -O binary --only-section=.text $< $@;

