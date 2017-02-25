.PHONY: run clean

CFLAGS=-std=gnu11 -pedantic -Wall -Werror \
	-ffreestanding \
    -nostdlib \
	-Wl,-Tmain.ld

%.s : %.c
	$(CC) -S $(CFLAGS) $(CPPFLAGS) $< -o $@

run: main
	./main.py $+

clean:
	-rm main *.s
