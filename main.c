void exit(int);
int main(void);
void start(void) {
    exit(main());
}
void exit(int ret) {
    __asm__ __volatile__ (
        "mov    %0, %%edi   \n\t"
        "hlt\n\t"
        :
        : "g" (ret)
    );
}

static inline void puts(const char *);

int main(void) {
    puts("Hello World\n");
    return 0;
}

static inline void puts(const char *addr) {
    int c = 0;
    for(; addr[c]!=0; ++c);
    __asm__ volatile ("rep outsb\n" : "+c" (c) : "S" (addr), "d" (0x3f8));
}
