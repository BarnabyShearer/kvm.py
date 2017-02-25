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
        : "g" (main())
    );
}

int main(void) {
    return 0;
}
