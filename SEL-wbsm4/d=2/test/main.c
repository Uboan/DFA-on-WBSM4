#include "wbsm4.h"
#include <time.h>
#include <stdint.h>
uint64_t start_rdtsc()
{
    uint32_t cycles_high, cycles_low;
    __asm__ volatile(
        "CPUID\n\t"
        "RDTSC\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)cycles_low) | (((uint64_t)cycles_high) << 32);
}

uint64_t end_rdtsc()
{
    uint32_t cycles_high, cycles_low;
    __asm__ volatile(
        "RDTSCP\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t"
        : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)cycles_low) | (((uint64_t)cycles_high) << 32);
}
int main()
{
    unsigned char IN[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    u8 key[16] = {0};
    unsigned char OUT[16];
    unsigned char OOUT[16];
    shares *ptx[128];
    shares *k[32][32];
    shares *ctx[128];
    
    genenkey(key, k);
    int size = 16;
    int turns = 500;
    clock_t t = clock();
    for(int i=0; i<turns; i++)
    {
        
    ///// encode plaintexts
    import(IN, ptx);
    // genenkey(key, k);
    ///// encryption
    bs_wbsm4(ptx, k, ctx);
    ///// decode ciphertexts
    export(ctx, OUT);
    // printstate(OUT);
    }
    double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	double speed = (double) size / (1024 * 1024 * tt);
    printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);


    // sm4_context kk;
    // sm4_setkey_enc(&kk, key);
    // sm4_crypt_ecb(&kk, 1, 16, IN, OOUT);
    // printstate(OOUT);

    return 0;
}