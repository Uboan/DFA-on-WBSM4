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

void test(int p,int share_index,int faultmask){
    unsigned char IN[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    u8 key[16] = {0};
    unsigned char OUT[16];
    unsigned char FOUT[16];
    unsigned char OOUT[16];
    unsigned char diff[16];


    shares *ptx[128];
    shares *k[32][32];
    shares *ctx[128];
    shares *fctx[128];
    
    genenkey(key, k);

    for(int j=0;j<p;j++){
        for(unsigned o=0;o<16;o++){
            IN[o] = j;
        }
            ///// encode plaintexts
            import(IN, ptx);
            // genenkey(key, k);
            ///// encryption
            bs_wbsm4(ptx, k, ctx);
            
            ///// decode ciphertexts
            export(ctx, OUT);
            

            bs_fault_wbsm4(ptx, k, fctx,faultmask,share_index);
            export(fctx, FOUT);
            
            for(int i=0;i<16;i++){
                diff[i]=OUT[i]^FOUT[i];
            }
            if(diff[15]!=0||diff[13]!=0||diff[14]!=0||diff[12]!=0){
                printstate(OUT);
                printstate(FOUT);
                printstate(diff);
            }
            
    }
}
int main()
{
    //First byte 
    printf("First byte :\n");
    test(5,1,0x1);
    printf("\n-----------------\n");
    test(5,2,0x1); 
    printf("\n-----------------\n");

    //Second byte 
    
    printf("Second byte :\n ");
    test(5,9,0x1);
    printf("\n-----------------\n");
    test(5,10,0x1);
    printf("\n-----------------\n");

    //third byte 
    printf("Third byte :\n ");
    test(5,17,0x1);
    printf("\n-----------------\n");
    test(5,18,0x1);
    printf("\n-----------------\n");

    //fourth byte 
    printf("Fourth byte :\n ");
    test(8,25,0x1);
    printf("\n-----------------\n");
    test(8,26,0x1);
    printf("\n-----------------\n");
    // int size = 16;
    // int turns = 500;
    // clock_t t = clock();
    // for(int i=0; i<turns; i++)
    // {
        
    // ///// encode plaintexts
    // import(IN, ptx);
    // // genenkey(key, k);
    // ///// encryption
    // bs_wbsm4(ptx, k, ctx);
    // ///// decode ciphertexts
    // export(ctx, OUT);
    // // printstate(OUT);
    // }
    // double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	// double speed = (double) size / (1024 * 1024 * tt);
    // printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);


    // sm4_context kk;
    // sm4_setkey_enc(&kk, key);
    // sm4_crypt_ecb(&kk, 1, 16, IN, OOUT);
    // printstate(OOUT);

    return 0;
}