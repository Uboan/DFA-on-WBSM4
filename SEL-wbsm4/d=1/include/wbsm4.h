#ifndef WBSM4_H
#define WBSM4_H

#include "sm4.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include "random.h"
#include <stdlib.h>

typedef unsigned char u8;
typedef unsigned int u32;

#define N 5

typedef struct shares
{
    u8 a[2], b[N + 1];
}shares;

static const u8 idM8[8] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
static const u32 idM32[32] = {0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x8000000, 0x4000000, 0x2000000, 0x1000000, 0x800000, 0x400000, 0x200000, 0x100000, 0x80000, 0x40000, 0x20000, 0x10000, 0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1};

u8 randbit();
shares *randshares();
shares *encode(u8 x);
u8 decode(shares *s);
shares *refresh(shares *x);
shares *evalxor(shares *x, shares *y);
shares *evaland(shares *x, shares *y);
shares *evalnot(shares *x);

void bs_wbsbox(shares *x[8]);
void bs_wbmc(shares *x[32]);
void bs_wbsr(shares *x[128]);

void bs_sbox(shares *x[8]);
void L(shares *x[32]);
void Sbox(shares *x[32]);
void T(shares *x[32]);
void AddRoundKey(shares *x[32], shares *k[32]);
void bs_wbsm4(shares *x[128], shares *k[32][32], shares *y[128]);
void import(u8 in[16], shares *x[128]);
void export(shares *y[128], u8 out[16]);
void genenkey(u8 key[16], shares *k[32][32]);
void printstate(unsigned char * in);

#endif // WBSM4_H