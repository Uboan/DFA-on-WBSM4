#include "wbsm4.h"
void printstate(unsigned char * in)
{
    int i;
    for(i = 0; i < 16; i++) 
    {
        printf("%.2X", in[i]);
    }
    printf("\n");
}
u8 randbit()
{
    return cus_random() & 0x1;
}
shares *randshares()
{
    shares *s = (shares *)malloc(sizeof(shares));
    s->a = cus_random() & 0x1;
    s->b = cus_random() & 0x1;
    s->c = cus_random() & 0x1;
    return s;
}
//////////

////////// masking scheme
shares *encode(u8 x, u8 ra, u8 rb)
{
    shares *s = (shares *)malloc(sizeof(shares));;
    s->a = ra;
    s->b = rb;
    s->c = (ra & rb) ^ x;
    return s;
}

u8 decode(shares *s)
{
    return (s->a & s->b) ^ s->c;
}

shares *refresh(shares *m, shares *r)
{
    shares *s = (shares *)malloc(sizeof(shares));
    u8 ma = r->a & (m->b ^ r->c);
    u8 mb = r->b & (m->a ^ r->c);
    r->c = ma ^ mb ^ ((r->a ^ r->c) & (r->b ^ r->c)) ^ r->c;
    s->a = m->a ^ r->a;
    s->b = m->b ^ r->b;
    s->c = m->c ^ r->c;
    return s;
}

shares *evalxor(shares *m, shares *n, shares *rm, shares *rn)
{
    shares *s = (shares *)malloc(sizeof(shares));
    m = refresh(m, rm);
    n = refresh(n, rn);
    s->a = m->a ^ n->a;
    s->b = m->b ^ n->b;
    s->c = m->c ^ n->c ^ (m->a & n->b) ^ (m->b & n->a);
    return s;
}

shares *evaland(shares *m, shares *n, shares *rm, shares *rn)
{
    shares *s = (shares *)malloc(sizeof(shares));
    m = refresh(m, rm);
    n = refresh(n, rn);
    u8 ma = (m->b & n->c) ^ (rm->c & n->b);
    u8 md = (m->c & n->b) ^ (rn->c & m->b);
    s->a = (m->a & n->b) ^ rn->c;
    s->b = (m->b & n->a) ^ rm->c;
    s->c = (m->a & ma) ^ (n->a & md) ^ (rm->c & rn->c) ^ (m->c & n->c);
    return s;
}

shares *evalnot(shares *m)
{
    shares *s = (shares *)malloc(sizeof(shares));
    s->a = m->a;
    s->b = m->b;
    s->c = (~ (m->c)) & 0x1;
    return s;
}
void bs_sbox(shares *x[8])
{
    shares *s[8];
    shares *y_t[21], *t_t[8], *t_m[46], *y_m[18], *t_b[30];
    y_t[18] = evalxor(x[5], x[1], randshares(), randshares());
    t_t[ 0] = evalxor(x[4], x[3], randshares(), randshares());
    t_t[ 1] = evalxor(x[5], x[0], randshares(), randshares());
    t_t[ 2] = evalxor(x[0], y_t[18], randshares(), randshares());
    t_t[ 3] = evalxor(x[6], t_t[ 1], randshares(), randshares());
    t_t[ 4] = evalxor(x[1], x[0], randshares(), randshares());
    t_t[ 5] = evalxor(x[7], y_t[18], randshares(), randshares());
    t_t[ 6] = evalxor(x[4], x[1], randshares(), randshares());
    y_t[10] = evalxor(x[6], y_t[18], randshares(), randshares());
    y_t[ 0] = evalxor(x[2],  evalnot(y_t[10]), randshares(), randshares());
    y_t[ 1] = evalxor(t_t[ 0], t_t[ 3], randshares(), randshares());
    y_t[ 2] = evalxor(x[7], t_t[ 0], randshares(), randshares());
    y_t[ 4] = evalxor(x[7], t_t[ 3], randshares(), randshares());
    y_t[ 3] = evalxor(x[4], y_t[ 4], randshares(), randshares());
    y_t[ 5] = evalxor(x[2], t_t[ 5], randshares(), randshares());
    y_t[ 6] = evalxor(x[7],  evalnot(x[6]), randshares(), randshares());
    y_t[ 7] = evalxor(t_t[ 0],  evalnot(y_t[10]), randshares(), randshares());
    y_t[ 8] = evalxor(t_t[ 0], t_t[ 5], randshares(), randshares());
    y_t[ 9] = x[4];
    y_t[11] = evalxor(t_t[ 0], t_t[ 4], randshares(), randshares());
    y_t[12] = evalxor(x[2], t_t[ 4], randshares(), randshares());
    y_t[13] = evalxor(x[2],  evalnot(y_t[ 1]), randshares(), randshares());
    y_t[14] = evalxor(x[3],  evalnot(t_t[ 2]), randshares(), randshares());
    y_t[15] = evalxor(x[6],  evalnot(t_t[ 6]), randshares(), randshares());
    y_t[16] = evalxor(x[7],  evalnot(t_t[ 2]), randshares(), randshares());
    y_t[17] = evalxor(t_t[ 0],  evalnot(t_t[ 2]), randshares(), randshares());
    y_t[19] = evalxor(x[2],  evalnot(y_t[14]), randshares(), randshares());
    y_t[20] = evalxor(x[7], t_t[ 1], randshares(), randshares());

  	    // y_t[18] = x[2] ^ x[6];
		// t_t[ 0] = x[3] ^ x[4];
		// t_t[ 1] = x[2] ^ x[7];
		// t_t[ 2] = x[7] ^ y_t[18];
		// t_t[ 3] = x[1] ^ t_t[ 1];
		// t_t[ 4] = x[6] ^ x[7];
		// t_t[ 5] = x[0] ^ y_t[18];
		// t_t[ 6] = x[3] ^ x[6];
		// y_t[10] = x[1] ^ y_t[18];
		// y_t[ 0] = x[5] ^  0x01 ^ y_t[10];
		// y_t[ 1] = t_t[ 0] ^t_t[ 3];
		// y_t[ 2] = x[0] ^ t_t[ 0];
		// y_t[ 4] = x[0] ^ t_t[ 3];
		// y_t[ 3] = x[3] ^ y_t[ 4];
		// y_t[ 5] = x[5] ^ t_t[ 5];
		// y_t[ 6] = x[0] ^  0x01 ^ x[1];
		// y_t[ 7] = t_t[ 0] ^  0x01 ^ y_t[10];
		// y_t[ 8] = t_t[ 0] ^ t_t[ 5];
		// y_t[ 9] = x[3];
		// y_t[11] = t_t[ 0] ^ t_t[ 4];
		// y_t[12] = x[5] ^ t_t[ 4];
		// y_t[13] = x[5] ^  0x01 ^ y_t[ 1];
		// y_t[14] = x[4] ^  0x01 ^ t_t[ 2];
		// y_t[15] = x[1] ^  0x01 ^ t_t[ 6];
		// y_t[16] = x[0] ^  0x01 ^ t_t[ 2];
		// y_t[17] = t_t[ 0] ^  0x01 ^ t_t[ 2];
		// y_t[19] = x[5] ^  0x01 ^ y_t[14];
		// y_t[20] = x[0] ^ t_t[ 1];

    //The shared non-linear middle part for AES, AES^-1, and SM4
  	t_m[ 0] = evalxor(y_t[ 3], y_t[12], randshares(), randshares());
    t_m[ 1] = evaland(y_t[ 9], y_t[ 5], randshares(), randshares());
    t_m[ 2] = evaland(y_t[17], y_t[ 6], randshares(), randshares());
    t_m[ 3] = evalxor(y_t[10], t_m[ 1], randshares(), randshares());
    t_m[ 4] = evaland(y_t[14], y_t[ 0], randshares(), randshares());
    t_m[ 5] = evalxor(t_m[ 4], t_m[ 1], randshares(), randshares());
    t_m[ 6] = evaland(y_t[ 3], y_t[12], randshares(), randshares());
    t_m[ 7] = evaland(y_t[16], y_t[ 7], randshares(), randshares());
    t_m[ 8] = evalxor(t_m[ 0], t_m[ 6], randshares(), randshares());
    t_m[ 9] = evaland(y_t[15], y_t[13], randshares(), randshares());
    t_m[10] = evalxor(t_m[ 9], t_m[ 6], randshares(), randshares());
    t_m[11] = evaland(y_t[ 1], y_t[11], randshares(), randshares());
    t_m[12] = evaland(y_t[ 4], y_t[20], randshares(), randshares());
    t_m[13] = evalxor(t_m[12], t_m[11], randshares(), randshares());
    t_m[14] = evaland(y_t[ 2], y_t[ 8], randshares(), randshares());
    t_m[15] = evalxor(t_m[14], t_m[11], randshares(), randshares());
    t_m[16] = evalxor(t_m[ 3], t_m[ 2], randshares(), randshares());
    t_m[17] = evalxor(t_m[ 5], y_t[18], randshares(), randshares());
    t_m[18] = evalxor(t_m[ 8], t_m[ 7], randshares(), randshares());
    t_m[19] = evalxor(t_m[10], t_m[15], randshares(), randshares());
    t_m[20] = evalxor(t_m[16], t_m[13], randshares(), randshares());
    t_m[21] = evalxor(t_m[17], t_m[15], randshares(), randshares());
    t_m[22] = evalxor(t_m[18], t_m[13], randshares(), randshares());
    t_m[23] = evalxor(t_m[19], y_t[19], randshares(), randshares());
    t_m[24] = evalxor(t_m[22], t_m[23], randshares(), randshares());
    t_m[25] = evaland(t_m[22], t_m[20], randshares(), randshares());
    t_m[26] = evalxor(t_m[21], t_m[25], randshares(), randshares());
    t_m[27] = evalxor(t_m[20], t_m[21], randshares(), randshares());
    t_m[28] = evalxor(t_m[23], t_m[25], randshares(), randshares());
    t_m[29] = evaland(t_m[28], t_m[27], randshares(), randshares());
    t_m[30] = evaland(t_m[26], t_m[24], randshares(), randshares());
    t_m[31] = evaland(t_m[20], t_m[23], randshares(), randshares());
    t_m[32] = evaland(t_m[27], t_m[31], randshares(), randshares());
    t_m[33] = evalxor(t_m[27], t_m[25], randshares(), randshares());
    t_m[34] = evaland(t_m[21], t_m[22], randshares(), randshares());
    t_m[35] = evaland(t_m[24], t_m[34], randshares(), randshares());
    t_m[36] = evalxor(t_m[24], t_m[25], randshares(), randshares());
    t_m[37] = evalxor(t_m[21], t_m[29], randshares(), randshares());
    t_m[38] = evalxor(t_m[32], t_m[33], randshares(), randshares());
    t_m[39] = evalxor(t_m[23], t_m[30], randshares(), randshares());
    t_m[40] = evalxor(t_m[35], t_m[36], randshares(), randshares());
    t_m[41] = evalxor(t_m[38], t_m[40], randshares(), randshares());
    t_m[42] = evalxor(t_m[37], t_m[39], randshares(), randshares());
    t_m[43] = evalxor(t_m[37], t_m[38], randshares(), randshares());
    t_m[44] = evalxor(t_m[39], t_m[40], randshares(), randshares());
    t_m[45] = evalxor(t_m[42], t_m[41], randshares(), randshares());
    y_m[ 0] = evaland(t_m[38], y_t[ 7], randshares(), randshares());
    y_m[ 1] = evaland(t_m[37], y_t[13], randshares(), randshares());
    y_m[ 2] = evaland(t_m[42], y_t[11], randshares(), randshares());
    y_m[ 3] = evaland(t_m[45], y_t[20], randshares(), randshares());
    y_m[ 4] = evaland(t_m[41], y_t[ 8], randshares(), randshares());
    y_m[ 5] = evaland(t_m[44], y_t[ 9], randshares(), randshares());
    y_m[ 6] = evaland(t_m[40], y_t[17], randshares(), randshares());
    y_m[ 7] = evaland(t_m[39], y_t[14], randshares(), randshares());
    y_m[ 8] = evaland(t_m[43], y_t[ 3], randshares(), randshares());
    y_m[ 9] = evaland(t_m[38], y_t[16], randshares(), randshares());
    y_m[10] = evaland(t_m[37], y_t[15], randshares(), randshares());
    y_m[11] = evaland(t_m[42], y_t[ 1], randshares(), randshares());
    y_m[12] = evaland(t_m[45], y_t[ 4], randshares(), randshares());
    y_m[13] = evaland(t_m[41], y_t[ 2], randshares(), randshares());
    y_m[14] = evaland(t_m[44], y_t[ 5], randshares(), randshares());
    y_m[15] = evaland(t_m[40], y_t[ 6], randshares(), randshares());
    y_m[16] = evaland(t_m[39], y_t[ 0], randshares(), randshares());
    y_m[17] = evaland(t_m[43], y_t[12], randshares(), randshares());

  //bottom(outer) linear layer for sm4
  	t_b[ 0] = evalxor(y_m[ 4], y_m[ 7], randshares(), randshares());
    t_b[ 1] = evalxor(y_m[13], y_m[15], randshares(), randshares());
    t_b[ 2] = evalxor(y_m[ 2], y_m[16], randshares(), randshares());
    t_b[ 3] = evalxor(y_m[ 6], t_b[ 0], randshares(), randshares());
    t_b[ 4] = evalxor(y_m[12], t_b[ 1], randshares(), randshares());
    t_b[ 5] = evalxor(y_m[ 9], y_m[10], randshares(), randshares());
    t_b[ 6] = evalxor(y_m[11], t_b[ 2], randshares(), randshares());
    t_b[ 7] = evalxor(y_m[ 1], t_b[ 4], randshares(), randshares());
    t_b[ 8] = evalxor(y_m[ 0], y_m[17], randshares(), randshares());
    t_b[ 9] = evalxor(y_m[ 3], y_m[17], randshares(), randshares());
    t_b[10] = evalxor(y_m[ 8], t_b[ 3], randshares(), randshares());
    t_b[11] = evalxor(t_b[ 2], t_b[ 5], randshares(), randshares());
    t_b[12] = evalxor(y_m[14], t_b[ 6], randshares(), randshares());
    t_b[13] = evalxor(t_b[ 7], t_b[ 9], randshares(), randshares());
    t_b[14] = evalxor(y_m[ 0], y_m[ 6], randshares(), randshares());
    t_b[15] = evalxor(y_m[ 7], y_m[16], randshares(), randshares());
    t_b[16] = evalxor(y_m[ 5], y_m[13], randshares(), randshares());
    t_b[17] = evalxor(y_m[ 3], y_m[15], randshares(), randshares());
    t_b[18] = evalxor(y_m[10], y_m[12], randshares(), randshares());
    t_b[19] = evalxor(y_m[ 9], t_b[ 1], randshares(), randshares());
    t_b[20] = evalxor(y_m[ 4], t_b[ 4], randshares(), randshares());
    t_b[21] = evalxor(y_m[14], t_b[ 3], randshares(), randshares());
    t_b[22] = evalxor(y_m[16], t_b[ 5], randshares(), randshares());
    t_b[23] = evalxor(t_b[ 7], t_b[14], randshares(), randshares());
    t_b[24] = evalxor(t_b[ 8], t_b[11], randshares(), randshares());
    t_b[25] = evalxor(t_b[ 0], t_b[12], randshares(), randshares());
    t_b[26] = evalxor(t_b[17], t_b[ 3], randshares(), randshares());
    t_b[27] = evalxor(t_b[18], t_b[10], randshares(), randshares());
    t_b[28] = evalxor(t_b[19], t_b[ 6], randshares(), randshares());
    t_b[29] = evalxor(t_b[ 8], t_b[10], randshares(), randshares());
		// s[0] = t_b[11] ^ 0x01 ^  t_b[13];
		// s[1] = t_b[15] ^ 0x01 ^  t_b[23];
		// s[2] = t_b[20] ^ t_b[24];
		// s[3] = t_b[16] ^ t_b[25];
		// s[4] = t_b[26] ^ 0x01 ^  t_b[22];
		// s[5] = t_b[21] ^ t_b[13];
		// s[6] = t_b[27] ^ 0x01 ^  t_b[12];
		// s[7] = t_b[28] ^ 0x01 ^  t_b[29];

    s[7] = evalxor(t_b[11], evalnot(t_b[13]), randshares(), randshares());
    s[6] = evalxor(t_b[15], evalnot(t_b[23]), randshares(), randshares());
    s[5] = evalxor(t_b[20], t_b[24], randshares(), randshares());
    s[4] = evalxor(t_b[16], t_b[25], randshares(), randshares());
    s[3] = evalxor(t_b[26], evalnot(t_b[22]), randshares(), randshares());
    s[2] = evalxor(t_b[21], t_b[13], randshares(), randshares());
    s[1] = evalxor(t_b[27], evalnot(t_b[12]), randshares(), randshares());
    s[0] = evalxor(t_b[28], evalnot(t_b[29]), randshares(), randshares());

    memmove(x,s,sizeof(s));
}

void L(shares *x[32])
{
  shares *s[32];
  shares *t0, *t1, *t2;
  t0 = evalxor(x[0], x[2], randshares(), randshares());
  t1 = evalxor(t0, x[10], randshares(), randshares());
  t2 = evalxor(t1, x[18], randshares(), randshares());
  s[0] = evalxor(t2, x[24], randshares(), randshares());

  t0 = evalxor(x[1], x[3], randshares(), randshares());
  t1 = evalxor(t0, x[11], randshares(), randshares());
  t2 = evalxor(t1, x[19], randshares(), randshares());
  s[1] = evalxor(t2, x[25], randshares(), randshares());

  t0 = evalxor(x[2], x[4], randshares(), randshares());
  t1 = evalxor(t0, x[12], randshares(), randshares());
  t2 = evalxor(t1, x[20], randshares(), randshares());
  s[2] = evalxor(t2, x[26], randshares(), randshares());

  t0 = evalxor(x[3], x[5], randshares(), randshares());
  t1 = evalxor(t0, x[13], randshares(), randshares());
  t2 = evalxor(t1, x[21], randshares(), randshares());
  s[3] = evalxor(t2, x[27], randshares(), randshares());

  t0 = evalxor(x[4], x[6], randshares(), randshares());
  t1 = evalxor(t0, x[14], randshares(), randshares());
  t2 = evalxor(t1, x[22], randshares(), randshares());
  s[4] = evalxor(t2, x[28], randshares(), randshares());

  t0 = evalxor(x[5], x[7], randshares(), randshares());
  t1 = evalxor(t0, x[15], randshares(), randshares());
  t2 = evalxor(t1, x[23], randshares(), randshares());
  s[5] = evalxor(t2, x[29], randshares(), randshares());

  t0 = evalxor(x[6], x[8], randshares(), randshares());
  t1 = evalxor(t0, x[16], randshares(), randshares());
  t2 = evalxor(t1, x[24], randshares(), randshares());
  s[6] = evalxor(t2, x[30], randshares(), randshares());

  t0 = evalxor(x[7], x[9], randshares(), randshares());
  t1 = evalxor(t0, x[17], randshares(), randshares());
  t2 = evalxor(t1, x[25], randshares(), randshares());
  s[7] = evalxor(t2, x[31], randshares(), randshares());

  t0 = evalxor(x[0], x[8], randshares(), randshares());
  t1 = evalxor(t0, x[10], randshares(), randshares());
  t2 = evalxor(t1, x[18], randshares(), randshares());
  s[8] = evalxor(t2, x[26], randshares(), randshares());

  t0 = evalxor(x[1], x[9], randshares(), randshares());
  t1 = evalxor(t0, x[11], randshares(), randshares());
  t2 = evalxor(t1, x[19], randshares(), randshares());
  s[9] = evalxor(t2, x[27], randshares(), randshares());

  t0 = evalxor(x[2], x[10], randshares(), randshares());
  t1 = evalxor(t0, x[12], randshares(), randshares());
  t2 = evalxor(t1, x[20], randshares(), randshares());
  s[10] = evalxor(t2, x[28], randshares(), randshares());

  t0 = evalxor(x[3], x[11], randshares(), randshares());
  t1 = evalxor(t0, x[13], randshares(), randshares());
  t2 = evalxor(t1, x[21], randshares(), randshares());
  s[11] = evalxor(t2, x[29], randshares(), randshares());

  t0 = evalxor(x[4], x[12], randshares(), randshares());
  t1 = evalxor(t0, x[14], randshares(), randshares());
  t2 = evalxor(t1, x[22], randshares(), randshares());
  s[12] = evalxor(t2, x[30], randshares(), randshares());

  t0 = evalxor(x[5], x[13], randshares(), randshares());
  t1 = evalxor(t0, x[15], randshares(), randshares());
  t2 = evalxor(t1, x[23], randshares(), randshares());
  s[13] = evalxor(t2, x[31], randshares(), randshares());

  t0 = evalxor(x[0], x[6], randshares(), randshares());
  t1 = evalxor(t0, x[14], randshares(), randshares());
  t2 = evalxor(t1, x[16], randshares(), randshares());
  s[14]  = evalxor(t2, x[24], randshares(), randshares());

  t0 = evalxor(x[1], x[7], randshares(), randshares());
  t1 = evalxor(t0, x[15], randshares(), randshares());
  t2 = evalxor(t1, x[17], randshares(), randshares());
  s[15] = evalxor(t2, x[25], randshares(), randshares());

  t0 = evalxor(x[2], x[8], randshares(), randshares());
  t1 = evalxor(t0, x[16], randshares(), randshares());
  t2 = evalxor(t1, x[18], randshares(), randshares());
  s[16] = evalxor(t2, x[26], randshares(), randshares());

  t0 = evalxor(x[3], x[9], randshares(), randshares());
  t1 = evalxor(t0, x[17], randshares(), randshares());
  t2 = evalxor(t1, x[19], randshares(), randshares());
  s[17] = evalxor(t2, x[27], randshares(), randshares());

  t0 = evalxor(x[4], x[10], randshares(), randshares());
  t1 = evalxor(t0, x[18], randshares(), randshares());
  t2 = evalxor(t1, x[20], randshares(), randshares());
  s[18] = evalxor(t2, x[28], randshares(), randshares());

  t0 = evalxor(x[5], x[11], randshares(), randshares());
  t1 = evalxor(t0, x[19], randshares(), randshares());
  t2 = evalxor(t1, x[21], randshares(), randshares());
  s[19] = evalxor(t2, x[29], randshares(), randshares());

  t0 = evalxor(x[6], x[12], randshares(), randshares());
  t1 = evalxor(t0, x[20], randshares(), randshares());
  t2 = evalxor(t1, x[22], randshares(), randshares());
  s[20] = evalxor(t2, x[30], randshares(), randshares());

  t0 = evalxor(x[7], x[13], randshares(), randshares());
  t1 = evalxor(t0, x[21], randshares(), randshares());
  t2 = evalxor(t1, x[23], randshares(), randshares());
  s[21] = evalxor(t2, x[31], randshares(), randshares());

  t0 = evalxor(x[0], x[8], randshares(), randshares());
  t1 = evalxor(t0, x[14], randshares(), randshares());
  t2 = evalxor(t1, x[22], randshares(), randshares());
  s[22] = evalxor(t2, x[24], randshares(), randshares());

  t0 = evalxor(x[1], x[9], randshares(), randshares());
  t1 = evalxor(t0, x[15], randshares(), randshares());
  t2 = evalxor(t1, x[23], randshares(), randshares());
  s[23] = evalxor(t2, x[25], randshares(), randshares());

  t0 = evalxor(x[2], x[10], randshares(), randshares());
  t1 = evalxor(t0, x[16], randshares(), randshares());
  t2 = evalxor(t1, x[24], randshares(), randshares());
  s[24] = evalxor(t2, x[26], randshares(), randshares());

  t0 = evalxor(x[3], x[11], randshares(), randshares());
  t1 = evalxor(t0, x[17], randshares(), randshares());
  t2 = evalxor(t1, x[25], randshares(), randshares());
  s[25] = evalxor(t2, x[27], randshares(), randshares());

  t0 = evalxor(x[4], x[12], randshares(), randshares());
  t1 = evalxor(t0, x[18], randshares(), randshares());
  t2 = evalxor(t1, x[26], randshares(), randshares());
  s[26] = evalxor(t2, x[28], randshares(), randshares());

  t0 = evalxor(x[5], x[13], randshares(), randshares());
  t1 = evalxor(t0, x[19], randshares(), randshares());
  t2 = evalxor(t1, x[27], randshares(), randshares());
  s[27] = evalxor(t2, x[29], randshares(), randshares());

  t0 = evalxor(x[6], x[14], randshares(), randshares());
  t1 = evalxor(t0, x[20], randshares(), randshares());
  t2 = evalxor(t1, x[28], randshares(), randshares());
  s[28] = evalxor(t2, x[30], randshares(), randshares());

  t0 = evalxor(x[7], x[15], randshares(), randshares());
  t1 = evalxor(t0, x[21], randshares(), randshares());
  t2 = evalxor(t1, x[29], randshares(), randshares());
  s[29] = evalxor(t2, x[31], randshares(), randshares());

  t0 = evalxor(x[0], x[8], randshares(), randshares());
  t1 = evalxor(t0, x[16], randshares(), randshares());
  t2 = evalxor(t1, x[22], randshares(), randshares());
  s[30] = evalxor(t2, x[30], randshares(), randshares());

  t0 = evalxor(x[1], x[9], randshares(), randshares());
  t1 = evalxor(t0, x[17], randshares(), randshares());
  t2 = evalxor(t1, x[23], randshares(), randshares());
  s[31] = evalxor(t2, x[31], randshares(), randshares());

  memmove(x, s, sizeof(s));
}

void AddRoundKey(shares *x[32], shares *k[32])
{
    int i;
    for(i = 0; i < 32; i++)
    {
        x[i] = evalxor(x[i], k[i], randshares(), randshares());
    }
}
void T(shares *x[32])
{
    bs_sbox(x);
    bs_sbox(x + 8);
    bs_sbox(x + 16);
    bs_sbox(x + 24);
    L(x);
}
void bs_wbsm4(shares *x[128], shares *k[32][32], shares *y[128])
{
    int r, i;
    shares *temp, *xx[32];
    memmove(y, x, sizeof(shares *) * 128);

    for(r = 0; r < 32; r++)
    {
        for(i = 0; i < 32; i++)
        {
            temp = evalxor(y[32 + i], y[64 + i], randshares(), randshares());
            xx[i] = evalxor(temp, y[96 + i], randshares(), randshares());
        }
        AddRoundKey(xx, k[r]);
        T(xx);
        for(i = 0; i < 32; i++)
        {
            xx[i] = evalxor(xx[i], y[i], randshares(), randshares());
        }
        for(i = 0; i < 32; i++)
        {
            y[i] = y[32 + i];
            y[32 + i] = y[64 + i];
            y[64 + i] = y[96 + i];
            y[96 + i] = xx[i];
        }
    }
    for(i = 0; i < 32; i++)
    {
        temp = y[i];
        y[i] = y[96 + i];
        y[96 + i] = temp;
        temp = y[32 + i];
        y[32 + i] = y[64 + i];
        y[64 + i] = temp;
    }
}

void bs_fault_wbsm4(shares *x[128], shares *k[32][32], shares *y[128],uint8_t fault_mask,int share_index)
{
    int r, i;
    shares *temp, *xx[32];
    memmove(y, x, sizeof(shares *) * 128);

    for(r = 0; r < 31; r++)
    {
        
        for(i = 0; i < 32; i++)
        {
            temp = evalxor(y[32 + i], y[64 + i], randshares(), randshares());
            xx[i] = evalxor(temp, y[96 + i], randshares(), randshares());
        }
        AddRoundKey(xx, k[r]);
        T(xx);
        for(i = 0; i < 32; i++)
        {
            xx[i] = evalxor(xx[i], y[i], randshares(), randshares());
        }
        for(i = 0; i < 32; i++)
        {
            y[i] = y[32 + i];
            y[32 + i] = y[64 + i];
            y[64 + i] = y[96 + i];
            y[96 + i] = xx[i];
        }
    }

    for(r = 31; r < 32; r++)
    {
        // y[32+1]->a^=fault_mask;
        printf("before:%.2X\n",y[32+share_index]->c);
        y[32+share_index]->c^=fault_mask;
        printf("after:%.2X\n",y[32+share_index]->c);
        for(i = 0; i < 32; i++)
        {
            temp = evalxor(y[32 + i], y[64 + i], randshares(), randshares());
            xx[i] = evalxor(temp, y[96 + i], randshares(), randshares());
        }
        AddRoundKey(xx, k[r]);
        T(xx);
        for(i = 0; i < 32; i++)
        {
            xx[i] = evalxor(xx[i], y[i], randshares(), randshares());
        }
        for(i = 0; i < 32; i++)
        {
            y[i] = y[32 + i];
            y[32 + i] = y[64 + i];
            y[64 + i] = y[96 + i];
            y[96 + i] = xx[i];
        }
    }

    
    for(i = 0; i < 32; i++)
    {
        temp = y[i];
        y[i] = y[96 + i];
        y[96 + i] = temp;
        temp = y[32 + i];
        y[32 + i] = y[64 + i];
        y[64 + i] = temp;
    }



}







void import(u8 in[16], shares *x[128])
{
    int j, r;
    u8 temp;
    for(j = 0; j < 16; j++)
    {
        temp = in[j];
        for(r = 0; r < 8; r++)
        {
            if(temp & idM8[r]) x[j * 8 + r] = encode(1, randbit(), randbit());
            else x[j * 8 + r] = encode(0, randbit(), randbit());
        }
    }
}



void export(shares *y[128], u8 out[16])
{
    int j;
    memset(out, 0, sizeof(u8) * 16);
    for(j = 0; j < 128; j++)
    {
        if(decode(y[j])) out[j / 8] ^= idM8[j % 8];
    }
}
void genenkey(u8 key[16], shares *k[32][32])
{
    int i, j, r;
    u32 temp;
    sm4_context ctx;
    sm4_setkey_enc(&ctx, key);
    for(i = 0; i < 32; i++)
    {
        temp = ctx.sk[i];
        for(j = 0; j < 32; j++)
        {
            if(temp & idM32[j]) k[i][j] = encode(1, randbit(), randbit());
            else k[i][j] = encode(0, randbit(), randbit());
        }
    }
}