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
    int i;
    shares *s = (shares *)malloc(sizeof(shares));
    s->a[0] = cus_random() & 0x1;
    s->a[1] = cus_random() & 0x1;
    s->a[2] = cus_random() & 0x1;
    for(i = 1; i <= N; i++)
    {
        s->b[i] = cus_random() & 0x1;
    }
    return s;
}
//////////

////////// masking scheme
shares *encode(u8 x)
{
    int i;
    u8 ra[3], rb[N];
    shares *s = (shares *)malloc(sizeof(shares));
    for(i = 0; i <= 2; i++)
    {
        ra[i] = randbit();
        s->a[i] = ra[i];
    }
    s->b[N] = (s->a[0] & s->a[1] & s->a[2]) ^ x;
    for(i = 1; i < N; i++)
    {
        rb[i] = randbit();
        s->b[i] = rb[i];
        s->b[N] ^= rb[i];
    }
    return s;
}

u8 decode(shares *s)
{
    int i;
    u8 temp = s->a[0] & s->a[1] & s->a[2];
    for(i = 1; i <= N; i++)
    {
        temp ^= s->b[i];
    }
    return temp;
}

shares *refresh(shares *x)
{
    int i, j;
    shares *s = (shares *)malloc(sizeof(shares));
    u8 r[3], r0, temp, W, R, W1;
    for(i = 0; i <= 2; i++)
    {
        r[i] = randbit();
        s->a[i] = x->a[i] ^ r[i];
    }

    for(i = 1; i <= N; i++)
    {
        s->b[i] = x->b[i];
    }
    for(i = 1; i <= N; i++)
    {    
        for(j = i + 1; j <= N; j++)
        {
            temp = randbit();
            s->b[i] ^= temp;
            s->b[j] ^= temp;
        }
    }
    r0 = randbit();
    W = ((r[2] & (x->a[0] ^ r0)) & (r[1] ^ x->a[1] ^ r0)) ^ ((r[1] & (x->a[2] ^ r0)) & (r[0] ^ x->a[0] ^ r0)) ^ ((r[0] & (x->a[1] ^ r0)) & (r[2] ^ x->a[2] ^ r0));
    R = ((r[0] ^ r0) & (r[1] ^ r0) & (r[2] ^ r0)) ^ (r0 & ((r[2] & (x->a[0] ^ r0)) ^ (r[1] & (x->a[0] ^ r0)) ^ (r[0] & (x->a[1] ^ r0)))) ^ (r0 & ((r[2] & (x->a[1] ^ r0)) ^ (r[1] & (x->a[2] ^ r0)) ^ (r[0] & (x->a[2] ^ r0)))) ^ r0;
    // W1 = (r[0] & r[1] & r[2]) ^ (x->a[0] & r[1] & r[2]) ^ (x->a[1] & r[0] & r[2]) ^ (x->a[2] & r[0] & r[1]) ^ (x->a[0] & x->a[1] & r[2]) ^ (x->a[0] & x->a[2] & r[1]) ^ (x->a[1] & x->a[2] & r[0]);
    // R = W ^ W1;
    s->b[N] ^= W ^ R;
    return s;
}

shares *evalxor(shares *x, shares *y)
{
    int i;
    u8 U;
    shares *s = (shares *)malloc(sizeof(shares));
    x = refresh(x);
    y = refresh(y);
    for(i = 0; i <= 2; i++)
    {
        s->a[i] = x->a[i] ^ y->a[i];
    }
    
    for(i = 1; i < N; i++)
    {
        s->b[i] = x->b[i] ^ y->b[i];
    }
    U = (x->a[1] & ((x->a[2] & y->a[0]) ^ (y->a[2] & (x->a[0] ^ y->a[0])))) ^ (y->a[1] & ((x->a[2] & y->a[0]) ^ (x->a[0] & (x->a[2] ^ y->a[2]))));
    s->b[N] = x->b[N] ^ y->b[N] ^ U;
    return s;
}

shares *evaland(shares *x, shares *y)
{
    int i, j, t;
    u8 ra[3][N + 1], rb[N + 1][N + 1], u = 0, v = 0;
    shares *s = (shares *)malloc(sizeof(shares));
    x = refresh(x);
    y = refresh(y);
    for(i = 0; i <= 2; i++)
    {
        s->a[i] = x->a[i] & y->a[(i + 1) % 3];
        for(j = 1; j <= N; j++)
        {
            ra[i][j] = randbit();
            s->a[i] ^= ra[i][j];
        }
    }
    for(t = 1; t <= N; t++)
    {
        u ^= ra[1][t];
    }
    for(t = 1; t <= N; t++)
    {
        v ^= ra[2][t];
    }

    for(i = 0; i <= N; i++)
    {
        for(j = i + 1; j <= N; j++)
        {
            if(i == 0) 
            {
                rb[j][0] = (x->a[0] & ((x->a[2] & ((x->a[1] & y->b[j]) ^ (ra[0][j] & y->a[0]))) ^ (ra[1][j] & v & y->a[1]))) ^ \
                    (y->a[0] & ((y->a[1] & ((y->a[2] & x->b[j]) ^ (ra[1][j] & x->a[2]))) ^ (ra[0][j] & u & x->a[2]))) ^ \
                    (x->a[0] & y->a[1] & ((ra[1][j] & x->a[2] & y->a[0]) ^ (ra[2][j] & x->a[1] & y->a[2]))) ^ (ra[0][j] & x->a[1] & y->a[2] & (v ^ (x->a[2] & y->a[0]))) ^ \
                    (x->a[2] & y->a[0] & ((ra[0][j] & x->a[0]) ^ (ra[1][j] & y->a[1]))) ^ (u & v & ra[0][j]);
            }
            else
            {
                rb[i][j] = randbit();
                rb[j][i] = rb[i][j] ^ (x->b[i] & y->b[j]) ^ (x->b[j] & y->b[i]);
            }
        }
    }
    for(i = 1; i <= N; i++)
    {
        s->b[i] = x->b[i] & y->b[i];
        for(j = 0; j <= N; j++)
        {
            if(j != i) s->b[i] ^= rb[i][j];
        }
    }
    return s;
}

shares *evalnot(shares *x)
{
    int i;
    shares *s = (shares *)malloc(sizeof(shares));
    s->a[0] = x->a[0];
    s->a[1] = x->a[1];
    s->a[2] = x->a[2];
    for(i = 1; i < N; i++)
    {
        s->b[i] = x->b[i];
    }
    s->b[N] = x->b[N] ^ 0x1;
    return s;
}
void bs_sbox(shares *x[8])
{
    shares *s[8];
    shares *y_t[21], *t_t[8], *t_m[46], *y_m[18], *t_b[30];
    y_t[18] = evalxor(x[5], x[1]);
    t_t[ 0] = evalxor(x[4], x[3]);
    t_t[ 1] = evalxor(x[5], x[0]);
    t_t[ 2] = evalxor(x[0], y_t[18]);
    t_t[ 3] = evalxor(x[6], t_t[ 1]);
    t_t[ 4] = evalxor(x[1], x[0]);
    t_t[ 5] = evalxor(x[7], y_t[18]);
    t_t[ 6] = evalxor(x[4], x[1]);
    y_t[10] = evalxor(x[6], y_t[18]);
    y_t[ 0] = evalxor(x[2],  evalnot(y_t[10]));
    y_t[ 1] = evalxor(t_t[ 0], t_t[ 3]);
    y_t[ 2] = evalxor(x[7], t_t[ 0]);
    y_t[ 4] = evalxor(x[7], t_t[ 3]);
    y_t[ 3] = evalxor(x[4], y_t[ 4]);
    y_t[ 5] = evalxor(x[2], t_t[ 5]);
    y_t[ 6] = evalxor(x[7],  evalnot(x[6]));
    y_t[ 7] = evalxor(t_t[ 0],  evalnot(y_t[10]));
    y_t[ 8] = evalxor(t_t[ 0], t_t[ 5]);
    y_t[ 9] = x[4];
    y_t[11] = evalxor(t_t[ 0], t_t[ 4]);
    y_t[12] = evalxor(x[2], t_t[ 4]);
    y_t[13] = evalxor(x[2],  evalnot(y_t[ 1]));
    y_t[14] = evalxor(x[3],  evalnot(t_t[ 2]));
    y_t[15] = evalxor(x[6],  evalnot(t_t[ 6]));
    y_t[16] = evalxor(x[7],  evalnot(t_t[ 2]));
    y_t[17] = evalxor(t_t[ 0],  evalnot(t_t[ 2]));
    y_t[19] = evalxor(x[2],  evalnot(y_t[14]));
    y_t[20] = evalxor(x[7], t_t[ 1]);

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
  	t_m[ 0] = evalxor(y_t[ 3], y_t[12]);
    t_m[ 1] = evaland(y_t[ 9], y_t[ 5]);
    t_m[ 2] = evaland(y_t[17], y_t[ 6]);
    t_m[ 3] = evalxor(y_t[10], t_m[ 1]);
    t_m[ 4] = evaland(y_t[14], y_t[ 0]);
    t_m[ 5] = evalxor(t_m[ 4], t_m[ 1]);
    t_m[ 6] = evaland(y_t[ 3], y_t[12]);
    t_m[ 7] = evaland(y_t[16], y_t[ 7]);
    t_m[ 8] = evalxor(t_m[ 0], t_m[ 6]);
    t_m[ 9] = evaland(y_t[15], y_t[13]);
    t_m[10] = evalxor(t_m[ 9], t_m[ 6]);
    t_m[11] = evaland(y_t[ 1], y_t[11]);
    t_m[12] = evaland(y_t[ 4], y_t[20]);
    t_m[13] = evalxor(t_m[12], t_m[11]);
    t_m[14] = evaland(y_t[ 2], y_t[ 8]);
    t_m[15] = evalxor(t_m[14], t_m[11]);
    t_m[16] = evalxor(t_m[ 3], t_m[ 2]);
    t_m[17] = evalxor(t_m[ 5], y_t[18]);
    t_m[18] = evalxor(t_m[ 8], t_m[ 7]);
    t_m[19] = evalxor(t_m[10], t_m[15]);
    t_m[20] = evalxor(t_m[16], t_m[13]);
    t_m[21] = evalxor(t_m[17], t_m[15]);
    t_m[22] = evalxor(t_m[18], t_m[13]);
    t_m[23] = evalxor(t_m[19], y_t[19]);
    t_m[24] = evalxor(t_m[22], t_m[23]);
    t_m[25] = evaland(t_m[22], t_m[20]);
    t_m[26] = evalxor(t_m[21], t_m[25]);
    t_m[27] = evalxor(t_m[20], t_m[21]);
    t_m[28] = evalxor(t_m[23], t_m[25]);
    t_m[29] = evaland(t_m[28], t_m[27]);
    t_m[30] = evaland(t_m[26], t_m[24]);
    t_m[31] = evaland(t_m[20], t_m[23]);
    t_m[32] = evaland(t_m[27], t_m[31]);
    t_m[33] = evalxor(t_m[27], t_m[25]);
    t_m[34] = evaland(t_m[21], t_m[22]);
    t_m[35] = evaland(t_m[24], t_m[34]);
    t_m[36] = evalxor(t_m[24], t_m[25]);
    t_m[37] = evalxor(t_m[21], t_m[29]);
    t_m[38] = evalxor(t_m[32], t_m[33]);
    t_m[39] = evalxor(t_m[23], t_m[30]);
    t_m[40] = evalxor(t_m[35], t_m[36]);
    t_m[41] = evalxor(t_m[38], t_m[40]);
    t_m[42] = evalxor(t_m[37], t_m[39]);
    t_m[43] = evalxor(t_m[37], t_m[38]);
    t_m[44] = evalxor(t_m[39], t_m[40]);
    t_m[45] = evalxor(t_m[42], t_m[41]);
    y_m[ 0] = evaland(t_m[38], y_t[ 7]);
    y_m[ 1] = evaland(t_m[37], y_t[13]);
    y_m[ 2] = evaland(t_m[42], y_t[11]);
    y_m[ 3] = evaland(t_m[45], y_t[20]);
    y_m[ 4] = evaland(t_m[41], y_t[ 8]);
    y_m[ 5] = evaland(t_m[44], y_t[ 9]);
    y_m[ 6] = evaland(t_m[40], y_t[17]);
    y_m[ 7] = evaland(t_m[39], y_t[14]);
    y_m[ 8] = evaland(t_m[43], y_t[ 3]);
    y_m[ 9] = evaland(t_m[38], y_t[16]);
    y_m[10] = evaland(t_m[37], y_t[15]);
    y_m[11] = evaland(t_m[42], y_t[ 1]);
    y_m[12] = evaland(t_m[45], y_t[ 4]);
    y_m[13] = evaland(t_m[41], y_t[ 2]);
    y_m[14] = evaland(t_m[44], y_t[ 5]);
    y_m[15] = evaland(t_m[40], y_t[ 6]);
    y_m[16] = evaland(t_m[39], y_t[ 0]);
    y_m[17] = evaland(t_m[43], y_t[12]);

  //bottom(outer) linear layer for sm4
  	t_b[ 0] = evalxor(y_m[ 4], y_m[ 7]);
    t_b[ 1] = evalxor(y_m[13], y_m[15]);
    t_b[ 2] = evalxor(y_m[ 2], y_m[16]);
    t_b[ 3] = evalxor(y_m[ 6], t_b[ 0]);
    t_b[ 4] = evalxor(y_m[12], t_b[ 1]);
    t_b[ 5] = evalxor(y_m[ 9], y_m[10]);
    t_b[ 6] = evalxor(y_m[11], t_b[ 2]);
    t_b[ 7] = evalxor(y_m[ 1], t_b[ 4]);
    t_b[ 8] = evalxor(y_m[ 0], y_m[17]);
    t_b[ 9] = evalxor(y_m[ 3], y_m[17]);
    t_b[10] = evalxor(y_m[ 8], t_b[ 3]);
    t_b[11] = evalxor(t_b[ 2], t_b[ 5]);
    t_b[12] = evalxor(y_m[14], t_b[ 6]);
    t_b[13] = evalxor(t_b[ 7], t_b[ 9]);
    t_b[14] = evalxor(y_m[ 0], y_m[ 6]);
    t_b[15] = evalxor(y_m[ 7], y_m[16]);
    t_b[16] = evalxor(y_m[ 5], y_m[13]);
    t_b[17] = evalxor(y_m[ 3], y_m[15]);
    t_b[18] = evalxor(y_m[10], y_m[12]);
    t_b[19] = evalxor(y_m[ 9], t_b[ 1]);
    t_b[20] = evalxor(y_m[ 4], t_b[ 4]);
    t_b[21] = evalxor(y_m[14], t_b[ 3]);
    t_b[22] = evalxor(y_m[16], t_b[ 5]);
    t_b[23] = evalxor(t_b[ 7], t_b[14]);
    t_b[24] = evalxor(t_b[ 8], t_b[11]);
    t_b[25] = evalxor(t_b[ 0], t_b[12]);
    t_b[26] = evalxor(t_b[17], t_b[ 3]);
    t_b[27] = evalxor(t_b[18], t_b[10]);
    t_b[28] = evalxor(t_b[19], t_b[ 6]);
    t_b[29] = evalxor(t_b[ 8], t_b[10]);
		// s[0] = t_b[11] ^ 0x01 ^  t_b[13];
		// s[1] = t_b[15] ^ 0x01 ^  t_b[23];
		// s[2] = t_b[20] ^ t_b[24];
		// s[3] = t_b[16] ^ t_b[25];
		// s[4] = t_b[26] ^ 0x01 ^  t_b[22];
		// s[5] = t_b[21] ^ t_b[13];
		// s[6] = t_b[27] ^ 0x01 ^  t_b[12];
		// s[7] = t_b[28] ^ 0x01 ^  t_b[29];

    s[7] = evalxor(t_b[11], evalnot(t_b[13]));
    s[6] = evalxor(t_b[15], evalnot(t_b[23]));
    s[5] = evalxor(t_b[20], t_b[24]);
    s[4] = evalxor(t_b[16], t_b[25]);
    s[3] = evalxor(t_b[26], evalnot(t_b[22]));
    s[2] = evalxor(t_b[21], t_b[13]);
    s[1] = evalxor(t_b[27], evalnot(t_b[12]));
    s[0] = evalxor(t_b[28], evalnot(t_b[29]));

    memmove(x,s,sizeof(s));
}

void L(shares *x[32])
{
  shares *s[32];
  shares *t0, *t1, *t2;
  t0 = evalxor(x[0], x[2]);
  t1 = evalxor(t0, x[10]);
  t2 = evalxor(t1, x[18]);
  s[0] = evalxor(t2, x[24]);

  t0 = evalxor(x[1], x[3]);
  t1 = evalxor(t0, x[11]);
  t2 = evalxor(t1, x[19]);
  s[1] = evalxor(t2, x[25]);

  t0 = evalxor(x[2], x[4]);
  t1 = evalxor(t0, x[12]);
  t2 = evalxor(t1, x[20]);
  s[2] = evalxor(t2, x[26]);

  t0 = evalxor(x[3], x[5]);
  t1 = evalxor(t0, x[13]);
  t2 = evalxor(t1, x[21]);
  s[3] = evalxor(t2, x[27]);

  t0 = evalxor(x[4], x[6]);
  t1 = evalxor(t0, x[14]);
  t2 = evalxor(t1, x[22]);
  s[4] = evalxor(t2, x[28]);

  t0 = evalxor(x[5], x[7]);
  t1 = evalxor(t0, x[15]);
  t2 = evalxor(t1, x[23]);
  s[5] = evalxor(t2, x[29]);

  t0 = evalxor(x[6], x[8]);
  t1 = evalxor(t0, x[16]);
  t2 = evalxor(t1, x[24]);
  s[6] = evalxor(t2, x[30]);

  t0 = evalxor(x[7], x[9]);
  t1 = evalxor(t0, x[17]);
  t2 = evalxor(t1, x[25]);
  s[7] = evalxor(t2, x[31]);

  t0 = evalxor(x[0], x[8]);
  t1 = evalxor(t0, x[10]);
  t2 = evalxor(t1, x[18]);
  s[8] = evalxor(t2, x[26]);

  t0 = evalxor(x[1], x[9]);
  t1 = evalxor(t0, x[11]);
  t2 = evalxor(t1, x[19]);
  s[9] = evalxor(t2, x[27]);

  t0 = evalxor(x[2], x[10]);
  t1 = evalxor(t0, x[12]);
  t2 = evalxor(t1, x[20]);
  s[10] = evalxor(t2, x[28]);

  t0 = evalxor(x[3], x[11]);
  t1 = evalxor(t0, x[13]);
  t2 = evalxor(t1, x[21]);
  s[11] = evalxor(t2, x[29]);

  t0 = evalxor(x[4], x[12]);
  t1 = evalxor(t0, x[14]);
  t2 = evalxor(t1, x[22]);
  s[12] = evalxor(t2, x[30]);

  t0 = evalxor(x[5], x[13]);
  t1 = evalxor(t0, x[15]);
  t2 = evalxor(t1, x[23]);
  s[13] = evalxor(t2, x[31]);

  t0 = evalxor(x[0], x[6]);
  t1 = evalxor(t0, x[14]);
  t2 = evalxor(t1, x[16]);
  s[14]  = evalxor(t2, x[24]);

  t0 = evalxor(x[1], x[7]);
  t1 = evalxor(t0, x[15]);
  t2 = evalxor(t1, x[17]);
  s[15] = evalxor(t2, x[25]);

  t0 = evalxor(x[2], x[8]);
  t1 = evalxor(t0, x[16]);
  t2 = evalxor(t1, x[18]);
  s[16] = evalxor(t2, x[26]);

  t0 = evalxor(x[3], x[9]);
  t1 = evalxor(t0, x[17]);
  t2 = evalxor(t1, x[19]);
  s[17] = evalxor(t2, x[27]);

  t0 = evalxor(x[4], x[10]);
  t1 = evalxor(t0, x[18]);
  t2 = evalxor(t1, x[20]);
  s[18] = evalxor(t2, x[28]);

  t0 = evalxor(x[5], x[11]);
  t1 = evalxor(t0, x[19]);
  t2 = evalxor(t1, x[21]);
  s[19] = evalxor(t2, x[29]);

  t0 = evalxor(x[6], x[12]);
  t1 = evalxor(t0, x[20]);
  t2 = evalxor(t1, x[22]);
  s[20] = evalxor(t2, x[30]);

  t0 = evalxor(x[7], x[13]);
  t1 = evalxor(t0, x[21]);
  t2 = evalxor(t1, x[23]);
  s[21] = evalxor(t2, x[31]);

  t0 = evalxor(x[0], x[8]);
  t1 = evalxor(t0, x[14]);
  t2 = evalxor(t1, x[22]);
  s[22] = evalxor(t2, x[24]);

  t0 = evalxor(x[1], x[9]);
  t1 = evalxor(t0, x[15]);
  t2 = evalxor(t1, x[23]);
  s[23] = evalxor(t2, x[25]);

  t0 = evalxor(x[2], x[10]);
  t1 = evalxor(t0, x[16]);
  t2 = evalxor(t1, x[24]);
  s[24] = evalxor(t2, x[26]);

  t0 = evalxor(x[3], x[11]);
  t1 = evalxor(t0, x[17]);
  t2 = evalxor(t1, x[25]);
  s[25] = evalxor(t2, x[27]);

  t0 = evalxor(x[4], x[12]);
  t1 = evalxor(t0, x[18]);
  t2 = evalxor(t1, x[26]);
  s[26] = evalxor(t2, x[28]);

  t0 = evalxor(x[5], x[13]);
  t1 = evalxor(t0, x[19]);
  t2 = evalxor(t1, x[27]);
  s[27] = evalxor(t2, x[29]);

  t0 = evalxor(x[6], x[14]);
  t1 = evalxor(t0, x[20]);
  t2 = evalxor(t1, x[28]);
  s[28] = evalxor(t2, x[30]);

  t0 = evalxor(x[7], x[15]);
  t1 = evalxor(t0, x[21]);
  t2 = evalxor(t1, x[29]);
  s[29] = evalxor(t2, x[31]);

  t0 = evalxor(x[0], x[8]);
  t1 = evalxor(t0, x[16]);
  t2 = evalxor(t1, x[22]);
  s[30] = evalxor(t2, x[30]);

  t0 = evalxor(x[1], x[9]);
  t1 = evalxor(t0, x[17]);
  t2 = evalxor(t1, x[23]);
  s[31] = evalxor(t2, x[31]);

  memmove(x, s, sizeof(s));
}

void AddRoundKey(shares *x[32], shares *k[32])
{
    int i;
    for(i = 0; i < 32; i++)
    {
        x[i] = evalxor(x[i], k[i]);
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
            temp = evalxor(y[32 + i], y[64 + i]);
            xx[i] = evalxor(temp, y[96 + i]);
        }
        AddRoundKey(xx, k[r]);
        T(xx);
        for(i = 0; i < 32; i++)
        {
            xx[i] = evalxor(xx[i], y[i]);
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
            if(temp & idM8[r]) x[j * 8 + r] = encode(1);
            else x[j * 8 + r] = encode(0);
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
            if(temp & idM32[j]) k[i][j] = encode(1);
            else k[i][j] = encode(0);
        }
    }
}