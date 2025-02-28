# exp.py
#!/usr/bin/env python
# from pwn import *
from os import urandom
from Crypto.Util.number import long_to_bytes, getRandomNBitInteger, bytes_to_long
from collections import Counter
from hashlib import sha256
import itertools, random, string
# context.log_level = "debug"

dic = string.ascii_letters + string.digits

# r = remote("127.0.0.1",8006)

def solve_pow(suffix,target):
    print("[+] Solving pow")
    for i in dic:
        for j in dic:
            for k in dic:
                head = i + j + k
                h = head.encode() + suffix
                sha256 = hashlib.sha256()
                sha256.update(h)
                res = sha256.hexdigest().encode()
                if res == target:
                    print("[+] Find pow")
                    return head

def get_enc_flag():
    r.recvuntil("your flag is\n")
    enc = r.recvuntil("\n")[:-1]
    return enc

def cmd(idx):
    r.recvuntil("> ")
    r.sendline(str(idx))

def encrypt1(pt):
    cmd(1)
    r.recvuntil("your plaintext in hex")
    r.sendline(pt)
    r.recvuntil("your ciphertext in hex:")
    enc = r.recvuntil("\n")[:-1]
    return enc

def encrypt2(pt,round,f,p):
    cmd(2)
    r.recvuntil("your plaintext in hex")
    r.sendline(pt)
    r.recvuntil("give me the value of r f p")
    payload = str(round) + " " + str(f) + " " + str(p)
    r.sendline(payload)
    r.recvuntil("your ciphertext in hex:")
    enc = r.recvuntil("\n")[:-1]
    return enc

def decrypt(ct,key):
    cmd(3)
    r.recvuntil("your key in hex")
    r.sendline(key)
    r.recvuntil("your ciphertext in hex")
    r.sendline(ct)
    r.recvuntil("your plaintext in hex:")
    dec = r.recvuntil("\n")[:-1]
    return dec


xor = lambda a, b:list(map(lambda x, y: x ^ y, a, b))
rotl = lambda x, n:((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)
get_uint32_be = lambda key_data:((key_data[0] << 24) | (key_data[1] << 16) | (key_data[2] << 8) | (key_data[3]))
put_uint32_be = lambda n:[((n>>24)&0xff), ((n>>16)&0xff), ((n>>8)&0xff), ((n)&0xff)]
padding = lambda data, block=16: data + [(16 - len(data) % block)for _ in range(16 - len(data) % block)]
unpadding = lambda data: data[:-data[-1]]
list_to_bytes = lambda data: b''.join([bytes((i,)) for i in data])
bytes_to_list = lambda data: [i for i in data]

#Expanded SM4 box table
SM4_BOXES_TABLE = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,
    0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,
    0x06,0x99,0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,
    0xcf,0xac,0x62,0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,
    0x75,0x8f,0x3f,0xa6,0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,
    0x19,0xe6,0x85,0x4f,0xa8,0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,
    0x0f,0x4b,0x70,0x56,0x9d,0x35,0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,
    0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,
    0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,
    0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,0xe0,0xae,0x5d,0xa4,0x9b,0x34,
    0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,0x1d,0xf6,0xe2,0x2e,0x82,
    0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,0xd5,0xdb,0x37,0x45,
    0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,0x8d,0x1b,0xaf,
    0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,0x0a,0xc1,
    0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,0x89,
    0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,
    0x48,
]

# System parameter
SM4_FK = [0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc]

# fixed parameter
SM4_CK = [
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
]

def invL(A):
    tmp = A ^ rotl(A,2) ^ rotl(A,4) ^ rotl(A,8) ^ rotl(A,12) ^ rotl(A,14) ^ rotl(A,16) ^ rotl(A,18) ^  rotl(A,22) ^ rotl(A,24) ^ rotl(A,30)
    return tmp

def invR(l):
    tmp = [l[3],l[2],l[1],l[0]]
    return tmp

def L(bb):
    c = bb ^ (rotl(bb, 2)) ^ (rotl(bb, 10)) ^ (rotl(bb, 18)) ^ (rotl(bb, 24))
    return c

def int2list(x):
    a0 = x & 0xffffffff
    a1 = (x >> 32) & 0xffffffff
    a2 = (x >> 64) & 0xffffffff
    a3 = (x >> 96) & 0xffffffff
    return [a3,a2,a1,a0]

def fault_attak(ct1s,ct2s,target,round):
    assert len(ct1s) == len(ct2s)
    keys = []
    for guess_key in range(256):
        for i in range(len(ct1s)):
            ct1 = ct1s[i]
            ct1 = invR(int2list(bytes_to_long(ct1)))

            ct2 = ct2s[i]
            ct2 = invR(int2list(bytes_to_long(ct2)))

            if round < 32:
                for r in range(32-round):
                    ct1 = rev_round(ct1,32-r)
                    ct2 = rev_round(ct2,32-r)

            x1,x2,x3,x4 = ct1
            xx1,xx2,xx3,xx4 = ct2

            out_diff = invL(xx4 ^ x4)
            in_diff = (x1^xx1)^(x2^xx2)^(x3^xx3)
            Sa = [(out_diff >> (i*8)) & 0xff for i in range(4)]
            Sa = Sa[3-target]
            Sb = SM4_BOXES_TABLE[((xx3 ^ xx2 ^ xx1) >> (3-target)*8) & 0xff ^ guess_key]
            Sc = SM4_BOXES_TABLE[((xx3 ^ xx2 ^ xx1 ^ in_diff) >> (3-target)*8) & 0xff ^ guess_key]
            if Sa == Sb ^ Sc:
                if guess_key not in keys:
                    keys.append(guess_key)   
                    break
    return keys

def int2hex(x):
    tmp = hex(x)[2:].rjust(32,"0")
    return tmp

def attack_round_key_byte(target,round,num):
    pts = []
    ct1s = []
    ct2s = []
    p = 4 + target
    FLAG = False
    if round == 32:
        p = target
        round = 31
        FLAG = True

    f = random.randint(1,0xf)
    for i in range(num):
        pt = getRandomNBitInteger(32 * 4)
        pt = int2hex(pt)
        ct1 = long_to_bytes(int(encrypt1(pt),16))[:16]
        ct2 = long_to_bytes(int(encrypt2(pt,round,f,p),16))[:16]
        pts.append(pt)
        ct1s.append(ct1)
        ct2s.append(ct2)
    if FLAG == True:
        res1 = set(fault_attak(ct1s,ct2s,target,32))
    else:
        res1 = set(fault_attak(ct1s,ct2s,target,round))

    pts = []
    ct1s = []
    ct2s = []
    f = random.randint(1,0xff)
    for i in range(num):
        pt = getRandomNBitInteger(32 * 4)
        pt = int2hex(pt)
        ct1 = long_to_bytes(int(encrypt1(pt),16))[:16]
        ct2 = long_to_bytes(int(encrypt2(pt,round,f,p),16))[:16]
        pts.append(pt)
        ct1s.append(ct1)
        ct2s.append(ct2)
    if FLAG == True:
        res2 = set(fault_attak(ct1s,ct2s,target,32))
    else:
        res2 = set(fault_attak(ct1s,ct2s,target,round))
    res = list(res1&res2)
    return res[0]

def attack_round_keys(round):
    keys = []
    for i in range(4):
        key = attack_round_key_byte(i,round,5)
        keys.append(key)
    return keys

def rev_round(ct,round):
    global subkeys
    X1,X2,X3,X4 = ct
    sub_key = get_uint32_be(subkeys[32-round])
    sbox_in = X1 ^ X2 ^ X3 ^ sub_key
    b = [0, 0, 0, 0]
    a = put_uint32_be(sbox_in)
    b[0] = SM4_BOXES_TABLE[a[0]]
    b[1] = SM4_BOXES_TABLE[a[1]]
    b[2] = SM4_BOXES_TABLE[a[2]]
    b[3] = SM4_BOXES_TABLE[a[3]]
    bb = get_uint32_be(b[0:4])
    c = bb ^ (rotl(bb, 2)) ^ (rotl(bb, 10)) ^ (rotl(bb, 18)) ^ (rotl(bb, 24))
    X0 = X4 ^ c
    ct = X0,X1,X2,X3
    return ct

def int_list_to_bytes(x):
    tmp = 0
    for i in x:
        tmp <<= 32
        tmp |= i
    tmp = long_to_bytes(tmp)
    return tmp

def round_key(ka):
    b = [0, 0, 0, 0]
    a = put_uint32_be(ka)
    b[0] = SM4_BOXES_TABLE[a[0]]
    b[1] = SM4_BOXES_TABLE[a[1]]
    b[2] = SM4_BOXES_TABLE[a[2]]
    b[3] = SM4_BOXES_TABLE[a[3]]
    bb = get_uint32_be(b[0:4])
    rk = bb ^ (rotl(bb, 13)) ^ (rotl(bb, 23))
    return rk

def rev_key(subkeys):
    tmp_keys = [i for i in subkeys]
    for i in range(32):
        tmp_keys.append(0)
    for i in range(32):
        tmp_keys[i+4] = tmp_keys[i] ^ round_key(tmp_keys[i+1] ^ tmp_keys[i+2] ^ tmp_keys[i+3] ^ SM4_CK[31-i])
    tmp_keys = tmp_keys[::-1]
    MK = xor(SM4_FK[0:4], tmp_keys[0:4])
    MK = int_list_to_bytes(MK)
    return MK

# r.recvuntil("sha256(XXX+")
# suffix = r.recvuntil(") == ",drop = True)
# target = r.recvuntil("\n")[:-1]
# s = solve_pow(suffix,target)
# r.sendline(s)

enc_flag = get_enc_flag()

subkeys = []
t = [32,31,30,29]
for i in t:
    print("[+] Crack Round " + str(i) + " subkey")
    keys = attack_round_keys(i)
    print("[+] Find Round " + str(i) + " subkey")
    print(keys)
    subkeys.append(keys)

subkeys = [get_uint32_be(i) for i in subkeys]
attack_key = rev_key(subkeys)
attack_key = int2hex(bytes_to_long(attack_key))
print("[+] Find keys :")
print(attack_key)

enc_flag = enc_flag.decode("utf-8")
print("[+] Enc flag is :")
print(enc_flag)

flag = decrypt(enc_flag,attack_key)
flag = long_to_bytes(int(flag.decode("utf-8"),16))
print("[+] Get flag :")
print(flag)

r.interactive()