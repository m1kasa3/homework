#include<stdio.h>
#include<stdint.h>
 
static const uint32_t IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};
 
uint32_t Tj(uint8_t j) {
    if (j < 16)
        return 0x79cc4519;
    return 0x7a879d8a;
}
 
uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, uint8_t j) {
    if (j < 16)
        return X ^ Y ^ Z;
    return (X & Y) | (X & Z) | (Y & Z);
}
 
uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, uint8_t j) {
    if (j < 16)
        return X ^ Y ^ Z;
    return (X & Y) | ((~X) & Z);
}
 
uint32_t RL(uint32_t a, uint8_t k) {
    k = k % 32;
    return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k));
}
 
uint32_t P0(uint32_t X) {
    return X ^ (RL(X, 9)) ^ (RL(X, 17));
}
 
uint32_t P1(uint32_t X) {
    return X ^ (RL(X, 15)) ^ (RL(X, 23));
}
 
void sm3_one_block(uint32_t *hash, const uint32_t *block) {
    uint32_t Wj0[68];
    uint32_t Wj1[64];
    uint32_t A = hash[0], B = hash[1], C = hash[2], D = hash[3];
    uint32_t E = hash[4], F = hash[5], G = hash[6], H = hash[7];
    uint32_t SS1, SS2, TT1, TT2;
    uint8_t i, j;
 
    for (i = 0; i < 16; i++) {
        Wj0[i] = block[i];
    }
    for (i = 16; i < 68; i++) {
        Wj0[i] = P1(Wj0[i - 16] ^ Wj0[i - 9] ^ RL(Wj0[i - 3], 15)) ^ RL(Wj0[i - 13], 7) ^ Wj0[i - 6];
    }
    for (i = 0; i < 64; i++) {
        Wj1[i] = Wj0[i] ^ Wj0[i + 4];
    }
 
    for (j = 0; j < 64; j++) {
        SS1 = RL((RL(A, 12) + E + RL(Tj(j), j)) & 0xFFFFFFFF, 7);
        SS2 = SS1 ^ (RL(A, 12));
        TT1 = (FF(A, B, C, j) + D + SS2 + Wj1[j]) & 0xFFFFFFFF;
        TT2 = (GG(E, F, G, j) + H + SS1 + Wj0[j]) & 0xFFFFFFFF;
        D = C;
        C = RL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = RL(F, 19);
        F = E;
        E = P0(TT2);
    }
 
    hash[0] = (A ^ hash[0]);
    hash[1] = (B ^ hash[1]);
    hash[2] = (C ^ hash[2]);
    hash[3] = (D ^ hash[3]);
    hash[4] = (E ^ hash[4]);
    hash[5] = (F ^ hash[5]);
    hash[6] = (G ^ hash[6]);
    hash[7] = (H ^ hash[7]);
}
 
void sm3_get_hash(uint32_t *src, uint32_t *hash, uint32_t len) {
    uint8_t last_block[64] = {0};
    uint32_t i = 0;
    for (i = 0; i < 8; i++) {
        hash[i] = IV[i];
    }
    for (i = 0; i < len; i = i + 64) {
        if (len - i < 64)break;
        sm3_one_block(hash, src + i);
    }
    uint32_t last_block_len = len - i;
    uint32_t word_len = ((last_block_len + 3) >> 2) << 2;
    uint32_t last_word_len = last_block_len & 3;
    for (int j = 0; j < word_len; j++)
        last_block[j] = *((uint8_t *) src + i + j);
    switch (last_word_len) {
        case 0:
            last_block[word_len + 3] = 0x80;
            break;
        case 1:
            last_block[word_len - 4] = 0;
            last_block[word_len - 3] = 0;
            last_block[word_len - 2] = 0x80;
            break;
        case 2:
            last_block[word_len - 4] = 0;
            last_block[word_len - 3] = 0x80;
            break;
        case 3:
            last_block[word_len - 4] = 0x80;
            break;
        default:
            break;
    }
    if (last_block_len < 56) {
        uint32_t bit_len = len << 3;
        last_block[63] = (bit_len >> 24) & 0xff;
        last_block[62] = (bit_len >> 16) & 0xff;
        last_block[61] = (bit_len >> 8) & 0xff;
        last_block[60] = (bit_len) & 0xff;
        sm3_one_block(hash, (uint32_t *) last_block);
    } else {
        sm3_one_block(hash, (uint32_t *) last_block);
        unsigned char lblock[64] = {0};
        uint32_t bit_len = len << 3;
        lblock[63] = (bit_len >> 24) & 0xff;
        lblock[62] = (bit_len >> 16) & 0xff;
        lblock[61] = (bit_len >> 8) & 0xff;
        lblock[60] = (bit_len) & 0xff;
        sm3_one_block(hash, (uint32_t *) lblock);
    }
}
void test_case1() {
    uint32_t src[1] = {0x61626300};
    uint32_t hash[8];
    uint32_t len = 3;
    sm3_get_hash(src, hash, len);
 
    printf("hash(hex): ");
    for (int i = 0; i < 8; i++) {
        printf("%08x ", hash[i]);
    }
    printf("\n");
}
 
void test_case2() {
    uint32_t src[16] = {0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364,
                        0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364};
    uint32_t hash[8];
    uint32_t len = 64;
    sm3_get_hash(src, hash, len);
 
    printf("hash(hex): ");
    for (int i = 0; i < 8; i++) {
        printf("%08x ", hash[i]);
    }
    printf("\n");
}
 
int main() {
    test_case1();
    test_case2();
    return 0;
}
