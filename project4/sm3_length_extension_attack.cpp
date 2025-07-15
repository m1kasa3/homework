#include<stdio.h>
#include<stdint.h>
#include <string.h>
 
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
// 生成SM3填充后的消息
void sm3_padding(const uint8_t *msg, uint32_t msg_len, uint8_t *out, uint32_t *out_len, uint64_t total_bit_len) {
    // msg_len: 原始消息长度（字节）
    // total_bit_len: 总消息长度（比特），即key+原始消息+扩展数据的总长度
    memcpy(out, msg, msg_len);
    out[msg_len] = 0x80;
    uint32_t pad_len = msg_len + 1;
    // 填充0，直到倒数8字节
    while ((pad_len % 64) != 56) {
        out[pad_len++] = 0x00;
    }
    // 填充长度（大端）
    for (int i = 0; i < 8; i++) {
        out[pad_len + 7 - i] = (total_bit_len >> (i * 8)) & 0xFF;
    }
    *out_len = pad_len + 8;
}

// 允许自定义IV和总长度的SM3哈希（只处理一块new_data，适合演示攻击）
void sm3_length_extension(const uint32_t *iv, const uint8_t *new_data, uint32_t new_data_len, uint64_t total_bit_len, uint32_t *out_hash) {
    // 只处理new_data，IV用攻击者伪造的
    uint8_t buf[128] = {0};
    uint32_t buf_len = 0;
    sm3_padding(new_data, new_data_len, buf, &buf_len, total_bit_len);
    // 只处理一块
    for (int i = 0; i < 8; i++) out_hash[i] = iv[i];
    sm3_one_block(out_hash, (uint32_t*)buf);
    // 如果buf_len > 64，还要再处理一块
    if (buf_len > 64) {
        sm3_one_block(out_hash, (uint32_t*)(buf + 64));
    }
}
 
// int main() {
//     test_case1();
//     test_case2();
//     return 0;
// }
int main() {
    // 假设key长度为16字节，内容未知
    int key_len = 16;
    // 原始消息
    const char *m = "abc";
    int m_len = strlen(m);

    // 攻击者已知的hash(key || m)
    // 这里我们模拟一下，假设key全为0
    uint8_t key[16] = {0};
    uint8_t full_msg[128] = {0};
    memcpy(full_msg, key, key_len);
    memcpy(full_msg + key_len, m, m_len);

    uint32_t hash[8];
    sm3_get_hash((uint32_t*)full_msg, hash, key_len + m_len);

    printf("原始hash(key||m): ");
    for (int i = 0; i < 8; i++) printf("%08x ", hash[i]);
    printf("\n");

    // 攻击者想扩展的新数据
    const char *new_data = "123456";
    int new_data_len = strlen(new_data);

    // 1. 计算key||m的padding
    uint8_t padding[128] = {0};
    uint32_t padding_len = 0;
    sm3_padding(NULL, key_len + m_len, padding, &padding_len, (key_len + m_len) * 8);

    // 2. 构造扩展后的消息：m || padding || new_data
    // 3. 用hash作为IV，处理new_data，消息总长度=key_len+m_len+padding_len+new_data_len
    uint64_t total_bit_len = (key_len + m_len + padding_len + new_data_len) * 8;
    uint32_t forged_hash[8];
    sm3_length_extension(hash, (const uint8_t*)new_data, new_data_len, total_bit_len, forged_hash);

    printf("扩展攻击后的hash(key||m||padding||new_data): ");
    for (int i = 0; i < 8; i++) printf("%08x ", forged_hash[i]);
    printf("\n");

    // 验证：直接计算key||m||padding||new_data的hash，结果应一致
    uint8_t real_msg[256] = {0};
    memcpy(real_msg, key, key_len);
    memcpy(real_msg + key_len, m, m_len);
    memcpy(real_msg + key_len + m_len, padding, padding_len);
    memcpy(real_msg + key_len + m_len + padding_len, new_data, new_data_len);
    uint32_t real_hash[8];
    sm3_get_hash((uint32_t*)real_msg, real_hash, key_len + m_len + padding_len + new_data_len);

    printf("真实hash(key||m||padding||new_data): ");
    for (int i = 0; i < 8; i++) printf("%08x ", real_hash[i]);
    printf("\n");

    return 0;
}
