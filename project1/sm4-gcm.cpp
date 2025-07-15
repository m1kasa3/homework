#define _CRT_SECURE_NO_WARNINGS
#include<iostream>
#include <cstring>
using namespace std;

static const unsigned char S_box[16][16] = {
	{0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
{0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
{0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
{0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
{0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
{0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
{0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
{0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
{0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
{0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
{0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
{0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
{0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
{0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
{0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
{0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};


static const unsigned long CK[32] =
{
0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};
static const unsigned long FK[4] = { 0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc };

long round_keys[32];  


unsigned long rotate_left(unsigned long n, int i) {
	return (n << i) | (n >> (32 - i));
}


unsigned long make_word(unsigned long n1, unsigned long n2, unsigned long n3, unsigned long n4) {
	return (n1 << 24) | (n2 << 16) | (n3 << 8) | n4;
}


unsigned int substitute_byte(unsigned int temp) {
	return S_box[temp >> 4][temp & 0xf];
}


unsigned long substitute_word(unsigned long in) {
	unsigned long result = 0;
	result |= static_cast<unsigned long>(substitute_byte(static_cast<unsigned int>(in >> 24) & 0xff));
	result <<= 8;
	result |= static_cast<unsigned long>(substitute_byte(static_cast<unsigned int>(in >> 16) & 0xff));
	result <<= 8;
	result |= static_cast<unsigned long>(substitute_byte(static_cast<unsigned int>(in >> 8) & 0xff));
	result <<= 8;
	result |= static_cast<unsigned long>(substitute_byte(static_cast<unsigned int>(in) & 0xff));
	return result;
}


unsigned long linear_transform(unsigned long temp) {
	return temp ^ rotate_left(temp, 13) ^ rotate_left(temp, 23);
}


unsigned long T_transform(unsigned long temp) {
	return linear_transform(substitute_word(temp));
}

// ��������Կ
void generate_round_keys(unsigned long master_keys[4]) {
	long k[4];
	long abefore, aafter;

	for (int i = 0; i < 4; i++) {
		k[i] = master_keys[i] ^ FK[i];
	}

	round_keys[0] = k[0] ^ T_transform(k[1] ^ k[2] ^ k[3] ^ CK[0]);
	round_keys[1] = k[1] ^ T_transform(k[2] ^ k[3] ^ round_keys[0] ^ CK[1]);
	round_keys[2] = k[2] ^ T_transform(k[3] ^ round_keys[0] ^ round_keys[1] ^ CK[2]);
	round_keys[3] = k[3] ^ T_transform(round_keys[0] ^ round_keys[1] ^ round_keys[2] ^ CK[3]);

	abefore = round_keys[3];

	for (int i = 4; i < 32; i++) {
		aafter = round_keys[i - 4] ^ T_transform(round_keys[i - 3] ^ round_keys[i - 2] ^ abefore ^ CK[i]);
		round_keys[i] = aafter;
		abefore = aafter;
	}
}



unsigned long round_function(unsigned long X0, unsigned long X1, unsigned long X2, unsigned long X3, unsigned long round_key) {
	return X0 ^ T_transform(X1 ^ X2 ^ X3 ^ round_key);
}


void encrypt_sm4(unsigned long plaintext[4], unsigned long master_keys[4]) {
	generate_round_keys(master_keys);

	long temp;
	int i;
	for (i = 0; i < 4; i++) {
		plaintext[i] = plaintext[i];
	}

	for (i = 0; i < 32; i++) {
		temp = round_function(plaintext[0], plaintext[1], plaintext[2], plaintext[3], round_keys[i]);
		plaintext[0] = plaintext[1];
		plaintext[1] = plaintext[2];
		plaintext[2] = plaintext[3];
		plaintext[3] = temp;
	}

	temp = plaintext[0];
	plaintext[0] = plaintext[3];
	plaintext[3] = temp;
	temp = plaintext[1];
	plaintext[1] = plaintext[2];
	plaintext[2] = temp;
}


void decrypt_sm4(unsigned long ciphertext[4], unsigned long master_keys[4]) {
	generate_round_keys(master_keys);

	long temp;
	int i;
	for (i = 0; i < 4; i++) {
		ciphertext[i] = ciphertext[i];
	}

	for (i = 0; i < 32; i++) {
		temp = round_function(ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3], round_keys[32 - i - 1]);
		ciphertext[0] = ciphertext[1];
		ciphertext[1] = ciphertext[2];
		ciphertext[2] = ciphertext[3];
		ciphertext[3] = temp;
	}

	temp = ciphertext[0];
	ciphertext[0] = ciphertext[3];
	ciphertext[3] = temp;
	temp = ciphertext[1];
	ciphertext[1] = ciphertext[2];
	ciphertext[2] = temp;
}

// 128位数据结构
struct block128 {
    unsigned char b[16];
};

// 将unsigned long数组转为block128
void ulong_to_block128(const unsigned long in[4], block128 &out) {
    for (int i = 0; i < 4; ++i) {
        out.b[i * 4 + 0] = (in[i] >> 24) & 0xFF;
        out.b[i * 4 + 1] = (in[i] >> 16) & 0xFF;
        out.b[i * 4 + 2] = (in[i] >> 8) & 0xFF;
        out.b[i * 4 + 3] = (in[i]) & 0xFF;
    }
}

// 将block128转为unsigned long数组
void block128_to_ulong(const block128 &in, unsigned long out[4]) {
    for (int i = 0; i < 4; ++i) {
        out[i] = ((unsigned long)in.b[i * 4 + 0] << 24) |
                 ((unsigned long)in.b[i * 4 + 1] << 16) |
                 ((unsigned long)in.b[i * 4 + 2] << 8) |
                 ((unsigned long)in.b[i * 4 + 3]);
    }
}

// 128位异或
void block128_xor(block128 &a, const block128 &b) {
    for (int i = 0; i < 16; ++i) {
        a.b[i] ^= b.b[i];
    }
}

// Galois域乘法（GF(2^128)）——简化版
void galois_mult(const block128 &X, const block128 &Y, block128 &result) {
    block128 Z = {0};
    block128 V;
    memcpy(&V, &Y, 16);
    for (int i = 0; i < 128; ++i) {
        int bit = (X.b[i / 8] >> (7 - (i % 8))) & 1;
        if (bit) block128_xor(Z, V);
        // V = V * x
        int lsb = V.b[15] & 1;
        for (int j = 15; j > 0; --j) V.b[j] = (V.b[j] >> 1) | ((V.b[j - 1] & 1) << 7);
        V.b[0] >>= 1;
        if (lsb) V.b[0] ^= 0xe1; // 0xe1 = 1110 0001, GCM多项式
    }
    memcpy(&result, &Z, 16);
}

// GHASH函数
void ghash(const block128 &H, const unsigned char *aad, int aad_len,
           const unsigned char *cipher, int cipher_len, block128 &tag) {
    block128 Y = {0};
    int i;
    // 处理AAD
    for (i = 0; i + 16 <= aad_len; i += 16) {
        block128 tmp;
        memcpy(&tmp, aad + i, 16);
        block128_xor(Y, tmp);
        galois_mult(Y, H, Y);
    }
    if (i < aad_len) {
        block128 tmp = {0};
        memcpy(&tmp, aad + i, aad_len - i);
        block128_xor(Y, tmp);
        galois_mult(Y, H, Y);
    }
    // 处理密文
    for (i = 0; i + 16 <= cipher_len; i += 16) {
        block128 tmp;
        memcpy(&tmp, cipher + i, 16);
        block128_xor(Y, tmp);
        galois_mult(Y, H, Y);
    }
    if (i < cipher_len) {
        block128 tmp = {0};
        memcpy(&tmp, cipher + i, cipher_len - i);
        block128_xor(Y, tmp);
        galois_mult(Y, H, Y);
    }
    // 处理长度信息
    block128 len_block = {0};
    unsigned long aad_bits = aad_len * 8;
    unsigned long cipher_bits = cipher_len * 8;
    len_block.b[7] = (aad_bits) & 0xFF;
    len_block.b[6] = (aad_bits >> 8) & 0xFF;
    len_block.b[5] = (aad_bits >> 16) & 0xFF;
    len_block.b[4] = (aad_bits >> 24) & 0xFF;
    len_block.b[15] = (cipher_bits) & 0xFF;
    len_block.b[14] = (cipher_bits >> 8) & 0xFF;
    len_block.b[13] = (cipher_bits >> 16) & 0xFF;
    len_block.b[12] = (cipher_bits >> 24) & 0xFF;
    block128_xor(Y, len_block);
    galois_mult(Y, H, Y);
    memcpy(&tag, &Y, 16);
}

// 计数器自增
void inc32(block128 &ctr) {
    for (int i = 15; i >= 12; --i) {
        if (++ctr.b[i]) break;
    }
}

// SM4-ECB加密单个128位块
void sm4_ecb_encrypt(const block128 &in, block128 &out, unsigned long master_keys[4]) {
    unsigned long input[4];
    block128_to_ulong(in, input);
    encrypt_sm4(input, master_keys);
    ulong_to_block128(input, out);
}

// GCM加密
void sm4_gcm_encrypt(const unsigned char *plaintext, int plen,
                     const unsigned char *aad, int aad_len,
                     const unsigned char *key, const unsigned char *iv, int iv_len,
                     unsigned char *ciphertext, unsigned char *tag) {
    // 1. 生成轮密钥
    unsigned long mk[4];
    for (int i = 0; i < 4; ++i) {
        mk[i] = ((unsigned long)key[i * 4 + 0] << 24) |
                ((unsigned long)key[i * 4 + 1] << 16) |
                ((unsigned long)key[i * 4 + 2] << 8) |
                ((unsigned long)key[i * 4 + 3]);
    }
    // 2. 计算H = SM4_E_K(0^128)
    block128 H = {0};
    sm4_ecb_encrypt(H, H, mk);

    // 3. 生成初始计数器J0
    block128 J0 = {0};
    if (iv_len == 12) { // 96位IV
        memcpy(J0.b, iv, 12);
        J0.b[15] = 1;
    } else {
        memcpy(J0.b, iv, iv_len > 16 ? 16 : iv_len);
    }

    // 4. 计数器加密
    block128 ctr;
    memcpy(&ctr, &J0, 16);
    inc32(ctr);

    int nblocks = (plen + 15) / 16;
    for (int i = 0; i < nblocks; ++i) {
        block128 keystream;
        sm4_ecb_encrypt(ctr, keystream, mk);
        int blocksize = (i == nblocks - 1 && plen % 16) ? (plen % 16) : 16;
        for (int j = 0; j < blocksize; ++j) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ keystream.b[j];
        }
        inc32(ctr);
    }

    // 5. 计算认证标签
    block128 tag_block;
    ghash(H, aad, aad_len, ciphertext, plen, tag_block);
    // Tag = GHASH ^ E_K(J0)
    block128 J0_enc;
    sm4_ecb_encrypt(J0, J0_enc, mk);
    block128_xor(tag_block, J0_enc);
    memcpy(tag, tag_block.b, 16);
}

// GCM解密
bool sm4_gcm_decrypt(const unsigned char *ciphertext, int clen,
                     const unsigned char *aad, int aad_len,
                     const unsigned char *key, const unsigned char *iv, int iv_len,
                     const unsigned char *tag,
                     unsigned char *plaintext) {
    // 1. 生成轮密钥
    unsigned long mk[4];
    for (int i = 0; i < 4; ++i) {
        mk[i] = ((unsigned long)key[i * 4 + 0] << 24) |
                ((unsigned long)key[i * 4 + 1] << 16) |
                ((unsigned long)key[i * 4 + 2] << 8) |
                ((unsigned long)key[i * 4 + 3]);
    }
    // 2. 计算H = SM4_E_K(0^128)
    block128 H = {0};
    sm4_ecb_encrypt(H, H, mk);

    // 3. 生成初始计数器J0
    block128 J0 = {0};
    if (iv_len == 12) {
        memcpy(J0.b, iv, 12);
        J0.b[15] = 1;
    } else {
        memcpy(J0.b, iv, iv_len > 16 ? 16 : iv_len);
    }

    // 4. 计数器加密
    block128 ctr;
    memcpy(&ctr, &J0, 16);
    inc32(ctr);

    int nblocks = (clen + 15) / 16;
    for (int i = 0; i < nblocks; ++i) {
        block128 keystream;
        sm4_ecb_encrypt(ctr, keystream, mk);
        int blocksize = (i == nblocks - 1 && clen % 16) ? (clen % 16) : 16;
        for (int j = 0; j < blocksize; ++j) {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ keystream.b[j];
        }
        inc32(ctr);
    }

    // 5. 验证认证标签
    block128 tag_block;
    ghash(H, aad, aad_len, ciphertext, clen, tag_block);
    block128 J0_enc;
    sm4_ecb_encrypt(J0, J0_enc, mk);
    block128_xor(tag_block, J0_enc);
    // 比较tag
    return memcmp(tag, tag_block.b, 16) == 0;
}

int main() {
    // 明文、密钥、IV、AAD示例
    unsigned char key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char iv[12] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,0x12,0x34,0x56,0x78};
    unsigned char aad[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};
    unsigned char plaintext[32] = "hello, this is sm4-gcm test!";
    unsigned char ciphertext[32] = {0};
    unsigned char tag[16] = {0};

    // 加密
    sm4_gcm_encrypt(plaintext, 32, aad, 16, key, iv, 12, ciphertext, tag);

    cout << "密文: ";
    for (int i = 0; i < 32; ++i) printf("%02x ", ciphertext[i]);
    cout << endl;
    cout << "认证标签: ";
    for (int i = 0; i < 16; ++i) printf("%02x ", tag[i]);
    cout << endl;

    // 解密
    unsigned char decrypted[32] = {0};
    bool ok = sm4_gcm_decrypt(ciphertext, 32, aad, 16, key, iv, 12, tag, decrypted);
    cout << "解密" << (ok ? "成功" : "失败") << endl;
    cout << "明文: " << decrypted << endl;

    return 0;
}
