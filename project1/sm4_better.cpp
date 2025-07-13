#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <chrono>
#include <iomanip>
#include <immintrin.h>  // 用于SIMD指令
#include <cstring>      // 用于memcpy

using namespace std;

// 优化1: 使用查找表替代S盒计算
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

// 优化2: 预计算S盒查找表，避免重复计算
static unsigned char S_box_lookup[256];
static bool sbox_initialized = false;

// 初始化S盒查找表
inline void init_sbox_lookup() {
    if (!sbox_initialized) {
        for (int i = 0; i < 256; i++) {
            S_box_lookup[i] = S_box[i >> 4][i & 0xf];
        }
        sbox_initialized = true;
    }
}

// 优化3: 使用内联函数和查找表
inline unsigned char substitute_byte_optimized(unsigned char temp) {
    return S_box_lookup[temp];
}

// 优化4: 使用位操作优化字节替换
inline unsigned long substitute_word_optimized(unsigned long in) {
    return (static_cast<unsigned long>(S_box_lookup[(in >> 24) & 0xff]) << 24) |
           (static_cast<unsigned long>(S_box_lookup[(in >> 16) & 0xff]) << 16) |
           (static_cast<unsigned long>(S_box_lookup[(in >> 8) & 0xff]) << 8) |
           static_cast<unsigned long>(S_box_lookup[in & 0xff]);
}

// 优化5: 使用SIMD指令优化循环左移（如果支持）
inline unsigned long rotate_left_optimized(unsigned long n, int i) {
    #ifdef __AVX2__
    // 使用SIMD指令优化
    return _rotl(n, i);
    #else
    // 标准实现
    return (n << i) | (n >> (32 - i));
    #endif
}

// 优化6: 内联线性变换函数
inline unsigned long linear_transform_optimized(unsigned long temp) {
    return temp ^ rotate_left_optimized(temp, 13) ^ rotate_left_optimized(temp, 23);
}

// 优化7: 内联T变换函数
inline unsigned long T_transform_optimized(unsigned long temp) {
    return linear_transform_optimized(substitute_word_optimized(temp));
}

// 常量定义
static const unsigned long CK[32] = {
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

// 优化8: 使用静态数组避免重复分配
static unsigned long round_keys[32];

// 优化9: 优化密钥生成，减少函数调用开销
inline void generate_round_keys_optimized(const unsigned long master_keys[4]) {
    unsigned long k[4];
    
    // 预计算k值
    k[0] = master_keys[0] ^ FK[0];
    k[1] = master_keys[1] ^ FK[1];
    k[2] = master_keys[2] ^ FK[2];
    k[3] = master_keys[3] ^ FK[3];

    // 展开前4轮计算
    round_keys[0] = k[0] ^ T_transform_optimized(k[1] ^ k[2] ^ k[3] ^ CK[0]);
    round_keys[1] = k[1] ^ T_transform_optimized(k[2] ^ k[3] ^ round_keys[0] ^ CK[1]);
    round_keys[2] = k[2] ^ T_transform_optimized(k[3] ^ round_keys[0] ^ round_keys[1] ^ CK[2]);
    round_keys[3] = k[3] ^ T_transform_optimized(round_keys[0] ^ round_keys[1] ^ round_keys[2] ^ CK[3]);

    // 优化循环展开
    unsigned long abefore = round_keys[3];
    for (int i = 4; i < 32; i += 4) {
        round_keys[i] = round_keys[i-4] ^ T_transform_optimized(round_keys[i-3] ^ round_keys[i-2] ^ abefore ^ CK[i]);
        round_keys[i+1] = round_keys[i-3] ^ T_transform_optimized(round_keys[i-2] ^ abefore ^ round_keys[i] ^ CK[i+1]);
        round_keys[i+2] = round_keys[i-2] ^ T_transform_optimized(abefore ^ round_keys[i] ^ round_keys[i+1] ^ CK[i+2]);
        round_keys[i+3] = abefore ^ T_transform_optimized(round_keys[i] ^ round_keys[i+1] ^ round_keys[i+2] ^ CK[i+3]);
        abefore = round_keys[i+3];
    }
}

// 优化10: 内联轮函数
inline unsigned long round_function_optimized(unsigned long X0, unsigned long X1, unsigned long X2, unsigned long X3, unsigned long round_key) {
    return X0 ^ T_transform_optimized(X1 ^ X2 ^ X3 ^ round_key);
}

// 优化11: 优化加密函数，减少内存访问
inline void encrypt_sm4_optimized(unsigned long plaintext[4], const unsigned long master_keys[4]) {
    // 初始化S盒查找表
    init_sbox_lookup();
    
    // 生成轮密钥
    generate_round_keys_optimized(master_keys);

    // 使用寄存器变量优化
    register unsigned long X0 = plaintext[0];
    register unsigned long X1 = plaintext[1];
    register unsigned long X2 = plaintext[2];
    register unsigned long X3 = plaintext[3];
    register unsigned long temp;

    // 优化12: 循环展开，减少分支预测失败
    for (int i = 0; i < 32; i += 4) {
        temp = round_function_optimized(X0, X1, X2, X3, round_keys[i]);
        X0 = X1; X1 = X2; X2 = X3; X3 = temp;
        
        temp = round_function_optimized(X0, X1, X2, X3, round_keys[i+1]);
        X0 = X1; X1 = X2; X2 = X3; X3 = temp;
        
        temp = round_function_optimized(X0, X1, X2, X3, round_keys[i+2]);
        X0 = X1; X1 = X2; X2 = X3; X3 = temp;
        
        temp = round_function_optimized(X0, X1, X2, X3, round_keys[i+3]);
        X0 = X1; X1 = X2; X2 = X3; X3 = temp;
    }

    // 反序变换
    plaintext[0] = X3;
    plaintext[1] = X2;
    plaintext[2] = X1;
    plaintext[3] = X0;
}

// 优化13: 优化解密函数
inline void decrypt_sm4_optimized(unsigned long ciphertext[4], const unsigned long master_keys[4]) {
    // 初始化S盒查找表
    init_sbox_lookup();
    
    // 生成轮密钥
    generate_round_keys_optimized(master_keys);

    // 使用寄存器变量优化
    register unsigned long X0 = ciphertext[0];
    register unsigned long X1 = ciphertext[1];
    register unsigned long X2 = ciphertext[2];
    register unsigned long X3 = ciphertext[3];
    register unsigned long temp;

    // 循环展开解密
    for (int i = 0; i < 32; i += 4) {
        temp = round_function_optimized(X0, X1, X2, X3, round_keys[31-i]);
        X0 = X1; X1 = X2; X2 = X3; X3 = temp;
        
        temp = round_function_optimized(X0, X1, X2, X3, round_keys[30-i]);
        X0 = X1; X1 = X2; X2 = X3; X3 = temp;
        
        temp = round_function_optimized(X0, X1, X2, X3, round_keys[29-i]);
        X0 = X1; X1 = X2; X2 = X3; X3 = temp;
        
        temp = round_function_optimized(X0, X1, X2, X3, round_keys[28-i]);
        X0 = X1; X1 = X2; X2 = X3; X3 = temp;
    }

    // 反序变换
    ciphertext[0] = X3;
    ciphertext[1] = X2;
    ciphertext[2] = X1;
    ciphertext[3] = X0;
}

// 优化14: 批量处理函数
void encrypt_sm4_batch(unsigned long* data, const unsigned long master_keys[4], int blocks) {
    init_sbox_lookup();
    generate_round_keys_optimized(master_keys);
    
    for (int block = 0; block < blocks; block++) {
        unsigned long* block_data = data + block * 4;
        encrypt_sm4_optimized(block_data, master_keys);
    }
}

// 性能测试函数
void performance_test() {
    cout << "\n=== 性能测试对比 ===" << endl;
    
    const int TEST_ITERATIONS = 100000;
    unsigned long test_data[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    unsigned long test_key[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    
    // 测试优化版本
    auto start_time = chrono::high_resolution_clock::now();
    
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        unsigned long temp_data[4];
        memcpy(temp_data, test_data, sizeof(test_data));
        encrypt_sm4_optimized(temp_data, test_key);
    }
    
    auto end_time = chrono::high_resolution_clock::now();
    auto optimized_duration = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    
    cout << "优化版本测试结果:" << endl;
    cout << "测试次数: " << TEST_ITERATIONS << " 次" << endl;
    cout << "总用时: " << optimized_duration.count() << " 微秒" << endl;
    cout << "平均时间: " << fixed << setprecision(3) 
         << (double)optimized_duration.count() / TEST_ITERATIONS << " 微秒/次" << endl;
    
    double throughput = (double)TEST_ITERATIONS * 16 / (optimized_duration.count() / 1000000.0);
    cout << "吞吐量: " << fixed << setprecision(2) << throughput / 1024 / 1024 << " MB/s" << endl;
}

int main() {
    cout << "SM4加密算法优化版本测试" << endl;
    cout << "=======================" << endl;
    
    // 初始化测试数据
    unsigned long plaintext[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    unsigned long master_keys[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    unsigned long original_plaintext[4];
    
    // 保存原始数据
    memcpy(original_plaintext, plaintext, sizeof(plaintext));
    
    cout << "原始明文: ";
    for (int i = 0; i < 4; i++) {
        cout << hex << setfill('0') << setw(8) << plaintext[i] << " ";
    }
    cout << endl;

    // 加密测试
    auto start_time = chrono::high_resolution_clock::now();
    encrypt_sm4_optimized(plaintext, master_keys);
    auto end_time = chrono::high_resolution_clock::now();
    auto encrypt_duration = chrono::duration_cast<chrono::microseconds>(end_time - start_time);

    cout << "加密后结果: ";
    for (int i = 0; i < 4; i++) {
        cout << hex << setfill('0') << setw(8) << plaintext[i] << " ";
    }
    cout << endl;
    cout << "加密用时: " << encrypt_duration.count() << " 微秒" << endl;

    // 解密测试
    start_time = chrono::high_resolution_clock::now();
    decrypt_sm4_optimized(plaintext, master_keys);
    end_time = chrono::high_resolution_clock::now();
    auto decrypt_duration = chrono::duration_cast<chrono::microseconds>(end_time - start_time);

    cout << "解密后结果: ";
    for (int i = 0; i < 4; i++) {
        cout << hex << setfill('0') << setw(8) << plaintext[i] << " ";
    }
    cout << endl;
    cout << "解密用时: " << decrypt_duration.count() << " 微秒" << endl;
    
    
    
    // 运行性能测试
    performance_test();
    
    
    return 0;
}
