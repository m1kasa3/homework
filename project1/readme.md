# SM4加密算法优化对比文档


### 查找表优化 (Lookup Table Optimization)

**原始实现：**

```cpp
unsigned int substitute_byte(unsigned int temp) {
    return S_box[temp >> 4][temp & 0xf];
}
```

**优化实现：**

```cpp
// 预计算查找表
static unsigned char S_box_lookup[256];
static bool sbox_initialized = false;

inline void init_sbox_lookup() {
    if (!sbox_initialized) {
        for (int i = 0; i < 256; i++) {
            S_box_lookup[i] = S_box[i >> 4][i & 0xf];
        }
        sbox_initialized = true;
    }
}

inline unsigned char substitute_byte_optimized(unsigned char temp) {
    return S_box_lookup[temp];
}
```

**优化效果：**

减少位运算操作 避免重复计算 提高缓存命中率



### 内联函数优化 (Inline Function Optimization)

**原始实现：**

```cpp
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
```

**优化实现：**

```cpp
inline unsigned long substitute_word_optimized(unsigned long in) {
    return (static_cast<unsigned long>(S_box_lookup[(in >> 24) & 0xff]) << 24) |
           (static_cast<unsigned long>(S_box_lookup[(in >> 16) & 0xff]) << 16) |
           (static_cast<unsigned long>(S_box_lookup[(in >> 8) & 0xff]) << 8) |
           static_cast<unsigned long>(S_box_lookup[in & 0xff]);
}
```

**优化效果：**

减少函数调用开销 编译器可以更好地优化 减少栈操作



### 循环展开优化 (Loop Unrolling)

**原始实现：**

```cpp
for (i = 0; i < 32; i++) {
    temp = round_function(plaintext[0], plaintext[1], plaintext[2], plaintext[3], round_keys[i]);
    plaintext[0] = plaintext[1];
    plaintext[1] = plaintext[2];
    plaintext[2] = plaintext[3];
    plaintext[3] = temp;
}
```

**优化实现：**

```cpp
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
```

**优化效果：**

减少循环控制开销 提高指令级并行性 减少分支预测失败



### 寄存器优化 (Register Optimization)

**原始实现：**

```cpp
void encrypt_sm4(unsigned long plaintext[4], unsigned long master_keys[4]) {
    long temp;
    int i;
    for (i = 0; i < 4; i++) {
        plaintext[i] = plaintext[i];
    }
    // ... 其他代码
}
```

**优化实现：**

```cpp
inline void encrypt_sm4_optimized(unsigned long plaintext[4], const unsigned long master_keys[4]) {
    register unsigned long X0 = plaintext[0];
    register unsigned long X1 = plaintext[1];
    register unsigned long X2 = plaintext[2];
    register unsigned long X3 = plaintext[3];
    register unsigned long temp;
    // ... 优化后的代码
}
```

**优化效果：**

减少内存访问 提高数据局部性 减少缓存未命中



### 2.5 SIMD指令优化 (SIMD Instruction Optimization)

**原始实现：**

```cpp
unsigned long rotate_left(unsigned long n, int i) {
    return (n << i) | (n >> (32 - i));
}
```

**优化实现：**

```cpp
inline unsigned long rotate_left_optimized(unsigned long n, int i) {
    #ifdef __AVX2__
    return _rotl(n, i);  // 使用SIMD指令
    #else
    return (n << i) | (n >> (32 - i));
    #endif
}
```

**优化效果：**

利用CPU向量指令 并行处理多个操作 减少指令数量

**在原有SM4代码基础上，为实现SM4-GCM模式，具体做了哪些更改和扩展**。

---

### 1. 新增的数据结构

- **block128结构体** 
  新增了一个`block128`结构体，用于表示128位（16字节）数据块。GCM模式所有数据都按16字节一块来处理。

---

### 2. 新增的辅助函数

- **ulong_to_block128 / block128_to_ulong** 
  用于在SM4内部的4个unsigned long数组和GCM用的16字节数组之间转换。

- **block128_xor** 
  实现两个128位数据块的异或操作。

- **galois_mult** 
  实现Galois域上的乘法（GF(2^128)），这是GCM认证的核心数学操作。

- **ghash** 
  实现GCM模式的认证函数，用于生成认证标签（Tag）。

- **inc32** 
  实现计数器自增，每加密一块数据，计数器加1。

- **sm4_ecb_encrypt** 
  用SM4算法加密一个128位数据块，作为GCM模式的密钥流生成器。

---

### 3. 新增的主流程函数

- **sm4_gcm_encrypt** 
  实现SM4-GCM加密和认证，输入明文、密钥、IV、AAD，输出密文和认证标签Tag。

- **sm4_gcm_decrypt** 
  实现SM4-GCM解密和认证校验，输入密文、密钥、IV、AAD、Tag，输出明文，并判断Tag是否正确。

---

### 4. 新增的main函数示例

- 新增了一个main函数，演示如何调用SM4-GCM加密、解密和认证的完整流程。

---

#
