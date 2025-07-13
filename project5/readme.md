## 算法原理

### SM2算法概述

SM2是中国国家密码管理局发布的椭圆曲线公钥密码算法，基于椭圆曲线密码学，具有以下特点：

- 密钥长度：256位
- 安全性：相当于3072位RSA
- 计算效率：比RSA更快
- 应用场景：数字签名、公钥加密、密钥交换

### 核心数学原理

#### 椭圆曲线方程

```
y² = x³ + ax + b (mod p)
```

#### SM2标准参数

- 有限域模数 p：256位素数
- 椭圆曲线参数 a, b
- 基点 G 和阶 n
- 余因子 h = 1

### 主要功能模块

#### 密钥生成

```python
def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
    private_key = secrets.randbelow(self.n - 1) + 1
    public_key = self._scalar_multiply_naf(self.G, private_key)
    return private_key, public_key
```

#### 加密算法

1. 生成随机数 k
2. 计算 C1 = kG
3. 计算 kP = (x2, y2)
4. 计算 t = KDF(x2||y2, klen)
5. 计算 C2 = M ⊕ t
6. 计算 C3 = Hash(x2||M||y2)
7. 输出密文 C = C1||C2||C3

####  解密算法

1. 从C中提取C1，验证点有效性
2. 计算 dC1 = (x2, y2)
3. 计算 t = KDF(x2||y2, klen)
4. 计算 M' = C2 ⊕ t
5. 验证 Hash(x2||M'||y2) = C3
6. 输出明文 M'

## 性能优化技术

### NAF算法优化标量乘法

```python
def _naf_decomposition(self, k: int) -> List[int]:
    """NAF（Non-Adjacent Form）分解"""
    naf = []
    while k > 0:
        if k % 2 == 1:
            ki = 2 - (k % 4)
            k = k - ki
        else:
            ki = 0
        naf.append(ki)
        k = k // 2
    return naf
```

**优化效果**：相比二进制展开法，平均减少25%的运算次数。

###  预计算和缓存

```python
def _precompute_values(self):
    """预计算常用值"""
    self._inv_cache = {}  # 模逆缓存
    self._pow2_cache = [1]  # 2的幂次缓存
    for i in range(1, 256):
        self._pow2_cache.append((self._pow2_cache[-1] * 2) % self.p)
```

**优化效果**：减少重复计算，提升模运算效率。

### 优化的数据类型转换

```python
def _optimized_int_to_bytes(self, x: int, length: Optional[int] = None) -> bytes:
    if length is None:
        length = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(length, 'big')
```

**优化效果**：使用Python内置高效转换函数，避免字符串拼接。

### 快速模运算

```python
def _fast_mod_mul(self, a: int, b: int) -> int:
    return (a * b) % self.p

def _fast_mod_add(self, a: int, b: int) -> int:
    return (a + b) % self.p
```

**优化效果**：专门的模运算函数，减少重复计算。

## 实验结果

实验结果如图


