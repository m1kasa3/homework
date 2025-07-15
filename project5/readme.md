# 算法实现与优化
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
# 签名误用
## 泄露随机数 k 导致私钥泄露 (Leaking k)
场景描述:
如果在签名过程中，随机数 

k（也称为 nonce）被泄露，攻击者可以仅凭单次签名 (r, s) 和泄露的 k，直接计算出签名者的私钥 d。该风险在文档的 "3.1 SM2 signature: leaking k" 一节中有详细描述 。


数学推导:
我们的目标是从已知的 s, k, r 和 d 的关系式中解出 d。

从 SM2 签名公式开始 ：


s = ((1 + d)⁻¹ * (k - r * d)) mod n

为了消去模逆元 (1 + d)⁻¹，将等式两边同时乘以 (1 + d)：
s * (1 + d) = (k - r * d) mod n

展开等式：
s + s * d = k - r * d mod n

将所有包含 d 的项移到等式左边，其余项移到右边：
s * d + r * d = k - s mod n

提取公因子 d：
d * (s + r) = k - s mod n

为了解出 d，两边同时乘以 (s + r)⁻¹：


d = (k - s) * (s + r)⁻¹ mod n 

推导完成。攻击者通过此公式即可计算出私钥 d。
## 重用随机数 k 导致私钥泄露 (Reusing k)
场景描述:
如果签名者使用相同的私钥 

d 和相同的随机数 k 对两条不同的消息 M₁ 和 M₂ 进行签名，攻击者可以利用这两组签名 (r₁, s₁) 和 (r₂, s₂) 来恢复私钥 d。此风险在文档的 "3.1 SM2 signature: reusing k" 一节中有描述 。


数学推导:
攻击者拥有两组签名和对应的消息哈希 e₁ 和 e₂。

根据 s 的计算公式，我们可以推导出 k 的表达式：
s * (1 + d) = k - r * d  mod n
k = s * (1 + d) + r * d  mod n

由于两次签名使用了相同的 k 和 d，我们得到两个关于 k 的等式：
k = s₁ * (1 + d) + r₁ * d  mod n
k = s₂ * (1 + d) + r₂ * d  mod n

令两个表达式相等：
s₁ * (1 + d) + r₁ * d = s₂ * (1 + d) + r₂ * d  mod n

展开并整理：
s₁ + s₁*d + r₁*d = s₂ + s₂*d + r₂*d  mod n
s₁ - s₂ = s₂*d - s₁*d + r₂*d - r₁*d  mod n
s₁ - s₂ = d * (s₂ - s₁ + r₂ - r₁)  mod n

解出 d：
d = (s₁ - s₂) * (s₂ - s₁ + r₂ - r₁)⁻¹ mod n

这个推导结果与文档中的公式 

d = (s₂ - s₁) / (s₁ - s₂ + r₁ - r₂)  在代数上是等价的（分子分母同乘以 -1）。
## 不同用户重用 k 导致密钥泄露
场景描述:
如果两个不同的用户，Alice (私钥 

d_A) 和 Bob (私钥 d_B)，在签名时因为使用了有缺陷的随机数生成器而恰好使用了相同的 k，那么其中任何一方（例如 Alice）在得知 k 后，就可以利用另一方（Bob）的公开签名来计算出对方的私钥。此场景在文档的 "3.1 SM2 signature: reusing k by different users" 中有描述 。

数学推导:
这个场景的推导非常直接，本质上是“泄露 k” 场景的变体。

假设 Alice 和 Bob 使用了同一个 k。Alice 知道这个 k (因为是她自己签名时用的)。

Bob 对消息 M_B 进行签名，产生了公开可见的签名 (r_B, s_B)。

Alice 掌握了 k, r_B, s_B。她想求解 Bob 的私钥 d_B。

这直接退化为了第一种攻击场景。Alice 使用 Bob 的签名数据代入恢复公式：


d_B = (k - s_B) * (s_B + r_B)⁻¹ mod n 
## SM2 与 ECDSA 使用相同 d 和 k 导致私钥泄露
场景描述:
这是一个跨算法的攻击。如果一个用户在不同的协议中（一个使用 SM2，一个使用 ECDSA）不慎使用了相同的私钥 

d 和相同的随机数 k，那么攻击者可以收集这两个协议下的签名，并解出私钥 d。此风险在文档的 "3.2 SM2 signature: same d and k with ECDSA" 中有描述 。

数学推导:
攻击者拥有一个 ECDSA 签名 (r₁, s₁) 和一个 SM2 签名 (r₂, s₂)。

从 ECDSA 签名中得到 k 的表达式:
s₁ = k⁻¹ * (e₁ + d * r₁) mod n
k = s₁⁻¹ * (e₁ + d * r₁) mod n

从 SM2 签名中得到 k 的表达式:
s₂ = ((1 + d)⁻¹ * (k - d * r₂)) mod n
k = s₂ * (1 + d) + d * r₂ mod n

令两个关于 k 的表达式相等:
s₁⁻¹ * (e₁ + d * r₁) = s₂ * (1 + d) + d * r₂ mod n

为了消去 s₁⁻¹，两边同时乘以 s₁：
e₁ + d * r₁ = s₁ * (s₂ * (1 + d) + d * r₂) mod n
e₁ + d * r₁ = s₁*s₂ + s₁*s₂*d + s₁*r₂*d mod n

将所有包含 d 的项移到一边：
e₁ - s₁*s₂ = d * (s₁*s₂ + s₁*r₂ - r₁) mod n

解出 d：
d = (e₁ - s₁*s₂) * (s₁*s₂ + s₁*r₂ - r₁)⁻¹ mod n

我们上述的推导不依赖 k，仅依赖两个签名和消息哈希，是实际可行的攻击。
