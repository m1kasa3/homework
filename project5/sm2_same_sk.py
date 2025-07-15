import hashlib
import os

# SM2 推荐曲线参数 (来自 PDF 第2页)
# y^2 = x^3 + ax + b
p = 0x8542D69E4C044F18E8892435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x78796884FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC6522883937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12DIDA2705249A
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E7987
Gx = 0x421DEBD61862EAB6746434EBC3CC315E3222083BADD50BDC4C4E6C147FEDD43D
Gy = 0x0680512BCBB42C07D47349D2153870C4E5D7FDFCBFA36EA1A8584189E46E09A2
G = (Gx, Gy)

# 模逆元计算
def inv_mod(x, n):
    return pow(x, n - 2, n)

# 模拟签名 (不涉及椭圆曲线点运算，因为代数关系已足够)
def sign_sm2_algebraic(d, k, message):
    # 在真实场景中, e = H(Z_A || M)。这里我们简化为 H(M)
    e_hex = hashlib.sha256(message.encode()).hexdigest()
    e = int(e_hex, 16)
    
    # 假设 kG = (x1, y1) 已经计算，这里我们只需要一个模拟的 x1
    # 为了让 r 有意义，我们假设 x1 是一个随机值
    # 注意：在真实攻击中，x1 是从 r 和 e 中反推出来的，但在这里我们不需要它
    # r = (e + x1) mod n
    
    # 我们直接使用 s 的公式，它不直接依赖 x1
    # s = ((1 + d)^-1 * (k - r * d)) mod n
    # 为了模拟签名，我们需要 r。我们伪造一个 r 值
    # 实际上，攻击者拥有 r 和 s
    r = (e + int.from_bytes(os.urandom(32), 'big')) % n
    
    s_inv_term = inv_mod(1 + d, n)
    s = (s_inv_term * (k - r * d)) % n
    
    return r, s, e

def sign_ecdsa_algebraic(d, k, message):
    e_hex = hashlib.sha256(message.encode()).hexdigest()
    e = int(e_hex, 16)
    
    # 同样，我们只需代数关系。假设 r = x1
    r = int.from_bytes(os.urandom(32), 'big') % n
    
    k_inv = inv_mod(k, n)
    s = (k_inv * (e + d * r)) % n
    return r, s, e

print("--- 4. 攻击场景: SM2 与 ECDSA 重用 d 和 k ---")

# 1. 模拟用户，拥有一个私钥 d
d_original = int.from_bytes(os.urandom(32), 'big') % n
print(f"原始私钥 d: {hex(d_original)}")

# 2. 用户不幸在两个协议中使用了相同的 k
k_reused = int.from_bytes(os.urandom(32), 'big') % n
print(f"重用的 k:   {hex(k_reused)}")

# 3. 生成 ECDSA 签名
message_ecdsa = "Message for ECDSA"
r1, s1, e1 = sign_ecdsa_algebraic(d_original, k_reused, message_ecdsa)
print(f"\nECDSA 签名 (r1, s1): ({hex(r1)}, {hex(s1)})")

# 4. 生成 SM2 签名
message_sm2 = "Message for SM2"
r2, s2, e2 = sign_sm2_algebraic(d_original, k_reused, message_sm2)
print(f"SM2 签名   (r2, s2): ({hex(r2)}, {hex(s2)})")

# 5. 攻击者使用两个签名恢复私钥
# d = (e1 - s1*s2) * (s1*s2 + s1*r2 - r1)^-1 mod n
numerator = (e1 - (s1 * s2)) % n
denominator = ((s1 * s2) + (s1 * r2) - r1) % n

d_recovered = (numerator * inv_mod(denominator, n)) % n
print(f"\n恢复的私钥 d: {hex(d_recovered)}")

# 6. 验证
assert d_original == d_recovered
print("\n[SUCCESS] 私钥恢复成功!\n" + "="*40 + "\n")
