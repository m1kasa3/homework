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

print("--- 3. 攻击场景: 不同用户重用 k ---")

# 1. 模拟 Alice 和 Bob
d_A = int.from_bytes(os.urandom(32), 'big') % n
d_B = int.from_bytes(os.urandom(32), 'big') % n
print(f"Alice 的私钥 dA: {hex(d_A)}")
print(f"Bob 的私钥   dB: {hex(d_B)}")

# 2. 两人因某种原因（如坏的RNG）使用了同一个 k
k_shared = int.from_bytes(os.urandom(32), 'big') % n
print(f"共享的 k:         {hex(k_shared)}")

# 3. Alice 签名 (她知道 k)
message_A = "Alice's message"
r_A, s_A, e_A = sign_sm2_algebraic(d_A, k_shared, message_A)

# 4. Bob 签名 (他的签名被公开)
message_B = "Bob's message"
r_B, s_B, e_B = sign_sm2_algebraic(d_B, k_shared, message_B)
print(f"\nBob 的公开签名 (rB, sB): ({hex(r_B)}, {hex(s_B)})")

# 5. Alice 作为攻击者，使用她已知的 k 和 Bob 的公开签名来恢复 Bob 的私钥
# dB = (k - sB) * (sB + rB)^-1 mod n
s_plus_r_inv_B = inv_mod(s_B + r_B, n)
dB_recovered_by_Alice = ((k_shared - s_B) * s_plus_r_inv_B) % n

print(f"\nAlice 恢复出的 Bob 的私钥: {hex(dB_recovered_by_Alice)}")

# 6. 验证
assert d_B == dB_recovered_by_Alice
print("\n[SUCCESS] Alice 成功恢复了 Bob 的私钥!\n" + "="*40 + "\n")
