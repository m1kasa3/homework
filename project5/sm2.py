import secrets
import struct
from math import gcd, ceil, log
from gmssl import sm3
from typing import Tuple, Optional, List
import time

# SM2标准参数
SM2_P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
SM2_A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
SM2_B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
SM2_N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
SM2_GX = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
SM2_GY = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2

# 缓存常用计算结果
_FIELD_BYTES = ceil(ceil(log(SM2_P, 2)) / 8)
_POINT_BYTES = 2 * _FIELD_BYTES + 1

class OptimizedSM2:
    """性能优化的SM2算法实现"""
    
    def __init__(self):
        """初始化SM2算法"""
        self.p = SM2_P
        self.a = SM2_A
        self.b = SM2_B
        self.n = SM2_N
        self.G = (SM2_GX, SM2_GY)
        
        # 预计算常用值
        self._precompute_values()
    
    def _precompute_values(self):
        """预计算常用值以提高性能"""
        # 预计算模逆的常用值
        self._inv_cache = {}
        
        # 预计算2的幂次
        self._pow2_cache = [1]
        for i in range(1, 256):
            self._pow2_cache.append((self._pow2_cache[-1] * 2) % self.p)
    
    def _fast_mod_inverse(self, a: int, m: int) -> int:
        """快速模逆算法（使用扩展欧几里得算法）"""
        if a in self._inv_cache:
            return self._inv_cache[a]
        
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd_val, x, y = extended_gcd(b % a, a)
            return gcd_val, y - (b // a) * x, x
        
        gcd_val, x, _ = extended_gcd(a, m)
        if gcd_val != 1:
            raise ValueError("模逆不存在")
        
        result = x % m
        self._inv_cache[a] = result
        return result
    
    def _fast_mod_mul(self, a: int, b: int) -> int:
        """快速模乘法"""
        return (a * b) % self.p
    
    def _fast_mod_add(self, a: int, b: int) -> int:
        """快速模加法"""
        return (a + b) % self.p
    
    def _fast_mod_sub(self, a: int, b: int) -> int:
        """快速模减法"""
        return (a - b) % self.p
    
    def _optimized_int_to_bytes(self, x: int, length: Optional[int] = None) -> bytes:
        """优化的整数到字节串转换"""
        if length is None:
            length = max(1, (x.bit_length() + 7) // 8)
        return x.to_bytes(length, 'big')
    
    def _optimized_bytes_to_int(self, data: bytes) -> int:
        """优化的字节串到整数转换"""
        return int.from_bytes(data, 'big')
    
    def _optimized_hex_to_bytes(self, hex_str: str) -> bytes:
        """优化的十六进制到字节串转换"""
        return bytes.fromhex(hex_str)
    
    def _optimized_bytes_to_hex(self, data: bytes) -> str:
        """优化的字节串到十六进制转换"""
        return data.hex()
    
    def _naf_decomposition(self, k: int) -> List[int]:
        """NAF（Non-Adjacent Form）分解，用于优化标量乘法"""
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
    
    def _point_add_optimized(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """优化的点加法"""
        if P == (0, 0):  # 无穷远点
            return Q
        if Q == (0, 0):
            return P
        
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2:
            if (y1 + y2) % self.p == 0:
                return (0, 0)  # 无穷远点
            else:
                return self._point_double_optimized(P)
        
        # 计算斜率
        lambda_val = self._fast_mod_mul(
            self._fast_mod_sub(y2, y1),
            self._fast_mod_inverse(self._fast_mod_sub(x2, x1), self.p)
        )
        
        # 计算新点坐标
        x3 = self._fast_mod_sub(
            self._fast_mod_sub(self._fast_mod_mul(lambda_val, lambda_val), x1),
            x2
        )
        y3 = self._fast_mod_sub(
            self._fast_mod_mul(lambda_val, self._fast_mod_sub(x1, x3)),
            y1
        )
        
        return (x3, y3)
    
    def _point_double_optimized(self, P: Tuple[int, int]) -> Tuple[int, int]:
        """优化的二倍点"""
        if P == (0, 0):
            return P
        
        x1, y1 = P
        if y1 == 0:
            return (0, 0)  # 无穷远点
        
        # 计算斜率
        lambda_val = self._fast_mod_mul(
            self._fast_mod_add(self._fast_mod_mul(3, self._fast_mod_mul(x1, x1)), self.a),
            self._fast_mod_inverse(self._fast_mod_mul(2, y1), self.p)
        )
        
        # 计算新点坐标
        x3 = self._fast_mod_sub(
            self._fast_mod_sub(self._fast_mod_mul(lambda_val, lambda_val), x1),
            x1
        )
        y3 = self._fast_mod_sub(
            self._fast_mod_mul(lambda_val, self._fast_mod_sub(x1, x3)),
            y1
        )
        
        return (x3, y3)
    
    def _scalar_multiply_naf(self, P: Tuple[int, int], k: int) -> Tuple[int, int]:
        """使用NAF算法的标量乘法"""
        if k == 0:
            return (0, 0)
        
        # NAF分解
        naf = self._naf_decomposition(k)
        
        # 预计算点
        P_neg = (P[0], (-P[1]) % self.p)
        
        # 初始化结果
        result = (0, 0)
        
        # 从高位到低位处理
        for i in range(len(naf) - 1, -1, -1):
            result = self._point_double_optimized(result)
            if naf[i] == 1:
                result = self._point_add_optimized(result, P)
            elif naf[i] == -1:
                result = self._point_add_optimized(result, P_neg)
        
        return result
    
    def _optimized_kdf(self, Z: bytes, klen: int) -> bytes:
        """优化的密钥派生函数"""
        v = 256  # SM3哈希长度
        if klen >= (2**32 - 1) * v:
            raise ValueError("密钥长度超出限制")
        
        ct = 1
        k = b''
        
        while len(k) < klen:
            # 构造输入
            input_data = Z + struct.pack('>I', ct)
            
            # 计算哈希 - 修复：sm3_hash返回字符串，需要转换为字节
            hash_result = sm3.sm3_hash(list(input_data))
            hash_bytes = bytes.fromhex(hash_result)
            
            k += hash_bytes
            ct += 1
        
        return k[:klen]
    
    def _sm3_hash_bytes(self, data: bytes) -> bytes:
        """SM3哈希函数，返回字节串"""
        hash_result = sm3.sm3_hash(list(data))
        return bytes.fromhex(hash_result)
    
    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        """生成密钥对"""
        private_key = secrets.randbelow(self.n - 1) + 1
        public_key = self._scalar_multiply_naf(self.G, private_key)
        return private_key, public_key
    
    def encrypt(self, message: str, public_key: Tuple[int, int]) -> str:
        """加密算法"""
        # 生成随机数
        k = secrets.randbelow(self.n - 1) + 1
        
        # 计算C1 = kG
        C1 = self._scalar_multiply_naf(self.G, k)
        
        # 计算kP
        kP = self._scalar_multiply_naf(public_key, k)
        x2, y2 = kP
        
        # 计算t = KDF(x2||y2, klen)
        message_bytes = message.encode('utf-8')
        klen = len(message_bytes)
        t = self._optimized_kdf(
            self._optimized_int_to_bytes(x2, _FIELD_BYTES) + 
            self._optimized_int_to_bytes(y2, _FIELD_BYTES),
            klen
        )
        
        # 检查t是否为全零
        if all(b == 0 for b in t):
            return self.encrypt(message, public_key)  # 重新生成
        
        # 计算C2 = M ⊕ t
        C2 = bytes(a ^ b for a, b in zip(message_bytes, t))
        
        # 计算C3 = Hash(x2||M||y2) - 修复：使用新的哈希函数
        hash_input = (self._optimized_int_to_bytes(x2, _FIELD_BYTES) + 
                     message_bytes + 
                     self._optimized_int_to_bytes(y2, _FIELD_BYTES))
        C3 = self._sm3_hash_bytes(hash_input)
        
        # 组合密文
        C1_bytes = self._optimized_int_to_bytes(0x04, 1) + \
                   self._optimized_int_to_bytes(C1[0], _FIELD_BYTES) + \
                   self._optimized_int_to_bytes(C1[1], _FIELD_BYTES)
        
        ciphertext = C1_bytes + C2 + C3
        return self._optimized_bytes_to_hex(ciphertext)
    
    def decrypt(self, ciphertext: str, private_key: int) -> str:
        """解密算法"""
        # 解析密文
        cipher_bytes = self._optimized_hex_to_bytes(ciphertext)
        
        if len(cipher_bytes) < _POINT_BYTES + 32:  # C1 + 最小C3
            raise ValueError("密文长度不足")
        
        # 提取C1
        C1_bytes = cipher_bytes[:_POINT_BYTES]
        if C1_bytes[0] != 0x04:
            raise ValueError("无效的点格式")
        
        x1 = self._optimized_bytes_to_int(C1_bytes[1:_FIELD_BYTES+1])
        y1 = self._optimized_bytes_to_int(C1_bytes[_FIELD_BYTES+1:_POINT_BYTES])
        C1 = (x1, y1)
        
        # 验证C1在曲线上
        if not self._is_on_curve(C1):
            raise ValueError("C1不在椭圆曲线上")
        
        # 计算dC1
        dC1 = self._scalar_multiply_naf(C1, private_key)
        x2, y2 = dC1
        
        # 计算t = KDF(x2||y2, klen)
        C2_length = len(cipher_bytes) - _POINT_BYTES - 32
        t = self._optimized_kdf(
            self._optimized_int_to_bytes(x2, _FIELD_BYTES) + 
            self._optimized_int_to_bytes(y2, _FIELD_BYTES),
            C2_length
        )
        
        if all(b == 0 for b in t):
            raise ValueError("解密失败：t全为零")
        
        # 提取C2和C3
        C2 = cipher_bytes[_POINT_BYTES:_POINT_BYTES+C2_length]
        C3 = cipher_bytes[_POINT_BYTES+C2_length:]
        
        # 计算M' = C2 ⊕ t
        message_bytes = bytes(a ^ b for a, b in zip(C2, t))
        
        # 验证C3 - 修复：使用新的哈希函数
        expected_C3 = self._sm3_hash_bytes(
            self._optimized_int_to_bytes(x2, _FIELD_BYTES) + 
            message_bytes + 
            self._optimized_int_to_bytes(y2, _FIELD_BYTES)
        )
        
        if C3 != expected_C3:
            raise ValueError("解密失败：哈希验证失败")
        
        return message_bytes.decode('utf-8')
    
    def _is_on_curve(self, P: Tuple[int, int]) -> bool:
        """检查点是否在椭圆曲线上"""
        if P == (0, 0):
            return True
        
        x, y = P
        left = self._fast_mod_mul(y, y)
        right = self._fast_mod_add(
            self._fast_mod_add(
                self._fast_mod_mul(self._fast_mod_mul(x, x), x),
                self._fast_mod_mul(self.a, x)
            ),
            self.b
        )
        return left == right
    
    
def performance_test():
    """性能测试"""
    print("=== SM2算法性能测试 ===\n")
    
    sm2 = OptimizedSM2()
    
    # 生成密钥对
    print("1. 密钥生成性能测试...")
    start_time = time.time()
    private_key, public_key = sm2.generate_keypair()
    keygen_time = time.time() - start_time
    print(f"密钥生成时间: {keygen_time:.4f} 秒")
    
    # 加密性能测试
    print("\n2. 加密性能测试...")
    test_messages = [
        "短消息",
        "中等长度消息" * 10,
        "长消息" * 100,
        "超长消息" * 1000
    ]
    
    for i, message in enumerate(test_messages, 1):
        print(f"\n测试 {i}: 消息长度 {len(message)} 字符")
        
        start_time = time.time()
        ciphertext = sm2.encrypt(message, public_key)
        encrypt_time = time.time() - start_time
        
        start_time = time.time()
        decrypted = sm2.decrypt(ciphertext, private_key)
        decrypt_time = time.time() - start_time
        
        print(f"加密时间: {encrypt_time:.4f} 秒")
        print(f"解密时间: {decrypt_time:.4f} 秒")
        print(f"总时间: {encrypt_time + decrypt_time:.4f} 秒")
        print(f"验证: {'成功' if decrypted == message else '失败'}")
    
   
    
    print("\n=== 性能测试完成 ===")

def main():
    """主函数"""
    
    # 基本功能测试
    sm2 = OptimizedSM2()
    
    # 生成密钥对
    print("生成密钥对...")
    private_key, public_key = sm2.generate_keypair()
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: {public_key}")
    print()
    
    # 加密解密测试
    message = "Hello, SM2"
    print(f"原始消息: {message}")
    
    ciphertext = sm2.encrypt(message, public_key)
    print(f"密文: {ciphertext[:100]}...")
    
    decrypted = sm2.decrypt(ciphertext, private_key)
    print(f"解密结果: {decrypted}")
    print(f"解密验证: {'成功' if decrypted == message else '失败'}")
    print()
    
    
    
    # 运行性能测试
    performance_test()

if __name__ == "__main__":
    main()
