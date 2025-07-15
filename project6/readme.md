### 协议说明

1. 初始化

   客户端和服务器初始化 OPRF 协议，生成各自的密钥对。服务器将泄露数据库（DB）按哈希前缀分成多个桶（bucket），以优化 PSI 的效率（参考论文中的桶化机制）。PSI 协议初始化，用于安全比较集合。

2. 客户端流程

   计算密码的哈希值（Hash(pw)）。使用 OPRF 盲化哈希值，生成盲化输入（blinded_h）和盲化因子（blinding_factor）。根据哈希前缀确定密码所属的桶编号（bucket_id）。发送盲化哈希和桶编号给服务器。接收服务器返回的 OPRF 评估结果和对应桶的 OPRF 输出集合。解盲 OPRF 输出，得到 unblinded_h。使用 PSI 协议检查 unblinded_h 是否在桶集合中，判断密码是否泄露。

3. 服务器流程

   接收客户端的盲化哈希（blinded_h）和桶编号（bucket_id）。对盲化哈希执行 OPRF 评估，生成 oprf_output。对指定桶中的所有哈希值执行 OPRF 评估，生成桶的 OPRF 输出集合（bucket_set）。将 oprf_output 和 bucket_set 发送回客户端。

   

### 代码说明

1. **OPRF 模拟**：使用 `SimplifiedOPRF` 类通过 Diffie-Hellman 密钥交换模拟 OPRF。客户端对密码哈希进行盲化，服务器对盲化输入进行评估，客户端解盲得到结果。实际中，应使用标准 OPRF 协议（如论文中的 2HashDH），并借助 `liboprf` 等库。
2. **私有集合交集（PSI）**：这里简化为直接比较 OPRF 输出的哈希值。实际 PSI 需要使用加密技术（如同态加密或不经意传输）确保双方数据隐私。论文中使用桶化 PSI，将密码分组到桶中以减少通信开销。
3. **泄露数据库**：`breach_db` 是模拟的泄露密码哈希列表（SHA-256）。实际系统中，这将是一个大型动态数据库。