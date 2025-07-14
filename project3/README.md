# Poseidon2 Circom Implementation (t=2)

本项目是使用 Circom 实现的 Poseidon2 哈希函数零知识电路（参数 t=2），并配合 Groth16 生成证明。

## 实验参数

- 哈希算法：Poseidon2
- 参数：(n, t, d) = (256, 2, 5)
- 电路：使用 circomlib poseidon 模块（支持常量轮数与 MDS 矩阵）
- 证明系统：Groth16
- 公共输入：Poseidon2 哈希输出
- 私密输入：原始 preimage（二元数组）

## 项目 结构

poseidon2-circom/
├── circuits/
│   └── poseidon2_t2.circom
├── rust/
│   └── poseidon2_hash.rs
├── inputs/
│   └── input.json
├── build/
├── Makefile
├── .gitignore
└── README.md

##  使用流程

1. 安装依赖工具：
   ```bash
   npm install -g snarkjs
   cargo install poseidon-rs # 或手动构建
   ```

2. 准备 ptau 文件（推荐使用现成的）：
   ```bash
   wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_10.ptau
   ```

3. 编译 + 生成证明：
   ```bash
   make
   ```

4. 验证证明：
   ```bash
   make verify
   ```

