# Poseidon2 Circom Implementation (t=2)

本项目使用 Circom 实现了 Poseidon2 哈希函数的零知识电路（参数为 t=2），并配合 Groth16 生成证明。该项目包含电路代码、Rust 预计算哈希代码、示例输入以及自动化构建脚本。

---

## 项目结构

poseidon2-circom/
├── circuits/
│ └── poseidon2_t2.circom # 核心电路代码
├── rust/
│ └── poseidon2_hash.rs # Rust预计算哈希代码
├── inputs/
│ └── input.json # 示例输入文件
├── build/ # 编译生成文件目录（自动生成）
├── Makefile # 自动化流程脚本
├── README.md # 项目说明文档
└── .gitignore # 忽略文件配置



---

## 环境依赖

- Node.js（推荐最新稳定版）
- npm 包管理工具
- circom 编译器（2.0 及以上版本）
- snarkjs
- Rust（包含 cargo 工具链）

## 安装步骤

1. 安装 Node.js 和 npm。

2. 全局安装 snarkjs：

```bash
npm install -g snarkjs
```

  3.安装 circom 编译器（建议官方最新版本）：

​      可参考官方仓库：https://github.com/iden3/circom

  4.安装 Rust：

访问 https://rustup.rs/ ，按照指示安装 Rust 工具链。

   5.编译 Rust 代码：

```bash
cd rust
cargo build --release

```

## 运行流程

### 1.准备 ptau 文件

项目需要 Powers of Tau 文件支持，可下载：

```
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_10.ptau

```

如果此链接不可用，可尝试其他镜像或手动上传。

### 2.编译电路，生成证明及验证

项目根目录执行：

```
make

```

此命令执行以下步骤：

- 编译电路（circom 编译）
- 运行 Groth16 setup 生成 zkey 文件
- 使用 Rust 代码生成 witness 输入（需先运行 rust 程序）
- 生成证明文件
- 验证证明正确性

### 3.生成 witness 输入

运行 Rust 程序：

```
cargo run --bin poseidon2_hash

```

程序会生成 `inputs/input.json`，包含私密输入和对应的哈希。
### 姓名学号

姚佳硕-202100460006

