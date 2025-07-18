# Project 2: 图片隐写实验

## 实验简介

本项目实现了基于图片的文本隐写，将文本信息嵌入到图片的红色通道最低有效位中，实现隐写与提取功能，并进行了简单的鲁棒性测试，包括图片翻转和对比度调整。

## 文件结构

project2/
 ├── images/               # 实验用原始图片（111.jpg）
 ├── output/               # 隐写后及测试生成的图片
 ├── main.py               # 隐写和提取及鲁棒性测试的主程序代码
 ├── README.md             # 实验说明文件

## 运行环境

- Python 3.6+
- 依赖库: Pillow (`pip install pillow`)

## 使用说明

1. 准备一张实验用图片 `111.jpg`，放入 `images/` 文件夹。
2. 在 `main.py` 中修改要隐写的文本 `secret` 变量。
3. 在命令行中运行：
   ```bash
   python main.py
   ```

   4.隐写后图片及鲁棒性测试图片会生成在 `output/` 文件夹，文件名包括：

   - `111_stego.png` （隐写图片）
   - `111_stego_flipped.png` （翻转测试）
   - `111_stego_contrast.png` （对比度调整测试）

   5.程序会自动提取隐写信息并打印。

## 实验效果

- 成功将文本“姚佳硕”隐写到图片中。
- 翻转和调整对比度后隐写信息出现乱码，说明鲁棒性有限。
- 原始隐写图片中提取的文本正确无误。

## 改进建议

- 增加对裁剪、旋转等更多图像变换的鲁棒性测试。
- 采用更复杂的隐写算法以提升鲁棒性。
- 增强隐写容量支持更长文本。
- 设计错误检测与纠正机制，提高提取准确率。

 实验者：姚佳硕
 学号：202100460006
