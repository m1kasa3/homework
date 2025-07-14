from PIL import Image, ImageEnhance
import os

def text_to_bin(text):
    # 将文本编码为UTF-8字节后转换为二进制字符串
    return ''.join([format(byte, '08b') for byte in text.encode('utf-8')])

def bin_to_text(bin_str):
    bytes_list = []
    for i in range(0, len(bin_str), 8):
        byte = bin_str[i:i+8]
        if len(byte) < 8:
            break
        bytes_list.append(int(byte, 2))
    try:
        return bytes(bytes_list).decode('utf-8')
    except UnicodeDecodeError:
        return bytes(bytes_list).decode('utf-8', errors='replace')

def embed_text(image_path, text, output_path):
    img = Image.open(image_path)
    # 末尾添加3个空字符作为结束符
    binary = text_to_bin(text + '\0\0\0')
    if img.mode != 'RGB':
        img = img.convert('RGB')
    pixels = img.load()

    idx = 0
    for y in range(img.height):
        for x in range(img.width):
            if idx >= len(binary):
                img.save(output_path)
                print(f"隐写信息已嵌入并保存为 {output_path}")
                return
            r, g, b = pixels[x, y]
            r = (r & 0xFE) | int(binary[idx])  # 修改红色通道最低位
            pixels[x, y] = (r, g, b)
            idx += 1
    # 如果信息过长，未嵌入完成
    img.save(output_path)
    print(f"隐写信息已嵌入（可能未完整）并保存为 {output_path}")

def extract_text(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    binary = ''
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            binary += str(r & 1)
    end_marker = '00000000' * 3  # 3个空字符结束符
    end_index = binary.find(end_marker)
    if end_index != -1:
        binary = binary[:end_index]
    text = bin_to_text(binary)
    print(f"提取出的隐写信息：{text}")
    return text

# 鲁棒性测试 - 翻转图片（左右镜像）
def test_flip(image_path, output_path):
    image = Image.open(image_path)
    flipped = image.transpose(Image.FLIP_LEFT_RIGHT)
    flipped.save(output_path)
    print(f"翻转图片保存至 {output_path}")

# 鲁棒性测试 - 调整对比度
def test_contrast(image_path, output_path, factor=1.5):
    image = Image.open(image_path)
    enhancer = ImageEnhance.Contrast(image)
    enhanced = enhancer.enhance(factor)
    enhanced.save(output_path)
    print(f"调整对比度后的图片保存至 {output_path}")

if __name__ == '__main__':
    cover_image = 'images/111.jpg'           # 原始载体图片路径
    stego_image = 'output/111_stego.png'    # 输出隐写图片路径
    secret = "姚佳硕"                        # 要隐藏的文本

    # 确保输出目录存在
    if not os.path.exists('output'):
        os.makedirs('output')

    # 1. 嵌入隐写信息
    embed_text(cover_image, secret, stego_image)
    # 2. 从隐写图像提取信息，验证嵌入效果
    extract_text(stego_image)

    # 3. 鲁棒性测试：翻转图片并提取信息
    flipped_path = 'output/111_stego_flipped.png'
    test_flip(stego_image, flipped_path)
    extract_text(flipped_path)

    # 4. 鲁棒性测试：调整对比度并提取信息
    contrast_path = 'output/111_stego_contrast.png'
    test_contrast(stego_image, contrast_path, factor=1.8)
    extract_text(contrast_path)
