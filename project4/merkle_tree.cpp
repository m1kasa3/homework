#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/err.h>

// 定义32字节的哈希类型
using Hash = std::vector<unsigned char>;

// --- 辅助函数 ---

// 将二进制哈希转换为十六进制字符串以便打印
std::string hash_to_hex(const Hash& hash) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : hash) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// SM3 哈希计算函数
Hash sm3_hash(const std::vector<unsigned char>& data) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    // 使用 SM3 算法
    const EVP_MD* md = EVP_get_digestbyname("SM3");
    if (!md) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("SM3 not supported by this OpenSSL version. Use OpenSSL 3.0+");
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize digest");
    }

    if (1 != EVP_DigestUpdate(mdctx, data.data(), data.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update digest");
    }

    Hash hash_result(EVP_MD_size(md));
    unsigned int length = 0;
    if (1 != EVP_DigestFinal_ex(mdctx, hash_result.data(), &length)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize digest");
    }
    hash_result.resize(length);
    EVP_MD_CTX_free(mdctx);

    return hash_result;
}


// --- Merkle 树核心类 ---

class MerkleTree {
public:
    // 存在性证明（审计路径）
    struct ExistenceProof {
        size_t leaf_index;
        std::vector<Hash> audit_path; // 兄弟节点的哈希路径
    };

    // 非存在性证明（依赖于排序树）
    struct NonExistenceProof {
        bool item_is_leftmost; // 待证数据是否小于所有叶子
        bool item_is_rightmost; // 待证数据是否大于所有叶子
        ExistenceProof adjacent_proof; // 相邻叶子的存在性证明
        std::string adjacent_leaf_data; // 相邻叶子的原始数据
    };

    // 构造函数：构建 Merkle 树
    MerkleTree(const std::vector<std::string>& leaves, bool sort_for_non_existence = false)
      : is_sorted_(sort_for_non_existence) {
        if (leaves.empty()) {
            // RFC6962: 空树的根是空字符串的哈希
            root_ = sm3_hash({});
            return;
        }
        
        original_leaves_ = leaves;
        if (is_sorted_) {
            std::sort(original_leaves_.begin(), original_leaves_.end());
        }

        build_tree();
    }

    // 获取根哈希
    Hash get_root() const {
        return root_;
    }

    // 生成存在性证明
    std::optional<ExistenceProof> generate_existence_proof(const std::string& leaf_data) {
        auto it = std::find(original_leaves_.begin(), original_leaves_.end(), leaf_data);
        if (it == original_leaves_.end()) {
            return std::nullopt; // 叶子不存在
        }
        size_t leaf_index = std::distance(original_leaves_.begin(), it);
        
        ExistenceProof proof;
        proof.leaf_index = leaf_index;
        
        size_t current_index = leaf_index;
        for (size_t i = 0; i < tree_levels_.size() - 1; ++i) {
            const auto& current_level = tree_levels_[i];
            size_t sibling_index;
            if (current_index % 2 == 0) {
                sibling_index = current_index + 1;
            } else {
                sibling_index = current_index - 1;
            }

            // 如果兄弟节点是最后一个且为奇数时复制的节点
            if (sibling_index >= current_level.size()) {
                proof.audit_path.push_back(current_level[current_index]);
            } else {
                proof.audit_path.push_back(current_level[sibling_index]);
            }
            current_index /= 2;
        }
        return proof;
    }

    // 验证存在性证明
    static bool verify_existence_proof(const Hash& root, const std::string& leaf_data, const ExistenceProof& proof) {
        Hash current_hash = hash_leaf(leaf_data);
        size_t current_index = proof.leaf_index;

        for (const auto& sibling_hash : proof.audit_path) {
            if (current_index % 2 == 0) { // 当前哈希在左边
                current_hash = hash_internal(current_hash, sibling_hash);
            } else { // 当前哈希在右边
                current_hash = hash_internal(sibling_hash, current_hash);
            }
            current_index /= 2;
        }
        return current_hash == root;
    }
    
    // 生成非存在性证明 (必须在排序树上调用)
    std::optional<NonExistenceProof> generate_non_existence_proof(const std::string& data) {
        if (!is_sorted_) {
            std::cerr << "Warning: Non-existence proof should only be generated from a sorted tree." << std::endl;
            return std::nullopt;
        }

        // lower_bound 找到第一个不小于 data 的元素
        auto it = std::lower_bound(original_leaves_.begin(), original_leaves_.end(), data);

        // 如果找到的元素就是 data 本身，说明它存在，无法生成证明
        if (it != original_leaves_.end() && *it == data) {
            return std::nullopt;
        }

        NonExistenceProof proof;
        if (it == original_leaves_.begin()) {
            // data 小于所有叶子
            proof.item_is_leftmost = true;
            proof.item_is_rightmost = false;
            proof.adjacent_leaf_data = *it; // 提供第一个叶子的证明
        } else if (it == original_leaves_.end()) {
            // data 大于所有叶子
            proof.item_is_leftmost = false;
            proof.item_is_rightmost = true;
            proof.adjacent_leaf_data = *(it - 1); // 提供最后一个叶子的证明
        } else {
            // data 在 *(it-1) 和 *it 之间
            proof.item_is_leftmost = false;
            proof.item_is_rightmost = false;
            // 提供后一个元素(it)的证明，证明这个“空隙”
            proof.adjacent_leaf_data = *it;
        }

        auto adjacent_existence_proof = generate_existence_proof(proof.adjacent_leaf_data);
        if (!adjacent_existence_proof) {
            // 理论上不可能发生
            return std::nullopt;
        }
        proof.adjacent_proof = *adjacent_existence_proof;
        return proof;
    }

    // 验证非存在性证明
    static bool verify_non_existence_proof(const Hash& root, const std::string& data_to_check, const NonExistenceProof& proof) {
        // 1. 验证相邻叶子的存在性证明是否有效
        if (!verify_existence_proof(root, proof.adjacent_leaf_data, proof.adjacent_proof)) {
            return false;
        }

        // 2. 检查相邻关系是否正确，从而证明 data_to_check 不存在
        if (proof.item_is_leftmost) {
            return data_to_check < proof.adjacent_leaf_data;
        }
        if (proof.item_is_rightmost) {
            return data_to_check > proof.adjacent_leaf_data;
        }
        
        // 找到相邻叶子在证明中的位置
        // lower_bound 找到第一个不小于 data_to_check 的元素
        const std::string& leaf_before = original_leaves_sorted_for_verification[proof.adjacent_proof.leaf_index - 1];
        const std::string& leaf_after = proof.adjacent_leaf_data;
        
        return data_to_check > leaf_before && data_to_check < leaf_after;
    }

    // 为了验证非存在性证明，验证者需要排序后的叶子列表
    // 在实际场景中，验证者可以从可信源获取这个列表
    static std::vector<std::string> original_leaves_sorted_for_verification;

private:
    std::vector<std::string> original_leaves_;
    std::vector<std::vector<Hash>> tree_levels_;
    Hash root_;
    bool is_sorted_;

    // RFC6962 叶子哈希
    static Hash hash_leaf(const std::string& data) {
        std::vector<unsigned char> to_hash;
        to_hash.push_back(0x00);
        to_hash.insert(to_hash.end(), data.begin(), data.end());
        return sm3_hash(to_hash);
    }

    // RFC6962 内部节点哈希
    static Hash hash_internal(const Hash& left, const Hash& right) {
        std::vector<unsigned char> to_hash;
        to_hash.push_back(0x01);
        to_hash.insert(to_hash.end(), left.begin(), left.end());
        to_hash.insert(to_hash.end(), right.begin(), right.end());
        return sm3_hash(to_hash);
    }
    
    void build_tree() {
        if (original_leaves_.empty()) return;

        tree_levels_.clear();

        // Level 0: 哈希所有叶子
        std::vector<Hash> current_level;
        for (const auto& leaf : original_leaves_) {
            current_level.push_back(hash_leaf(leaf));
        }
        tree_levels_.push_back(current_level);

        // 迭代构建上层，直到只剩一个根节点
        while (current_level.size() > 1) {
            std::vector<Hash> next_level;
            for (size_t i = 0; i < current_level.size(); i += 2) {
                const Hash& left = current_level[i];
                // 如果是奇数个节点，复制最后一个与自身配对
                const Hash& right = (i + 1 < current_level.size()) ? current_level[i + 1] : left;
                next_level.push_back(hash_internal(left, right));
            }
            current_level = next_level;
            tree_levels_.push_back(current_level);
        }

        root_ = current_level[0];
    }
};

// 静态成员初始化
std::vector<std::string> MerkleTree::original_leaves_sorted_for_verification;


// --- 主函数：演示 ---
int main() {
    // 1. 生成10万个叶子节点数据
    std::cout << "--- 1. Generating 100,000 leaf nodes ---" << std::endl;
    std::vector<std::string> leaves;
    for (int i = 0; i < 100000; ++i) {
        leaves.push_back("leaf-data-" + std::to_string(i));
    }
    std::cout << "Done." << std::endl << std::endl;

    // --- 存在性证明演示 ---
    std::cout << "--- 2. Existence Proof Demonstration (Unsorted Tree) ---" << std::endl;
    // 使用原始顺序（未排序）构建树
    MerkleTree tree(leaves, false);
    Hash root = tree.get_root();
    std::cout << "Merkle Tree Root (SM3): " << hash_to_hex(root) << std::endl;
    
    // a. 证明一个存在的叶子
    std::string existing_leaf = "leaf-data-54321";
    std::cout << "\nAttempting to prove existence of: \"" << existing_leaf << "\"" << std::endl;
    auto proof_opt = tree.generate_existence_proof(existing_leaf);
    if (proof_opt) {
        std::cout << "Proof generated successfully. Audit path size: " << proof_opt->audit_path.size() << std::endl;
        bool is_valid = MerkleTree::verify_existence_proof(root, existing_leaf, *proof_opt);
        std::cout << "Verification result: " << (is_valid ? "SUCCESS" : "FAILED") << std::endl;
    }

    // b. 尝试用错误的数据验证，应该失败
    std::cout << "\nAttempting to verify with tampered data..." << std::endl;
    std::string tampered_leaf = "leaf-data-tampered";
    bool is_valid_tampered = MerkleTree::verify_existence_proof(root, tampered_leaf, *proof_opt);
    std::cout << "Verification result for tampered data: " << (is_valid_tampered ? "SUCCESS" : "FAILED") << std::endl;
    
    std::cout << std::endl;

    // --- 非存在性证明演示 ---
    std::cout << "--- 3. Non-Existence Proof Demonstration (Sorted Tree) ---" << std::endl;
    std::cout << "Building a new tree with sorted leaves..." << std::endl;
    
    // 为了非存在性证明，我们需要一个基于排序叶子的树
    MerkleTree sorted_tree(leaves, true);
    Hash sorted_root = sorted_tree.get_root();
    std::cout << "Sorted Merkle Tree Root (SM3): " << hash_to_hex(sorted_root) << std::endl;
    
    // 验证者需要有排序后的叶子列表才能完成验证
    MerkleTree::original_leaves_sorted_for_verification = leaves;
    std::sort(MerkleTree::original_leaves_sorted_for_verification.begin(), MerkleTree::original_leaves_sorted_for_verification.end());

    std::string non_existing_leaf = "leaf-data-999999"; // 这个数据肯定不存在
    std::cout << "\nAttempting to prove non-existence of: \"" << non_existing_leaf << "\"" << std::endl;
    
    auto non_proof_opt = sorted_tree.generate_non_existence_proof(non_existing_leaf);
    if (non_proof_opt) {
        std::cout << "Non-existence proof generated successfully." << std::endl;
        std::cout << "Proves that \"" << non_existing_leaf << "\" is greater than the last element \"" << non_proof_opt->adjacent_leaf_data << "\"" << std::endl;
        
        bool is_non_existent = MerkleTree::verify_non_existence_proof(sorted_root, non_existing_leaf, *non_proof_opt);
        std::cout << "Verification result for non-existence: " << (is_non_existent ? "SUCCESS" : "FAILED") << std::endl;
    } else {
         std::cout << "Failed to generate non-existence proof (maybe the item actually exists?)" << std::endl;
    }

    // 尝试为一个存在的叶子生成非存在性证明，应该失败
    std::string existing_leaf_sorted = "leaf-data-100";
    std::cout << "\nAttempting to prove non-existence of an existing leaf: \"" << existing_leaf_sorted << "\"" << std::endl;
    auto non_proof_fail_opt = sorted_tree.generate_non_existence_proof(existing_leaf_sorted);
    if (!non_proof_fail_opt) {
        std::cout << "Correctly failed to generate proof for an existing item." << std::endl;
    }

    return 0;
}
