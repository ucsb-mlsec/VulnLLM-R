#!/bin/bash

# 示例1：从原始数据集生成相关CWE（简单版本）
echo "=== 示例1：从原始数据集生成相关CWE ==="
python generate_related_cwe_simple.py \
    --model_name "gpt-4o-mini" \
    --dataset_type "test/function_level" \
    --languages c python java \
    --batch_size 20 \
    --max_tokens 2048 \
    --only_vulnerable \
    --requests_per_minute 60

# 示例2：从reasoning数据生成相关CWE（只处理正确预测的样本）
echo -e "\n=== 示例2：从reasoning数据生成相关CWE ==="
python generate_related_cwe.py \
    --model_name "gpt-4o-mini" \
    --dataset_type "clean_dataset" \
    --training_set "test" \
    --input_path "../../datasets/reasoning_data/clean_dataset/gpt-4o-mini_test.json" \
    --only_correct \
    --batch_size 50 \
    --max_tokens 2048

# 示例3：使用本地vLLM服务器
echo -e "\n=== 示例3：使用本地vLLM服务器 ==="
python generate_related_cwe_simple.py \
    --model_name "Qwen/Qwen2.5-7B-Instruct" \
    --dataset_type "test/test_clean" \
    --languages c \
    --tp 2 \
    --batch_size 100 \
    --only_vulnerable

# 示例4：使用OpenAI兼容的API服务器
echo -e "\n=== 示例4：使用API服务器 ==="
python generate_related_cwe.py \
    --model_name "deepseek-chat" \
    --server_url "https://api.deepseek.com/v1" \
    --dataset_type "noisy_dataset" \
    --training_set "train" \
    --batch_size 30 \
    --requests_per_minute 30 