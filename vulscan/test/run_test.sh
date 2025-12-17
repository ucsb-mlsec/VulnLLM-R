#!/bin/bash

# Default parameters
output_dir="results/test_data"
requests_per_minute=1000
batch_size=4
tp=4
max_tokens=8192
n=1
test_data="./datasets/test/function_level/ ./datasets/test/repo_level/"
language="c python java"

usage() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  -o DIR       Output directory (default: $output_dir)"
  echo "  -r NUM       Requests per minute (default: $requests_per_minute)"
  echo "  -b NUM       Batch size (default: $batch_size)"
  echo "  -t NUM       Tensor parallelism (default: $tp)"
  echo "  -m NUM       Max tokens (default: $max_tokens)"
  echo "  -n NUM       Number of samples (default: $n)"
  echo "  -d PATH      Test data path (default: $test_data)"
  echo "  -l LANGS     Languages (default: $language)"
  echo "  -h           Show this help message"
  exit 1
}

while getopts "o:r:b:t:g:m:n:d:l:h" opt; do
  case $opt in
    o) output_dir="$OPTARG" ;;
    r) requests_per_minute="$OPTARG" ;;
    b) batch_size="$OPTARG" ;;
    t) tp="$OPTARG" ;;
    m) max_tokens="$OPTARG" ;;
    n) n="$OPTARG" ;;
    d) test_data="$OPTARG" ;;
    l) language="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# Define models
models=(
    "agentica-org/DeepCoder-14B-Preview"
    "google/gemma-3-4b-it"
    "google/gemma-3-12b-it"
    "Qwen/Qwen2.5-1.5B-Instruct"
    "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    "Qwen/Qwen2.5-Coder-7B-Instruct"
    "Qwen/Qwen2.5-7B-Instruct"
    "Qwen/Qwen2.5-32B-Instruct"
    "Qwen/QwQ-32B-Preview"
    "Qwen/QwQ-32B"
    "simplescaling/s1.1-32B"
    "NovaSky-AI/Sky-T1-32B-Preview"
    "NovaSky-AI/Sky-T1-32B-Flash"
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B"
    "together-deepseek-reasoner"
    "gpt-4o"
    "o3-mini"
    "claude-3-7-sonnet-20250219"
)
commercial_models=(
  "together-deepseek-reasoner"
  "gpt-4o"
  "gpt-4o-2024-11-20"
  "o3-mini"
  "claude-3-7-sonnet-20250219"
  "deepseek/deepseek-reasoner"
)
is_commercial_model() {
  local model=$1
  for commercial_model in "${commercial_models[@]}"; do
    if [[ "$model" == "$commercial_model" ]]; then
      return 0 # True
    fi
  done
  return 1 # False
}

cd "$(pwd | grep -q '/vulscan/test$' && echo '.' || echo './vulscan/test')" || exit
realpath_value=$(realpath ../../)
export PYTHONPATH=$PYTHONPATH:$realpath_value

# Iterate over models
for model in "${models[@]}"; do
  echo "Running model: $model"

  if is_commercial_model "$model"; then
    # Run without GPU monitoring for commercial models
    if [[ "$model" == *deepseek-reasoner* ]]; then
      python test.py \
        --output_dir "$output_dir" \
        --dataset_path "$test_data" \
        --language "$language" \
        --model "$model" \
        --requests_per_minute "$requests_per_minute" \
        --save --use_cot --use_policy \
        --batch_size "$batch_size" --together_deepseek \
        --max_tokens "$max_tokens" --random_cwe --n "$n"
    else
      python test.py \
        --output_dir "$output_dir" \
        --dataset_path "$test_data" \
        --language "$language" \
        --model "$model" \
        --requests_per_minute "$requests_per_minute" \
        --save --use_cot --use_policy \
        --batch_size "$batch_size" \
        --max_tokens "$max_tokens" --random_cwe --n "$n"
    fi
  else
    python test.py \
      --output_dir "$output_dir" \
      --dataset_path "$test_data" \
      --language "$language" \
      --model "$model" \
      --requests_per_minute "$requests_per_minute" \
      --save --use_cot --use_policy \
      --batch_size "$batch_size" --tp "$tp" --vllm \
      --max_tokens "$max_tokens" --random_cwe --n "$n"
  fi
  # Wait before the next iteration
  echo "Waiting for GPU to release resources..."
  sleep 5
done
