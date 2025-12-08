#!/bin/bash

# Define models
models=(
  # official models
#    "agentica-org/DeepCoder-14B-Preview"
#    "google/gemma-3-4b-it"
#    "google/gemma-3-12b-it"
#    "Qwen/Qwen2.5-1.5B-Instruct"
#    "Qwen/Qwen2.5-Coder-1.5B-Instruct"
#    "Qwen/Qwen2.5-Coder-7B-Instruct"
#    "Qwen/Qwen2.5-7B-Instruct"
#    "Qwen/Qwen2.5-32B-Instruct"
#    "Qwen/QwQ-32B-Preview"
#    "Qwen/QwQ-32B"
#    "simplescaling/s1.1-32B"
#    "NovaSky-AI/Sky-T1-32B-Preview"
#    "NovaSky-AI/Sky-T1-32B-Flash"
#    "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"
#    "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B"
    "together-deepseek-reasoner"
#    "gpt-4o"
#    "o3-mini"
#    "claude-3-7-sonnet-20250219"
  #   our models
  #  "secmlr/VD-DS-Clean-16k_Qwen2.5-7B-Instruct_full_sft_1e-5"
  #  "secmlr/VD-DS-Clean-8k_VD-QWQ-Clean-8k_Qwen2.5-7B-Instruct_full_sft_1e-5"
  #  "secmlr/VD-DS-Clean-16k_VD-QWQ-Clean-16k_Qwen2.5-7B-Instruct_full_sft_1e-5"
  #  "secmlr/Sky-T1-Filtered_VD-DS-Clean-16k_VD-QWQ-Clean-16k_Qwen2.5-7B-Instruct_full_sft_1e-5"
  #  "secmlr/dpo_VD-DS-Clean-8k_VD-QWQ-Clean-8k_Qwen2.5-7B-Instruct_full_sft_1e-5_full"
  #  "secmlr/dpo_VD-DS-Clean-8k_VD-QWQ-Clean-8k_Qwen2.5-7B-Instruct_full_sft_1e-5_full_normal"
  #  "secmlr/Sky-Simpo_VD-DS-Clean-8k_VD-QWQ-Clean-8k_Qwen2.5-7B-Instruct_full_sft_1e-5_full_normal"
  #  "secmlr/VD-DS-Clean-8k_VD-DS-Clean-16k_Qwen2.5-7B-Instruct_full_sft_1e-5"
  #  "secmlr/ruizhe_simplier_reasoning_DS-QwQ-Qwen2.5-7B-Instruct_full_sft_full_sft_simplier_reasoning_dsr1"
  #  "secmlr/ruizhe_simplier_VD-QWQ-Clean-8k_VD-QWQ-Clean-16k_Qwen2.5-7B-Instruct_full_sft_1e-5_QwQ8k16k"
  #  "secmlr/rz_simplier_reasoning_VD-DS-Clean-8k_VD-DS-Clean-16k_Qwen2.5-7B-Instruct_full_sft_1e-5_sft"
  #  "secmlr/VD-DS-Clean-8k_VD-QWQ-Clean-8k_VD-QWQ-Noisy-Small-16k_Qwen2.5-7B-Instruct_full_sft_1e-5"
  #  "secmlr/VD-DS-Clean-8k_VD-QWQ-Clean-8k_VD-QWQ-Noisy-Small-8k_Qwen2.5-7B-Instruct_full_sft_1e-5"
  #  "secmlr/jrz_summarized_QwQcln8k_QwQNoisySm8k_dscln8k-DSCln8k_QWQCln8k_QWQNoisySm8k_Qwen-7B_Instruct_sft"
  #  "secmlr/ruizhe_summarized_QwQcln8k_QwQNoisySm8k_VD-DSCln8k_QWQCln8k_QWQNoisySm8k_Qwen2.5-7B_Instruct_sft"
  #  "secmlr/VD-DS-Clean-8k_VD-QWQ-Clean-8k_VD-QWQ-Noisy-Small-8k_Qwen2.5-7B-Instruct_2_full_sft_1e-5"
  #  "secmlr/R-VD-DS-Clean-8k_R-VD-QWQ-Clean-8k_R-VD-QWQ-Noisy-Small-8k_Qwen2.5-7B-Instruct_full_sft_1e-5"
  #  "secmlr/QWQ-OSS-D_QWQ-Clean-D_QWQ-Noisy-D_Qwen2.5-7B-Instruct_full_sft_1e-5"
  #  "secmlr/DS-Clean_QWQ-Clean_Qwen2.5-7B-Instruct_full_sft_1e-5"
#    "deepseek/deepseek-reasoner"
    "secmlr/final_model_nopolicy"
#    "secmlr/QWQ-JAVA_DS-JAVA_final_model_sft"
#    "secmlr/DS-Noisy_DS-Clean_DS-OSS_QWQ-OSS_QWQ-Clean_QWQ-Noisy_Qwen2.5-7B-Instruct_full_sft_1e-5"
#    "secmlr/ruizhe_simplier_dsNoisy32kCln32k_DSCln_QWQCln_Qwen2.5-7B_summarized_sft"
#    "secmlr/ruizhe_simplier_dsNsy32kCln32k_QwQNsy32kCln32k_DSCln_QWQCln_Qwen7B_summarized_sft"
#    "secmlr/ruizhe_simplier_dsNsy32kCln32k_QwQNsy32kCln32k_DSNsyCln_QWQNsyCln_Qwen7B_summarized_sft"
#    "secmlr/ruizhe_simplier_dsNoisy32kCln32k_DSNoisyCln_QWQNoisyCln_Qwen2.5-7B_summarized_sft"
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
# Define parameters
output_dir="results/test_data"
requests_per_minute=1000
batch_size=4
# tp from args, defaults to 4
tp="${1:-4}"
gpu_percentage=92
max_tokens=8192
n=1
test_data="./datasets/test/function_level/ ./datasets/test/repo_level/"
language="c python java"
#test_data="./datasets/test/test_clean ./datasets/test/test_improved ./datasets/test/test_long_context ./datasets/test/test_patched"
#test_data="./datasets/test/test_long_context"
# Change to the target directory

cd "$(pwd | grep -q '/vulscan/test$' && echo '.' || echo './vulscan/test')" || exit
realpath_value=$(realpath ../../)
export PYTHONPATH=$PYTHONPATH:$realpath_value

# Iterate over models
for model in "${models[@]}"; do
  # Iterate over OOD option
  #    for ood_option in "" "--ood"; do
  #    for ood_option in "--ood"; do
  for ood_option in ""; do
    # Models containing "7B" use both --use_cot and --use_own_cot
    echo "Running model: $model using --use_cot $ood_option"

    if [[ "$model" == *"Qwen/Qwen2.5-7B-Instruct"* ]]; then
      for cot_option in "--use_cot" "--use_own_cot"; do
        echo "Running model: $model using $cot_option $ood_option"
        python gpu_monitor.py --interval 30 --gpu_num $tp --percentage $gpu_percentage \
          "python test.py \
          --output_dir $output_dir \
          --dataset_path $test_data \
          --language $language \
          --model $model \
          --requests_per_minute $requests_per_minute \
          --save $cot_option --use_policy $ood_option \
          --batch_size $batch_size --tp $tp --vllm \
          --max_tokens $max_tokens --random_cwe --n $n"

        # Wait before the next iteration
        echo "Waiting for GPU to release resources..."
        sleep 10
      done
    else
      if is_commercial_model "$model"; then
        # Run without GPU monitoring for commercial models
        if [[ "$model" == *deepseek-reasoner* ]]; then
          python test.py \
            --output_dir $output_dir \
            --dataset_path $test_data \
            --language $language \
            --model $model \
            --requests_per_minute $requests_per_minute \
            --save --use_cot --use_policy $ood_option \
            --batch_size $batch_size --together_deepseek \
            --max_tokens $max_tokens --random_cwe --n $n
        else
          python test.py \
            --output_dir $output_dir \
            --dataset_path $test_data \
            --language $language \
            --model $model \
            --requests_per_minute $requests_per_minute \
            --save --use_cot --use_policy $ood_option \
            --batch_size $batch_size \
            --max_tokens $max_tokens --random_cwe --n $n
        fi
      else
        python gpu_monitor.py --interval 30 --gpu_num $tp --percentage $gpu_percentage \
          "python test.py \
          --output_dir $output_dir \
          --dataset_path $test_data \
          --language $language \
          --model $model \
          --requests_per_minute $requests_per_minute \
          --save --use_cot --use_policy $ood_option \
          --batch_size $batch_size --tp $tp --vllm \
          --max_tokens $max_tokens --random_cwe --n $n"
      fi
      # Wait before the next iteration
      echo "Waiting for GPU to release resources..."
      sleep 10
    fi
  done
done

cd ../../ || exit
# Redirect output to both the terminal and a log file
#python ./results/convert.py --json_dir $output_dir | tee "${1:-convert_output.log}"
