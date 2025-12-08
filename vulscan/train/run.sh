#!/usr/bin/env bash

## 7B+DS
#python ../test/gpu_monitor.py --interval 30 --gpu_num 2 --percentage 92 "torchrun --nnodes 1 --node_rank 0 --nproc_per_node 2 --master_addr 127.0.0.1 --master_port 29500 train.py --model_name_or_path Qwen/Qwen2.5-7B-Instruct --run_name qwen2_7B_full_sft_1e-5 --dataset VD-DS-Clean-8k --push_to_hub --push_to_hub_organization secmlr"
#
## DS7B+QWQ
#python ../test/gpu_monitor.py --interval 30 --gpu_num 2 --percentage 92 "torchrun --nnodes 1 --node_rank 0 --nproc_per_node 2 --master_addr 127.0.0.1 --master_port 29500 train.py --model_name_or_path deepseek-ai/DeepSeek-R1-Distill-Qwen-7B --run_name DeepSeek-R1-Distill-Qwen-7B_full_sft_1e-5 --dataset VD-QWQ-Clean-8k --push_to_hub --push_to_hub_organization secmlr"
#
## 7B+QWQ+Sky
#python ../test/gpu_monitor.py --interval 30 --gpu_num 2 --percentage 92 "torchrun --nnodes 1 --node_rank 0 --nproc_per_node 2 --master_addr 127.0.0.1 --master_port 29500 train.py --config configs/vd_qwq_sky_qwen2_full_sft.yaml --model_name_or_path Qwen/Qwen2.5-7B-Instruct --run_name qwen2_7B_full_sft_1e-5 --dataset Sky-T1-Filtered,VD-QWQ-Clean-8k"

# DS7B+QWQ+Sky
python ../test/gpu_monitor.py --interval 30 --gpu_num 4 --percentage 92 "torchrun --nnodes 1 --node_rank 0 --nproc_per_node 4 --master_addr 127.0.0.1 --master_port 29500 train.py --config configs/vd_qwq_sky_qwen2_full_sft.yaml --model_name_or_path deepseek-ai/DeepSeek-R1-Distill-Qwen-7B --run_name DeepSeek-R1-Distill-Qwen-7B_full_sft_1e-5 --dataset Sky-T1-Filtered,VD-QWQ-Clean-8k"

# 7B+QWQ+DS
python ../test/gpu_monitor.py --interval 30 --gpu_num 4 --percentage 92 "torchrun --nnodes 1 --node_rank 0 --nproc_per_node 4 --master_addr 127.0.0.1 --master_port 29500 train.py --config configs/vd_qwq_sky_qwen2_full_sft.yaml --model_name_or_path Qwen/Qwen2.5-7B-Instruct --run_name qwen2_7B_full_sft_1e-5 --dataset Sky-T1-Filtered,VD-DS-Clean-8k"