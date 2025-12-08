## Prerequisite

```shell
cd LLaMA-Factory
pip install -e .
cd ..
```

## Launch Training (New Version)

- dataset
    - Sky-T1-HF
    - VD-QWQ-Clean-8k
    - VD-QWQ-Clean-16k
    - VD-DS-Clean-8k
    - VD-QWQ-Noisy-Small-16k
    - VD-QWQ-Noisy-Small-8k

```shell
CUDA_VISIBLE_DEVICES=1,2 torchrun --nnodes 1 \
--node_rank 0 \
--nproc_per_node 2 \
--master_addr 127.0.0.1 \
--master_port 29501 \
train.py \
--model_name_or_path Qwen/Qwen2.5-7B-Instruct \
--run_name full_sft_1e-5 \
--dataset Sky-T1-HF \

--push_to_hub \
--push_to_hub_organization secmlr

CUDA_VISIBLE_DEVICES=0,1,2,3 torchrun --nnodes 1 \
--node_rank 0 \
--nproc_per_node 4 \
--master_addr 127.0.0.1 \
--master_port 29500 \
train.py \
--model_name_or_path Qwen/Qwen2.5-7B-Instruct \
--run_name full_sft_1e-5 \
--dataset VD-QWQ-Clean-8k \
--push_to_hub \
--push_to_hub_organization secmlr

# dataset: vulscan/train/data/dataset_info.json, refer to VD-QWQ-Clean-8k
```

model_name_or_path, run_name and dataset are required. Besides, if output_dir is not specified, the training loges will
be saved at `./result/{args.dataset}/{model_short_name}_{args.run_name}`.

A default set of training parameters, called DEFAULT_CONFIG_DICT, are provided. You can pass arguments in the
DEFAULT_CONFIG_DICT to overwrite them. You can also pass arguments that are not in DEFAULT_CONFIG_DICT but supported by
LLaMA-Factory.

```python
DEFAULT_CONFIG_DICT = {
    "use_unsloth_gc": True,
    "enable_liger_kernel": True,
    "stage": "sft",
    "do_train": True,
    "finetuning_type": "full",
    "deepspeed": "examples/deepspeed/ds_z3_config.json",
    "dataset": "Sky-T1-HF",
    "dataset_dir": "../data",
    "template": "qwen",
    "cutoff_len": 16384,
    "max_samples": 1000000,
    "overwrite_cache": True,
    "preprocessing_num_workers": 16,
    "logging_steps": 1,
    "save_steps": 200,
    "plot_loss": True,
    "per_device_train_batch_size": 1,
    "gradient_accumulation_steps": 12,
    "learning_rate": 1e-05,
    "num_train_epochs": 3.0,
    "lr_scheduler_type": "cosine",
    "warmup_ratio": 0.1,
    "bf16": True,
    "ddp_timeout": 180000000,
    "report_to": "wandb",
    "push_to_hub": False,
    "hub_strategy": "all_checkpoints",
}
```

for example, if you want to sft 32B model with deepspeed zero3 offload, you can use the following command:

```shell
CUDA_VISIBLE_DEVICES=3,4 torchrun --nnodes 1 \
--node_rank 0 \
--nproc_per_node 2 \
--master_addr 127.0.0.1 \
--master_port 29500 \
train.py \
--model_name_or_path Qwen/Qwen2.5-32B-Instruct \
--run_name full_sft_1e-5 \
--dataset VD-QWQ-Clean-8k \
--deepspeed examples/deepspeed/ds_z3_offload_config.json
```

You can still use the yaml files if you want (if is provided, all other arguments will be ignored). Here is an example:

```shell
CUDA_VISIBLE_DEVICES=3 python -m torch.distributed.run --nnodes 1 --node_rank 0 --nproc_per_node 1 --master_addr 127.0.0.1 --master_port 29501 train.py --config configs/qwen2_3B_full_sft.yaml
```

## gpu monitor

```shell
python ../test/gpu_monitor.py --interval 30 --gpu_num 4 --percentage 92 "torchrun --nnodes 1 --node_rank 0 --nproc_per_node 4 --master_addr 127.0.0.1 --master_port 29500 train.py --model_name_or_path Qwen/Qwen2.5-7B-Instruct --run_name qwen2_7B_full_sft_1e-5 --dataset VD-QWQ-Clean-8k --push_to_hub --push_to_hub_organization secmlr"

# dpo
python ../test/gpu_monitor.py --interval 30 --gpu_num 4 --percentage 92 "torchrun --nnodes 1 --node_rank 0 --nproc_per_node 4 --master_addr 127.0.0.1 --master_port 29500 train.py --model_name_or_path secmlr/VD-DS-Clean-8k_VD-QWQ-Clean-8k_Qwen2.5-7B-Instruct_full_sft_1e-5 --run_name full --stage dpo --pref_beta 2.0 --simpo_gamma 0.3 --pref_loss simpo --dataset VD-DS-QWQ-Clean-8k_qwen2_7B_full_sft_1e-5_train_dpo --push_to_hub --push_to_hub_organization secmlr --cutoff_len 32768"
```