import json


import argparse
import yaml
import os
from loguru import logger
from pathlib import Path

DEFAULT_CONFIG_DICT = {
    "use_unsloth_gc": True,
    "enable_liger_kernel": True,
    "stage": "sft",
    "do_train": True,
    "finetuning_type": "full",
    "deepspeed": "examples/deepspeed/ds_z3_offload_config.json",
    "dataset": "Sky-T1-HF",
    "dataset_dir": "../data",
    "template": "qwen",
    "cutoff_len": 32768,
    "max_samples": 15000,
    "overwrite_cache": True,
    "preprocessing_num_workers": 16,
    "logging_steps": 1,
    "save_steps": 400,
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
    "hub_strategy": "every_save",
}


def launch(args_dict: dict):
    from llamafactory.train.tuner import run_exp

    run_exp(args_dict)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=str,
        help="Path to the config file, if is provided, all other arguments will be ignored",
    )
    parser.add_argument("--model_name_or_path", type=str, help="Model name or path")
    parser.add_argument("--run_name", type=str, help="Run name")
    parser.add_argument("--output_dir", type=str, help="Output directory")
    parser.add_argument("--dataset", type=str, help="Dataset name")
    parser.add_argument("--hub_strategy", type=str, help="strategy for push to hub")
    parser.add_argument("--push_to_hub", action="store_true", help="Push to hub")
    parser.add_argument(
        "--push_to_hub_organization", type=str, help="Push to hub organization"
    )
    parser.add_argument("--push_to_hub_model_id", type=str, help="Push to hub model id")
    parser.add_argument("--dataset_full_name", type=str, help="Dataset name")

    args, unknown_args = parser.parse_known_args()
    if args.config:
        if (
            not os.path.exists(args.config)
            or not os.path.isfile(args.config)
            or not args.config.endswith(".yaml")
        ):
            raise ValueError(f"Invalid config file: {args.config}")
        with open(args.config) as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
        # overwrite config with command line arguments
        delattr(args, "config")
        config.update({k: v for k, v in vars(args).items() if v or k not in config})
        args = argparse.Namespace(**config)
        dataset_name = args.dataset.replace(",", "_")
        model_short_name = args.model_name_or_path.split("/")[-1]
        if not getattr(args, "output_dir"):
            args.output_dir = (
                f"./result/{dataset_name}/{model_short_name}_{args.run_name}"
            )
        if args.push_to_hub and not args.push_to_hub_model_id:
            args.push_to_hub_model_id = (
                f"{dataset_name}_{model_short_name}_{args.run_name}"
            )
    else:
        config = DEFAULT_CONFIG_DICT
        required_args = ["model_name_or_path", "run_name", "dataset"]
        for arg in required_args:
            if not getattr(args, arg):
                raise ValueError(f"Argument {arg} is required")
        dataset_name = args.dataset.replace(",", "_")
        model_short_name = args.model_name_or_path.split("/")[-1]
        if not getattr(args, "output_dir"):
            args.output_dir = (
                f"./result/{dataset_name}/{model_short_name}_{args.run_name}"
            )
        if args.push_to_hub and not args.push_to_hub_model_id:
            if "dpo" in dataset_name:
                args.push_to_hub_model_id = f"dpo_{model_short_name}_{args.run_name}"
            else:
                args.push_to_hub_model_id = (
                    f"{dataset_name}_{model_short_name}_{args.run_name}"
                )
        for key, value in vars(args).items():
            if value is not None:
                config[key] = value

        extra_config = {}
        for i in range(0, len(unknown_args), 2):
            key = unknown_args[i].lstrip("--")
            value = unknown_args[i + 1] if i + 1 < len(unknown_args) else True
            if key in config:
                # use the type of the default value
                extra_config[key] = type(config[key])(value)
            else:
                try:
                    value = int(value)
                except ValueError:
                    try:
                        value = float(value)
                    except ValueError:
                        pass
                extra_config[key] = value
        config.update(extra_config)
        args = argparse.Namespace(**config)

    # Detect template based on model name
    if hasattr(args, 'model_name_or_path') and args.model_name_or_path:
        model_name = args.model_name_or_path
        if 'Llama-3' in model_name:
            args.template = 'llama3'
            logger.info("Detected Meta-Llama model, setting template to 'llama3'")
        elif 'qwen' in model_name.lower():
            args.template = 'qwen'
            logger.info("Detected Qwen model, setting template to 'qwen'")
        elif 'gpt' in model_name.lower():
            args.template = 'gpt'
            logger.info("Detected GPT model, setting template to 'gpt'")

    args.output_dir = Path(args.output_dir).resolve()
    args_dict = vars(args)
    logger.info(f"Arguments: {args_dict}")
    os.chdir("LLaMA-Factory")

    # if dataset is not in dataset_info, add it
    dataset_list = args.dataset.split(",")
    try:
        dataset_full_name_list = args.dataset_full_name.split(",")
        delattr(args, "dataset_full_name")

    except AttributeError:
        dataset_full_name_list = []
    dataset_info_path = Path(args.dataset_dir).resolve() / "dataset_info.json"
    if not dataset_info_path.exists():
        raise FileNotFoundError(f"{dataset_info_path} does not exist")

    with open(dataset_info_path, "r") as f:
        dataset_info = json.load(f)
    flag = False
    for i, dataset in enumerate(dataset_list):
        if dataset not in dataset_info:
            flag = True
            if not dataset_full_name_list:
                raise ValueError(
                    f"dataset {dataset} is not found in data/dataset_info.json, you need to provide dataset_name as huggingface url or file name"
                )
            if len(dataset_full_name_list) != len(dataset_list):
                raise ValueError(
                    f"As dataset is not found in data/dataset_info.json, dataset_name should be provided for all datasets, dataset_name should be the same length as dataset, got {len(dataset_list)} dataset and {len(dataset_full_name_list)} dataset_name"
                )
            dataset_info[dataset] = {
                "hf_hub_url": dataset_full_name_list[i],
                "formatting": "sharegpt",
                "columns": {"messages": "conversations", "system": "system"},
                "tags": {
                    "role_tag": "from",
                    "content_tag": "value",
                    "user_tag": "user",
                    "assistant_tag": "assistant",
                },
            }
    if flag:
        with open(dataset_info_path, "w") as f:
            json.dump(dataset_info, f, indent=4)

    launch(args_dict)
