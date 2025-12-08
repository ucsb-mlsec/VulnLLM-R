import argparse
import subprocess
import os
import time
import json

from vulscan.utils.project_info import PROJECT_PATH
from vulscan.train.get_gpu_env import cal_gpu_num


def run_training(
    model_name_or_path,
    dataset,
    dataset_full_name,
    run_name,
    nproc_per_node,
    push_to_hub=True,
    push_to_hub_organization="secmlr",
    push_to_hub_model_id=None,
    master_addr="127.0.0.1",
    master_port="29540",
):
    """Run the training script using subprocess."""
    print(f"\n=== Starting training phase for model: {model_name_or_path} ===")

    # Construct training command
    gpu_str = cal_gpu_num(check_interval=30, gpu_num=nproc_per_node, percentage=92)
    os.environ["CUDA_VISIBLE_DEVICES"] = gpu_str
    train_cmd = [
        "torchrun",
        "--nnodes",
        "1",
        "--node_rank",
        "0",
        "--nproc_per_node",
        str(nproc_per_node),
        "--master_addr",
        master_addr,
        "--master_port",
        master_port,
        "train.py",
        "--model_name_or_path",
        model_name_or_path,
        "--run_name",
        run_name,
        "--dataset",
        dataset,
    ]
    if dataset_full_name:
        train_cmd.extend(["--dataset_full_name", dataset_full_name])
    # Add optional arguments
    if push_to_hub:
        train_cmd.extend(["--push_to_hub"])

    if push_to_hub_organization:
        train_cmd.extend(["--push_to_hub_organization", push_to_hub_organization])

    if push_to_hub_model_id:
        train_cmd.extend(["--push_to_hub_model_id", push_to_hub_model_id])

    # Execute training command
    print(f"Executing training command: {' '.join(train_cmd)}")
    try:
        os.chdir(os.path.join(PROJECT_PATH, "vulscan/train"))
        subprocess.run(train_cmd, check=True, text=True, stderr=subprocess.STDOUT)
        print(f"Training for model {model_name_or_path} completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Training process for model {model_name_or_path} failed with error: {e}")
        return False


def run_testing(
    model_name,
    dataset,
    run_name,
    nproc_per_node,
    languages=None,
    requests_per_minute=100,
    batch_size=4,
    tp=2,
    vllm=True,
    max_tokens=8192,
    use_cot=True,
    use_policy=True,
    random_cwe=True,
):
    """Run the testing script using subprocess."""
    if languages is None:
        languages = ["python","c",  "java"]
    print(f"\n=== Starting testing phase for run: {run_name} ===")
    gpu_str = cal_gpu_num(check_interval=30, gpu_num=nproc_per_node, percentage=90)
    os.environ["CUDA_VISIBLE_DEVICES"] = gpu_str
    # Determine model path based on training parameters
    dataset_name = dataset.replace(",", "_")
    model_short_name = model_name.split("/")[-1]
    # hub_model_name = f"secmlr/{dataset_name}_{run_name}"
    file_name = f"./vulscan/train/result/{dataset_name}/{model_short_name}_{run_name}"

    # Additional test datasets
    test_datasets = [
        "./datasets/test/function_level",
        "./datasets/test/repo_level",
    ]

    # Construct testing command
    test_cmd = [
        "python",
        "-m",
        "vulscan.test.test",
        "--output_dir",
        "results/new_data",
        "--dataset_path",
    ]

    # Add dataset paths
    test_cmd.extend(test_datasets)

    # Add language parameters
    test_cmd.append("--language")
    test_cmd.extend(languages)

    # Add model path
    test_cmd.extend(["--model", file_name])

    # Add other parameters
    test_cmd.extend(["--requests_per_minute", str(requests_per_minute)])
    test_cmd.extend(["--batch_size", str(batch_size)])
    test_cmd.extend(["--tp", str(tp)])
    test_cmd.extend(["--max_tokens", str(max_tokens)])

    # Add optional flags
    if use_cot:
        test_cmd.append("--use_cot")
    if use_policy:
        test_cmd.append("--use_policy")
    if vllm:
        test_cmd.append("--vllm")
    if random_cwe:
        test_cmd.append("--random_cwe")

    test_cmd.append("--save")

    # Execute testing command
    print(f"Executing testing command: {' '.join(test_cmd)}")
    try:
        os.chdir(PROJECT_PATH)
        subprocess.run(test_cmd, check=True, text=True, stderr=subprocess.STDOUT)
        print(f"Testing for run {run_name} completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Testing process for run {run_name} failed with error: {e}")
        return False


def process_model_configuration(model_config, args):
    """Process a single model configuration through training and testing."""
    model_name = model_config.get("model_name_or_path")
    dataset = model_config.get("dataset", args.dataset)
    run_name = model_config.get("run_name", args.run_name)
    nproc_per_node = model_config.get("nproc_per_node", args.nproc_per_node)
    dataset_full_name = model_config.get("dataset_full_name", args.dataset_full_name)
    push_to_hub_model_id = model_config.get("push_to_hub_model_id", args.push_to_hub_model_id)

    print(f"\n\n{'='*80}")
    print(f"PROCESSING MODEL: {model_name}")
    print(
        f"Dataset: {dataset}, Run name: {run_name}, Processes per node: {nproc_per_node}"
    )
    print(f"{'='*80}\n")

    # Run the training phase
    if model_config.get("train_enabled", True) is False:
        print(f"Skipping training for model {model_name} (disabled)")
        training_success = True
    else:
        training_success = run_training(
            model_name_or_path=model_name,
            dataset=dataset,
            dataset_full_name=dataset_full_name,
            run_name=run_name,
            nproc_per_node=nproc_per_node,
            push_to_hub=not args.no_push_to_hub,
            push_to_hub_organization=args.push_to_hub_organization,
            push_to_hub_model_id=push_to_hub_model_id,
            master_addr=args.master_addr,
            master_port=args.master_port,
        )
        # Wait a bit for the model to be available (especially if pushed to hub)
        print(f"Waiting {args.wait_time} seconds before starting testing...")
        time.sleep(args.wait_time)

    if training_success:
        # Run the testing phase
        if model_config.get("test_enabled", True) is False:
            print(f"Skipping testing for model {model_name} (disabled)")
            testing_success = True
        else:
            testing_success = run_testing(
                model_name=model_name,
                dataset=dataset,
                run_name=run_name,
                nproc_per_node=nproc_per_node,
                languages=args.languages,
                requests_per_minute=args.requests_per_minute,
                batch_size=args.batch_size,
                tp=args.tp,
                vllm=not args.no_vllm,
                max_tokens=args.max_tokens,
                use_cot=not args.no_cot,
                use_policy=not args.no_policy,
                random_cwe=not args.no_random_cwe,
            )

        if testing_success:
            print(f"Complete pipeline executed successfully for model: {model_name}!")
            return True
        else:
            print(f"Testing phase failed for model: {model_name}")
            return False
    else:
        print(f"Training phase failed for model: {model_name}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Run training and testing pipeline for multiple models"
    )

    # Model configuration options
    parser.add_argument(
        "--models_config",
        type=str,
        help="Path to JSON file containing model configurations",
    )
    parser.add_argument(
        "--model_list", type=str, nargs="+", help="List of model names to process"
    )

    # Required arguments (can be overridden in JSON config)
    parser.add_argument(
        "--model_name_or_path",
        type=str,
        help="Path to pre-trained model (if not using config file)",
    )
    parser.add_argument("--dataset", type=str, help="Dataset name for training")
    parser.add_argument(
        "--dataset_full_name", type=str, help="Dataset name for training"
    )
    parser.add_argument("--run_name", type=str, help="Base name for this training run")
    parser.add_argument(
        "--nproc_per_node", type=int, default=4, help="Number of processes per node"
    )

    # Optional training arguments
    parser.add_argument(
        "--master_addr",
        type=str,
        default="127.0.0.1",
        help="Master address for distributed training",
    )
    parser.add_argument(
        "--master_port",
        type=str,
        default="29540",
        help="Master port for distributed training",
    )
    parser.add_argument(
        "--no_push_to_hub", action="store_true", help="Disable push to hub"
    )
    parser.add_argument(
        "--push_to_hub_organization",
        type=str,
        default="secmlr",
        help="Organization name for push to hub",
    )
    parser.add_argument(
        "--push_to_hub_model_id",
        type=str,
        default=None,
        help="Custom model ID for push to hub",
    )

    # Optional testing arguments
    parser.add_argument(
        "--languages",
        nargs="+",
        default=["c", "python"],
        help="Programming languages to test",
    )
    parser.add_argument(
        "--requests_per_minute", type=int, default=100, help="API requests per minute"
    )
    parser.add_argument(
        "--batch_size", type=int, default=4, help="Batch size for testing"
    )
    parser.add_argument(
        "--tp", type=int, default=2, help="Tensor parallelism for testing"
    )
    parser.add_argument(
        "--max_tokens", type=int, default=8192, help="Maximum tokens for generation"
    )
    parser.add_argument(
        "--no_vllm", action="store_true", help="Disable VLLM for testing"
    )
    parser.add_argument(
        "--no_cot", action="store_true", help="Disable chain-of-thought"
    )
    parser.add_argument("--no_policy", action="store_true", help="Disable policy")
    parser.add_argument(
        "--no_random_cwe", action="store_true", help="Disable random CWE"
    )
    parser.add_argument(
        "--wait_time",
        type=int,
        default=10,
        help="Wait time in seconds between training and testing",
    )
    parser.add_argument(
        "--continue_on_failure",
        action="store_true",
        help="Continue processing models even if one fails",
    )

    args = parser.parse_args()

    # Determine which models to process
    models_to_process = []

    # Option 1: JSON config file
    if args.models_config:
        if not os.path.exists(args.models_config):
            print(f"Error: Model configuration file {args.models_config} not found.")
            return

        try:
            with open(args.models_config, "r") as f:
                config_data = json.load(f)

            if isinstance(config_data, list):
                models_to_process = config_data
            elif isinstance(config_data, dict) and "models" in config_data:
                models_to_process = config_data["models"]
            else:
                print(
                    "Error: Invalid JSON format. Expected a list or a dict with 'models' key."
                )
                return

        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in configuration file {args.models_config}.")
            return

    # Option 2: Command line model list
    elif args.model_list:
        for model_name in args.model_list:
            # Create a configuration for each model
            models_to_process.append(
                {
                    "model_name_or_path": model_name,
                    "run_name": f"{args.run_name}_{model_name.split('/')[-1]}",
                    "dataset": args.dataset,
                    "nproc_per_node": args.nproc_per_node,
                    "dataset_full_name": args.dataset_full_name,
                }
            )

    # Option 3: Single model from command line arguments
    elif args.model_name_or_path:
        models_to_process.append(
            {
                "model_name_or_path": args.model_name_or_path,
                "run_name": args.run_name,
                "dataset": args.dataset,
                "nproc_per_node": args.nproc_per_node,
                "dataset_full_name": args.dataset_full_name,
            }
        )

    else:
        print(
            "Error: You must specify either --models_config, --model_list, or --model_name_or_path"
        )
        return

    # Process all model configurations
    total_models = len(models_to_process)
    successful_models = 0
    failed_models = []

    print(f"\nStarting pipeline for {total_models} model configurations")

    for i, model_config in enumerate(models_to_process):
        print(f"\nProcessing model {i+1}/{total_models}")

        if "model_name_or_path" not in model_config:
            print(f"Error: Missing model_name_or_path in configuration at index {i}")
            failed_models.append(f"Configuration at index {i} (missing model name)")
            if not args.continue_on_failure:
                print(
                    "Stopping due to configuration error. Use --continue_on_failure to proceed anyway."
                )
                break
            continue
        if model_config.get("enabled", True) is False:
            print(f"Skipping model {model_config['model_name_or_path']} (disabled)")
            continue
        success = process_model_configuration(model_config, args)

        if success:
            successful_models += 1
        else:
            failed_models.append(model_config["model_name_or_path"])
            if not args.continue_on_failure:
                print(
                    "Stopping due to failure. Use --continue_on_failure to proceed with remaining models."
                )
                break

    # Print summary
    print("\n" + "=" * 80)
    print(
        f"PIPELINE SUMMARY: {successful_models}/{total_models} models processed successfully"
    )

    if failed_models:
        print("\nFailed models:")
        for model in failed_models:
            print(f" - {model}")

    print("=" * 80)


if __name__ == "__main__":
    main()
