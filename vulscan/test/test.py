import argparse
import glob
import json
import os
import re
import sys
from pathlib import Path

import orjson
import torch

from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
from model_zoo.huggingface_model import HuggingFaceModel
from model_zoo.litellm_model import LiteLLMModel
from model_zoo.openai_model import OpenAIModel
from model_zoo.vllm_model import VllmModel
from transformers import set_seed
from vllm import SamplingParams

from vulscan.test.test_utils.generation_utils import evaluate_examples
from vulscan.test.test_utils.utils import (
    save_results,
    load_reasoning_data,
    create_reasoning_test_sample,
)
from vulscan.utils.cwes import (
    remove_idx,
    function_level_ood_cwes,
    java_ood_cwes,
)
from vulscan.utils.project_info import PROJECT_PATH
from vulscan.utils.sys_prompts import (
    qwen_sys_prompt,
    deepseek_sys_prompt,
    our_cot,
    policy,
    sft_sys_prompt,
    default_sys_prompt,
    new_policy,
)


class MaxThinkLimiter:
    def __init__(
        self,
        yes_id: int,
        no_id: int,
        seperate_ids: list[int],
        threshold: float = 0.5,
    ):
        self.yes_id = yes_id
        self.no_id = no_id
        self.seperate_id = tuple(seperate_ids)
        self.num_seperate_ids = len(seperate_ids)
        self.threshold = threshold

    def __call__(self, token_ids: list[int], logits: torch.Tensor) -> torch.Tensor:
        """
        LogitsProcessor is a function that takes a list of previously generated
        tokens and a tensor of the logits for the next token, and returns a modified
        tensor of logits to sample from.

        token_ids only contains the generated tokens without the prompts

        """
        # if seperate ids match with the last tokens in token_ids
        if token_ids[-self.num_seperate_ids :] == self.seperate_id:
            # this is yes or no
            assert torch.argmax(logits).item() in (
                self.yes_id,
                self.no_id,
            ), " Logit id is not yes or no"
            our_logit = logits[[self.yes_id, self.no_id]]
            our_logit = our_logit / torch.sum(our_logit)
            # if our_logit[1] < our_logit[0] < 0.58:
            if self.threshold > 0.5:
                if our_logit[1] < our_logit[0] < self.threshold:
                    print("swith the answer")
                    # switch the answer
                    tmp = logits[self.yes_id].clone()
                    logits[self.yes_id] = logits[self.no_id]
                    logits[self.no_id] = tmp
            elif self.threshold < 0.5:
                if our_logit[0] < our_logit[1] < (1 - self.threshold):
                    print("swith the answer")
                    # switch the answer
                    tmp = logits[self.yes_id].clone()
                    logits[self.yes_id] = logits[self.no_id]
                    logits[self.no_id] = tmp
        return logits


def set_args():
    args = argparse.ArgumentParser()
    args.add_argument("--wandb", action="store_true")
    args.add_argument("--seed", type=int, default=42, help="seed")
    args.add_argument("--dataset_path", type=str, nargs="+", required=True)
    args.add_argument("--output_dir", type=str, required=True)
    args.add_argument("--ignore_large_functions", action="store_true", default=True)
    args.add_argument("--save", action="store_true")
    args.add_argument(
        "--requests_per_minute", type=int, default=60, help="requests per minute"
    )
    args.add_argument(
        "--test_samples_num", type=int, default=sys.maxsize, help="test samples num"
    )
    args.add_argument(
        "--max_tokens", type=int, default=16384, help="max tokens for each prompt"
    )
    args.add_argument("--n", type=int, default=1, help="n samples")
    args.add_argument(
        "--filter_long_sequence", type=int, default=16000, help="filter long sequence"
    )
    args.add_argument("--model", type=str, default="gpt-4o-2024-11-20")
    args.add_argument("--model_type", type=str, default=None)
    args.add_argument("--revision", type=str, default=None)
    args.add_argument("--use_policy", action="store_true", default=False)
    args.add_argument("--use_free_policy", action="store_true", default=False)
    args.add_argument("--use_cot", action="store_true", default=False)
    args.add_argument("--use_own_cot", action="store_true", default=False)
    args.add_argument("--random_cwe", action="store_true", default=False)
    args.add_argument("--server_url", type=str, default=None)
    args.add_argument("--api_key", type=str, default=None)
    args.add_argument("--quantization", action="store_true")
    args.add_argument("--tp", type=int, default=1, help="tensor parallel size")
    args.add_argument("--bit", type=int, default=4, help="quantization bit")
    args.add_argument("--batch_size", type=int, default=4, help="batch size")
    args.add_argument("--vllm", action="store_true", default=False)
    args.add_argument("--temperature", type=float, default=0.0)
    args.add_argument("--threshold", type=float, default=0.5)
    args.add_argument("--na_ratio", type=float, default=0.5)
    args.add_argument("--together_deepseek", action="store_true", default=False)
    args.add_argument("--language", type=str, required=True, nargs="+")
    args.add_argument("--ids", type=str, nargs="+")
    args.add_argument("--cwe", type=str, nargs="+", help="CWE filter")
    args.add_argument("--ood", action="store_true", default=False)
    args.add_argument("--logit_processor", action="store_true", default=False)
    args.add_argument("--addition_constraint", action="store_true", default=False)
    args.add_argument(
        "--use_cwe_constraint",
        action="store_true",
        default=False,
        help="Whether to add a special prompt based on the CWE ID",
    )
    args.add_argument(
        "--reasoning_effort",
        default=None,
        type=str,
        help="Reasoning effort for the model",
    )
    args.add_argument(
        "--multi_run_with_related_cwe",
        action="store_true",
        default=False,
        help="Run multi_run_n times without policy to collect predicted CWEs, then run once with collected CWEs as related CWEs. "
        "This helps improve accuracy by leveraging the model's predictions to enrich the CWE context. "
        "Usage: --multi_run_with_related_cwe [--use_policy]",
    )
    args.add_argument(
        "--multi_run_n",
        type=int,
        default=6,
    )
    args.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Show detailed analysis for incorrect predictions",
    )
    args = args.parse_args()
    if args.use_cot and args.use_own_cot:
        raise ValueError("Cannot use both cot and own_cot")
    if not args.quantization:
        args.dtype = torch.bfloat16
        args.bit = 16
    else:
        if args.bit == 4:
            args.dtype = torch.bfloat16
        elif args.bit == 8:
            args.dtype = torch.float16
            print("Using float16 for 8bit quantization")
        else:
            raise ValueError("bit must be 4 or 8")

    if args.quantization:
        from transformers import BitsAndBytesConfig

        if args.bit == 4:
            args.quanti_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=args.dtype,
            )
        else:  # args.bit == 8
            args.quanti_config = BitsAndBytesConfig(
                load_in_8bit=True,
                llm_int8_threshold=6.0,
            )
    else:
        args.quanti_config = None
    return args


if __name__ == "__main__":
    load_dotenv()
    args = set_args()
    os.makedirs(os.path.join(PROJECT_PATH, args.output_dir), exist_ok=True)
    # set current working directory
    os.chdir(PROJECT_PATH)
    args.dataset_path = [
        Path(dataset_path).resolve() for dataset_path in args.dataset_path
    ]
    # set seed by huggingface
    set_seed(args.seed)

    print("=" * 80)
    for k, v in vars(args).items():
        print(k, ": ", v)
    print("=" * 80)

    base_model = args.model

    system_prompt = None
    reduced = False
    model_type = "default"
    if "DeepSeek-R1-Distill-Qwen" in base_model or "DeepCoder" in base_model:
        system_prompt = qwen_sys_prompt
        # model_type = "ds" # this has some issues
    elif "Sky-T1" in base_model:
        system_prompt = sft_sys_prompt
    elif "secmlr" in base_model or os.path.exists(base_model):
        system_prompt = qwen_sys_prompt
        if "R-" in base_model:
            reduced = True
        model_type = "ds"
    elif "simplescaling" in base_model:
        system_prompt = (
            "You are Qwen, created by Alibaba Cloud. You are a helpful assistant."
        )
    elif "QwQ" in base_model or (args.use_cot and "Qwen" in base_model):
        system_prompt = qwen_sys_prompt
        model_type = "ds"
    elif "deepseek-reasoner" in base_model:
        system_prompt = deepseek_sys_prompt
    elif "google" in base_model:
        system_prompt = default_sys_prompt
    model_type = args.model_type if args.model_type else model_type

    if "claude" in base_model:
        args.max_tokens = 8192
        print("Setting max tokens to 8192 for claude")
        args.requests_per_minute = 60
        print("Setting requests per minute to 10 for claude")

    if (
        "gpt-4o" in base_model
        or "o3" in base_model
        or "claude" in base_model
        or "deepseek-reasoner" in base_model
    ):
        limiter = AsyncLimiter(args.requests_per_minute, 60)
        model = LiteLLMModel(
            model=base_model,
            limiter=limiter,
            temperature=args.temperature,
            together_deepseek=args.together_deepseek,
            reasoning_effort=args.reasoning_effort,
        )
    elif args.server_url:
        if "gpt-oss" in base_model:
            os.environ["OPENAI_API_KEY"] = os.environ["TOGETHER_API_KEY"]
        else:
            args.requests_per_minute = 10000
            print("Setting requests per minute to 10000 for custom model")
        limiter = AsyncLimiter(args.requests_per_minute, 60)
        model = OpenAIModel(
            model=base_model,
            server_url=args.server_url,
            limiter=limiter,
            temperature=args.temperature,
            api_key=args.api_key,
        )
    elif args.vllm:
        sampling_param = SamplingParams(
            max_tokens=args.max_tokens,
            temperature=args.temperature,
        )
        if "Qwen3" in base_model:
            sampling_param = SamplingParams(
                max_tokens=args.max_tokens,
                temperature=0.6,
                top_p=0.95,
                top_k=20,
                min_p=0,
            )
        if "Llama-3" in base_model:
            sampling_param = SamplingParams(
                max_tokens=args.max_tokens,
                temperature=args.temperature,

            )
        model = VllmModel(
            model=base_model,
            sampling_params=sampling_param,
            revision=args.revision,
            num_gpus=args.tp,
            seed=args.seed,
        )
        if args.logit_processor:
            tokenizer = model.model.get_tokenizer()
            yes_id = tokenizer.convert_tokens_to_ids("Ġyes")
            no_id = tokenizer.convert_tokens_to_ids("Ġno")
            seperate_ids = tokenizer.encode_plus("#judge:")["input_ids"]
            logits_processors = [
                MaxThinkLimiter(
                    yes_id=yes_id,
                    no_id=no_id,
                    seperate_ids=seperate_ids,
                    threshold=args.threshold,
                )
            ]
            sampling_params2 = SamplingParams(
                max_tokens=200,
                temperature=args.temperature,
                logits_processors=logits_processors,
            )
    else:
        model = HuggingFaceModel(
            model=base_model,
            device_map="auto",
            torch_dtype=args.dtype,
            quantization_config=args.quanti_config,
            quantization=args.quantization,
        )
    # wandb
    for dataset_path in args.dataset_path:
        for language in args.language:
            if not os.path.exists(os.path.join(dataset_path, language)):
                continue
            name = args.output_dir.split("/")[-1]
            # data
            output_path = "/dev/null"
            ood_dict = dict()
            if args.ood:
                if language == "java":
                    ood_dict[language] = java_ood_cwes[language]
                else:
                    if "repo_level" in dataset_path.as_posix():
                        print("We do not support OOD for repo-level datasets")
                        continue
                    elif "function_level" in dataset_path.as_posix():
                        ood_dict[language] = function_level_ood_cwes[language]
                    # elif "clean" in dataset_path.as_posix():
                    #     ood_dict[language] = clean_ood_cwes[language]
                    # elif "improved" in dataset_path.as_posix():
                    #     ood_dict[language] = hard_ood_cwes[language]
                    # elif "primevul_pair" in dataset_path.as_posix():
                    #     ood_dict[language] = primevul_ood_cwes[language]
                    # elif (
                    #     "patched" in dataset_path.as_posix()
                    #     or "long_context" in dataset_path.as_posix()
                    # ):
                    #     ood_dict[language] = []
                    else:
                        raise ValueError(
                            f"dataset path {dataset_path.as_posix()} is not supported for OOD"
                        )
            else:
                # this is needed for load_reasoning_data
                ood_dict[language] = []

            if args.wandb:
                import wandb
                name = f"{dataset_path}_eval_{name}"
                wandb.init(project="patch_llm", name=name, entity="rucnyz")

            eval_examples, _, _ = load_reasoning_data(
                dataset_path,
                output_path,
                ood_dict,
                args.model,
                policy if args.use_policy else "",
                our_cot,
                args.use_own_cot,
                skip_human=False,
                random_cwe=args.random_cwe,
                reduced=reduced,
                addition_constraint=args.addition_constraint,
                use_cwe_constraint=args.use_cwe_constraint,
                ood=args.ood,
            )

            eval_examples = eval_examples[: args.test_samples_num]
            if args.ids:
                eval_examples = [
                    item for item in eval_examples if str(item["idx"]) in args.ids
                ]
            if args.cwe:
                # cwe_set = set(args.cwe)
                eval_examples = [
                    item for item in eval_examples if item["cwe"][0] in args.cwe
                ]
            if "aixcc" not in dataset_path.as_posix():
                eval_examples = [
                    item for item in eval_examples if str(item["idx"]) not in remove_idx
                ]
            if eval_examples:
                if args.multi_run_with_related_cwe:
                    # Step 1: Run args.multi_run_n times without policy to collect predicted CWEs
                    print("=" * 80)
                    print("Starting multi-run with related CWE collection...")
                    print(
                        "Step 1: Running args.multi_run_n times without policy to collect predicted CWEs"
                    )
                    print("=" * 80)

                    collected_cwes = {}  # Dictionary to store collected CWEs for each example

                    # Save original policy setting
                    original_use_policy = args.use_policy
                    args.use_policy = False

                    # First, load examples without policy
                    eval_examples_no_policy, _, _ = load_reasoning_data(
                        dataset_path,
                        output_path,
                        ood_dict,
                        args.model,
                        "",  # No policy
                        our_cot,
                        args.use_own_cot,
                        skip_human=False,
                        random_cwe=args.random_cwe,
                        reduced=reduced,
                        addition_constraint=args.addition_constraint,
                        use_cwe_constraint=args.use_cwe_constraint,
                        ood=args.ood,
                    )

                    # Apply the same filters
                    eval_examples_no_policy = eval_examples_no_policy[
                        : args.test_samples_num
                    ]
                    if args.ids:
                        eval_examples_no_policy = [
                            item
                            for item in eval_examples_no_policy
                            if str(item["idx"]) in args.ids
                        ]
                    if args.cwe:
                        eval_examples_no_policy = [
                            item
                            for item in eval_examples_no_policy
                            if item["cwe"][0] in args.cwe
                        ]
                    if "aixcc" not in dataset_path.as_posix():
                        eval_examples_no_policy = [
                            item
                            for item in eval_examples_no_policy
                            if str(item["idx"]) not in remove_idx
                        ]

                    # Run n times to collect CWEs
                    all_predictions = {}  # Store all predictions for each example
                    for run_idx in range(args.multi_run_n):
                        print(
                            f"\nRun {run_idx + 1}/{args.multi_run_n} without policy..."
                        )
                        result, save_output = evaluate_examples(
                            model,
                            eval_examples_no_policy,
                            False,  # No wandb for intermediate runs
                            args.max_tokens,
                            system_prompt=system_prompt,
                            model_type=model_type,
                            n=args.n,
                            sampling_params2=sampling_params2
                            if args.logit_processor
                            else None,
                        )

                        # Collect predicted CWEs from this run
                        for i, output_item in enumerate(
                            save_output
                        ):  # Skip the result dict at index 0
                            idx = output_item["idx"]
                            pred_cwe = output_item["predicted_vulnerability_type"]
                            pred_score = output_item["predicted_is_vulnerable"]

                            if idx not in collected_cwes:
                                collected_cwes[idx] = set()

                            if idx not in all_predictions:
                                all_predictions[idx] = {
                                    "predictions": [],
                                    "true_cwes": output_item[
                                        "original_vulnerability_type"
                                    ],
                                    "is_vulnerable": output_item["is_vulnerable"],
                                }

                            all_predictions[idx]["predictions"].append(
                                {"pred_cwe": pred_cwe, "pred_score": pred_score}
                            )

                            # Extract CWE IDs from the prediction
                            if pred_cwe and pred_cwe != "N/A":
                                cwe_matches = re.findall(r"CWE-\d+", pred_cwe.upper())
                                for cwe in cwe_matches:
                                    collected_cwes[idx].add(cwe)

                    # Calculate accuracy for the first step
                    print("\n" + "=" * 80)
                    print(
                        f"First step accuracy analysis ({args.multi_run_n} runs combined):"
                    )

                    correct_vulnerable = 0
                    total_vulnerable = 0
                    correct_benign = 0
                    total_benign = 0

                    for idx, pred_data in all_predictions.items():
                        true_cwes = pred_data["true_cwes"]
                        is_vulnerable = pred_data["is_vulnerable"]
                        predictions = pred_data["predictions"]

                        if is_vulnerable == "yes":
                            total_vulnerable += 1
                            # Check if any of the args.multi_run_n predictions contains the true CWE
                            found_correct = False
                            for pred in predictions:
                                if (
                                    pred["pred_score"] == "yes"
                                    and pred["pred_cwe"] != "N/A"
                                ):
                                    # Check if predicted CWE matches any true CWE
                                    pred_cwe_matches = re.findall(
                                        r"CWE-\d+", pred["pred_cwe"].upper()
                                    )
                                    for pred_cwe in pred_cwe_matches:
                                        if pred_cwe in true_cwes:
                                            found_correct = True
                                            break
                                if found_correct:
                                    break

                            if found_correct:
                                correct_vulnerable += 1

                        else:  # benign sample
                            total_benign += 1
                            # Check if any of the args.multi_run_n predictions is "no" or has "N/A"
                            found_correct = False
                            for pred in predictions:
                                if (
                                    pred["pred_score"] == "no"
                                    or pred["pred_cwe"] == "N/A"
                                ):
                                    found_correct = True
                                    break

                            if found_correct:
                                correct_benign += 1

                    # Print Statistics
                    vulnerable_acc = (
                        correct_vulnerable / total_vulnerable
                        if total_vulnerable > 0
                        else 0
                    )
                    benign_acc = (
                        correct_benign / total_benign if total_benign > 0 else 0
                    )
                    overall_acc = (
                        (correct_vulnerable + correct_benign)
                        / (total_vulnerable + total_benign)
                        if (total_vulnerable + total_benign) > 0
                        else 0
                    )

                    print(
                        f"Vulnerable samples: {correct_vulnerable}/{total_vulnerable} correct ({vulnerable_acc:.2%})"
                    )
                    print(
                        f"Benign samples: {correct_benign}/{total_benign} correct ({benign_acc:.2%})"
                    )
                    print(
                        f"Overall accuracy: {correct_vulnerable + correct_benign}/{total_vulnerable + total_benign} ({overall_acc:.2%})"
                    )

                    # Print detailed analysis for incorrect predictions
                    if args.verbose:
                        print("\n" + "-" * 40)
                        print("Incorrect predictions in first step:")
                        for idx, pred_data in all_predictions.items():
                            true_cwes = pred_data["true_cwes"]
                            is_vulnerable = pred_data["is_vulnerable"]
                            predictions = pred_data["predictions"]

                            is_correct = False
                            if is_vulnerable == "yes":
                                # Check if any prediction contains true CWE
                                for pred in predictions:
                                    if (
                                        pred["pred_score"] == "yes"
                                        and pred["pred_cwe"] != "N/A"
                                    ):
                                        pred_cwe_matches = re.findall(
                                            r"CWE-\d+", pred["pred_cwe"].upper()
                                        )
                                        for pred_cwe in pred_cwe_matches:
                                            if pred_cwe in true_cwes:
                                                is_correct = True
                                                break
                                    if is_correct:
                                        break
                            else:
                                # Check if any prediction is "no" or "N/A"
                                for pred in predictions:
                                    if (
                                        pred["pred_score"] == "no"
                                        or pred["pred_cwe"] == "N/A"
                                    ):
                                        is_correct = True
                                        break

                            if not is_correct:
                                print(f"\nExample {idx}:")
                                print(f"  True: {is_vulnerable}, CWE: {true_cwes}")
                                pred_list = [
                                    f"{p['pred_score']}:{p['pred_cwe']}"
                                    for p in predictions
                                ]
                                print(f"  Predictions: {pred_list}")

                    # Print statistics about collected CWEs
                    print("\n" + "=" * 80)
                    print("Collected CWEs summary:")
                    total_examples_with_cwes = sum(
                        1 for cwes in collected_cwes.values() if cwes
                    )
                    total_unique_cwes = len(
                        set(cwe for cwes in collected_cwes.values() for cwe in cwes)
                    )
                    print(
                        f"Total examples with predicted CWEs: {total_examples_with_cwes}/{len(eval_examples_no_policy)}"
                    )
                    print(f"Total unique CWEs collected: {total_unique_cwes}")

                    print("\n" + "=" * 80)
                    print("Step 2: Processing samples based on first step results")
                    print("=" * 80)

                    # Restore original policy setting
                    args.use_policy = original_use_policy

                    # Prepare lists for different handling
                    examples_to_evaluate = []
                    early_terminated_results = []

                    # Check each example individually
                    for example in eval_examples_no_policy:
                        idx = example["idx"]

                        # Check if this example has majority N/A predictions
                        if idx in all_predictions:
                            predictions = all_predictions[idx]["predictions"]
                            na_count_for_sample = sum(
                                1
                                for pred in predictions
                                if pred["pred_score"] == "no"
                                or pred["pred_cwe"] == "N/A"
                            )

                            if (
                                na_count_for_sample / len(predictions)
                            ) >= args.na_ratio:
                                # Early terminate this sample - predict as "no" with N/A
                                print(
                                    f"Example {idx}: {na_count_for_sample}/{len(predictions)} are N/A/no - early terminating as 'no'"
                                )

                                # Create a result for this sample
                                true_score = (
                                    example["output"]
                                    .split("#judge: ")[1]
                                    .split()[0]
                                    .strip()
                                )
                                true_cwe = (
                                    example["output"]
                                    .split("#type: ")[1]
                                    .split()[0]
                                    .strip()
                                )

                                early_terminated_results.append(
                                    {
                                        "input": example["input"],
                                        "output": "#judge: no\n#type: N/A",
                                        "is_vulnerable": true_score,
                                        "predicted_is_vulnerable": "no",
                                        "vulnerability_type": true_cwe,
                                        "original_vulnerability_type": example["cwe"],
                                        "predicted_vulnerability_type": "N/A",
                                        "flag": "tn" if true_score == "no" else "fn",
                                        "is_wrong": False
                                        if true_score == "no"
                                        else True,
                                        "idx": example["idx"],
                                        "dataset": example["dataset"],
                                        "latency": 0,
                                        "completion_tokens": 0,
                                    }
                                )
                                continue

                        # Add collected CWEs if available
                        if idx in collected_cwes:
                            # Add collected CWEs as related CWEs

                            related_cwes = list(collected_cwes[idx])

                            if related_cwes:
                                # Find the original data for this example
                                original_data = None
                                for json_file in glob.glob(
                                    os.path.join(dataset_path, language, "CWE-*.json")
                                ):
                                    with open(json_file, "r", encoding="utf-8") as f:
                                        data = json.load(f)
                                    for item in data:
                                        if item["idx"] == idx:
                                            original_data = item
                                            break
                                    if original_data:
                                        break

                                if original_data:
                                    if "RELATED_CWE" not in original_data:
                                        original_data["RELATED_CWE"] = []
                                    original_data["RELATED_CWE"] = related_cwes

                                    # Regenerate the input prompt
                                    input_prompt, chosen_output = (
                                        create_reasoning_test_sample(
                                            original_data,
                                            args.model,
                                            # policy if args.use_policy else "",
                                            new_policy if args.use_policy else "",
                                            our_cot,
                                            args.use_own_cot,
                                            use_related_cwe=True,
                                            random_cwe=args.random_cwe,
                                            reduced=reduced,
                                            addition_constraint=args.addition_constraint,
                                            use_cwe_constraint=args.use_cwe_constraint,
                                            use_original_cwe=False,
                                        )
                                    )

                                    # Update the example
                                    example["input"] = input_prompt
                                    example["output"] = chosen_output
                        # This example needs evaluation
                        examples_to_evaluate.append(example)
                    print(
                        f"\nEarly terminated samples: {len(early_terminated_results)}"
                    )
                    print(f"Samples to evaluate: {len(examples_to_evaluate)}")

                    if examples_to_evaluate:
                        print("\nRunning final evaluation on remaining samples...")
                        result, save_output = evaluate_examples(
                            model,
                            examples_to_evaluate,
                            False,  # Don't use wandb for partial evaluation
                            args.max_tokens,
                            system_prompt=system_prompt,
                            model_type=model_type,
                            n=args.n,
                            sampling_params2=sampling_params2
                            if args.logit_processor
                            else None,
                        )

                        # Combine results
                        save_output.extend(early_terminated_results)

                        # Recalculate statistics for all samples
                        tp, fp, fn, tn = 0, 0, 0, 0
                        wrong_num = 0

                        for item in save_output:
                            if item["flag"] == "tp":
                                tp += 1
                            elif item["flag"] == "fp":
                                fp += 1
                            elif item["flag"] == "fn":
                                fn += 1
                            elif item["flag"] == "tn":
                                tn += 1
                            else:
                                wrong_num += 1

                        from vulscan.test.test_utils.utils import calculate_score

                        result = calculate_score(
                            tp, fp, fn, tn, len(eval_examples), args.wandb, wrong_num
                        )
                        print("\nFinal combined results:")
                        print(orjson.dumps(result, option=orjson.OPT_INDENT_2).decode())
                        print("wrong: {}".format(result["wrong_num"]))
                        print("fpr: {:.3f}".format(result["false_positive_rate"]))
                        print("fnr: {:.3f}".format(result["false_negative_rate"]))
                        print("Vul F1: {:.3f}".format(result["positive F1"]))
                        print("Benign F1: {:.3f}".format(result["negative F1"]))
                        print("Overall F1: {:.3f}".format(result["overall F1"]))
                    else:
                        # All samples were early terminated
                        save_output = early_terminated_results

                        # Calculate statistics
                        tp, fp = 0, 0
                        wrong_num = 0
                        fn = sum(1 for item in save_output if item["flag"] == "fn")
                        tn = sum(1 for item in save_output if item["flag"] == "tn")

                        from vulscan.test.test_utils.utils import calculate_score

                        result = calculate_score(
                            tp, fp, fn, tn, len(eval_examples), args.wandb, wrong_num
                        )
                        print("\nAll samples early terminated:")
                        print(orjson.dumps(result, option=orjson.OPT_INDENT_2).decode())
                else:
                    # Normal evaluation without multi-run
                    result, save_output = evaluate_examples(
                        model,
                        eval_examples,
                        args.wandb,
                        args.max_tokens,
                        system_prompt=system_prompt,
                        model_type=model_type,
                        n=args.n,
                        sampling_params2=sampling_params2
                        if args.logit_processor
                        else None,
                    )
                print(
                    f"Testing done on {dataset_path}, language {language}, using {min(args.test_samples_num, len(eval_examples))} samples"
                )
                save_output.insert(
                    0,
                    result,
                )
                # save the output
                if args.save:
                    os.makedirs(args.output_dir, exist_ok=True)
                    rel_path = str(dataset_path.relative_to(PROJECT_PATH))
                    dataset_name = rel_path.replace("/", "_")
                    model_name_parts = args.model.split("/")
                    if len(model_name_parts) > 2:
                        # shortname = last two parts of the model path
                        model_shortname = (
                            model_name_parts[-2] + "_" + model_name_parts[-1]
                        )
                    else:
                        model_shortname = model_name_parts[-1]
                    if args.reasoning_effort:
                        model_shortname += f"_{args.reasoning_effort}"
                    if args.use_cot:
                        cot = "cot"
                    elif args.use_own_cot:
                        cot = "own_cot"
                    else:
                        cot = "no_cot"

                    # Add multi_run identifier if applicable
                    multi_run_suffix = (
                        "__multi_run" if args.multi_run_with_related_cwe else ""
                    )

                    save_results(
                        os.path.join(
                            args.output_dir,
                            f"{args.max_tokens}__{args.n}__{dataset_name}__{'ood' if args.ood else 'full'}__{cot}__{language}__{'policy' if args.use_policy else 'no_policy'}__{model_shortname}{multi_run_suffix}.json",
                        ),
                        save_output,
                        args.wandb,
                    )
                    print(f"Results saved to {args.output_dir}")
