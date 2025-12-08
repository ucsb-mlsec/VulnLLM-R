import os
import sys

import orjson
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv

from model_zoo import LiteLLMModel, VllmModel
from vulscan.data_process.generate_reasoning.parser import (
    ArgumentGroup,
    ArgumentParser,
    CommonArgumentGroup,
)
from vulscan.test.test_utils.generation_utils import (
    run_model,
    check_pred_cwe_correctness,
)
from vulscan.test.test_utils.utils import load_reasoning_data
from vulscan.utils.cwes import clean_ood_cwes, hard_ood_cwes
from vulscan.utils.project_info import PROJECT_PATH
from vulscan.utils.sys_prompts import (
    deepseek_sys_prompt,
    our_cot,
    policy,
    qwq_sys_prompt_generation,
)


class GenerateArgumentGroup(ArgumentGroup):
    def add_arguments(self, parser) -> None:
        parser.add_argument("--tp", type=int, default=2)
        parser.add_argument("--max_tokens", type=int, default=16384)
        parser.add_argument("--batch_size", type=int, default=200)
        parser.add_argument("--server_url", type=str, default=None)
        parser.add_argument("--together_deepseek", action="store_true", default=False)
        parser.add_argument("--n", type=int, default=1)
        parser.add_argument(
            "--requests_per_minute", type=int, default=60, help="requests per minute"
        )
        parser.add_argument(
            "--reasoning_effort",
            default=None,
            type=str,
            help="Reasoning effort for the model",
        )
        parser.add_argument(
            "--use_cwe_constraint",
            action="store_true",
            default=False,
            help="Whether to add a special prompt based on the CWE ID",
        )
        parser.add_argument(
            "--language",
            type=str,
            nargs="+",
            default=["c", "python", "java"],
            help="language of the dataset",
        )


def create_generate_parser():
    return ArgumentParser(CommonArgumentGroup(), GenerateArgumentGroup())


def generate_reasoning(
    model_name,
    dataset_type,
    input_dir,
    output_dir,
    server_url=None,
    training_set="train",
    tp=2,
    max_tokens=16384,
    batch_size=200,
    policy=policy,
    our_cot=our_cot,
    use_our_cot=False,
    n=1,
    file_name_prefix=None,
    use_cwe_constraint=False,
):
    short_model_name = model_name.split("/")[-1]
    file_name = (
        f"{short_model_name}_{training_set}.json"
        if file_name_prefix is None
        else f"{file_name_prefix}_{short_model_name}_{training_set}.json"
    )
    output_path = os.path.join(output_dir, dataset_type, file_name)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    acc_num = 0  # num of samples with correct predictions

    if os.path.exists(output_path):
        # Load existing reasoning data
        with open(output_path, "rb") as f:
            reasoning_data = orjson.loads(f.read())
        acc_num = reasoning_data[0]["acc_num"]
        reasoning_data = reasoning_data[1:]
        if len(reasoning_data) == 0:
            remaining_data, existing_data, data_num = load_reasoning_data(
                input_dir,
                output_path,
                cwe_dict,
                model_name,
                policy,
                our_cot,
                use_our_cot,
                random_cwe=True,  # this is needed for training and testing data
                use_cwe_constraint=use_cwe_constraint,
            )
        # filter out if model_answer is not None because we do not need to rerun these samples
        else:
            existing_data = [
                item for item in reasoning_data if item["model_reasoning"]
            ]  # data with model output
            existing_idx = set(item["idx"] for item in existing_data)
            remaining_data = [
                item for item in reasoning_data if item["idx"] not in existing_idx
            ]  # data without model output
            print(
                f"existing data: {len(existing_data)}, remaining data: {len(remaining_data)}"
            )
    else:
        remaining_data, existing_data, data_num = load_reasoning_data(
            input_dir,
            output_path,
            cwe_dict,
            model_name,
            policy,
            our_cot,
            use_our_cot,
            random_cwe=True,
            use_cwe_constraint=use_cwe_constraint,
        )
    # Run model to get model answer and reasoning
    system_prompt = None
    if "deepseek-reasoner" in model_name:
        system_prompt = deepseek_sys_prompt
    elif "QwQ" in model_name:
        system_prompt = qwq_sys_prompt_generation

    if file_name_prefix is not None:
        if "Tokenlimit" in file_name_prefix:
            system_prompt = (
                system_prompt
                + "\n\nImportant: Think for up to "
                + os.getenv("PROMPTTOKEN")
                + " tokens."
            )
        elif "Promptshort" in file_name_prefix:
            system_prompt = (
                system_prompt
                + "\n\nImportant: Answer after a short amount of thinking. Do not spend excessive time double-checking your work."
            )

    if (
        "gpt" in model_name
        or "o3" in model_name
        or "claude" in model_name
        or "deepseek-reasoner" in model_name
    ):
        limiter = AsyncLimiter(args.requests_per_minute, 60)
        model = LiteLLMModel(
            model=model_name,
            limiter=limiter,
            together_deepseek=args.together_deepseek,
            reasoning_effort=args.reasoning_effort,
        )
    elif server_url:
        limiter = AsyncLimiter(args.requests_per_minute, 60)
        model = LiteLLMModel(
            model=model_name, server_url=args.server_url, limiter=limiter
        )
    else:
        model = VllmModel(model=model_name, num_gpus=tp)
    existing_data_num = len(existing_data)
    for current_data_idx in range(0, len(remaining_data), batch_size):
        current_data = remaining_data[current_data_idx : current_data_idx + batch_size]
        (pred_score, true_score, pred_vul_type, true_vul_type, full_outputs, _, _) = (
            run_model(
                model,
                current_data,
                max_tokens,
                n=n,
                system_prompt=system_prompt,
                model_type="generate",
            )
        )
        assert len(full_outputs) == len(current_data)

        for i in range(len(current_data)):
            correctness = check_pred_cwe_correctness(
                pred_score[i], pred_vul_type[i], true_score[i], true_vul_type[i]
            )

            remaining_data[current_data_idx + i]["correct"] = correctness
            remaining_data[current_data_idx + i]["model_answer"] = pred_score[i]
            remaining_data[current_data_idx + i]["model_reasoning"] = full_outputs[i]
            remaining_data[current_data_idx + i]["model_vul_type"] = pred_vul_type[i]
            acc_num += correctness
        print(
            f"current acc: {acc_num / (existing_data_num + current_data_idx + len(current_data))}"
        )
        save_data = existing_data + remaining_data
        save_data.insert(0, {"acc_num": acc_num})
        with open(output_path, "wb") as f:
            f.write(orjson.dumps(save_data, option=orjson.OPT_INDENT_2, default=str))


if __name__ == "__main__":
    load_dotenv()
    bin_dir = os.path.dirname(sys.executable)
    os.environ["PATH"] = bin_dir + ":" + os.environ["PATH"]
    parser = create_generate_parser()
    args = parser.parse_args()
    # Additional validation
    if args.dataset_type == "noisy_dataset":
        cwe_dict = hard_ood_cwes
    elif args.dataset_type == "clean_dataset":
        cwe_dict = clean_ood_cwes
    elif args.dataset_type == "ossfuzz_dataset":
        cwe_dict = clean_ood_cwes
    elif args.dataset_type == "redteam_dataset":
        cwe_dict = {"c": [], "python": [], "java": []}
    else:
        raise ValueError(
            f"Invalid dataset type: {args.dataset_type}. Please support cwe_dict for this dataset type."
        )

    chosen_langs = [lang.lower() for lang in args.language]
    cwe_dict = {
        lang: cwes for lang, cwes in cwe_dict.items() if lang.lower() in chosen_langs
    }

    OUTPUT_DIR = os.path.join(PROJECT_PATH, "datasets/reasoning_data")
    INPUT_DIR = os.path.join(
        PROJECT_PATH, f"datasets/{args.dataset_type}/{args.training_set}"
    )

    generate_reasoning(
        model_name=args.model_name,
        input_dir=INPUT_DIR,
        output_dir=OUTPUT_DIR,
        server_url=args.server_url,
        training_set=args.training_set,
        tp=args.tp,
        max_tokens=args.max_tokens,
        batch_size=args.batch_size,
        dataset_type=args.dataset_type,
        n=args.n,
        file_name_prefix=args.file_name_prefix,
        use_cwe_constraint=args.use_cwe_constraint,
    )
