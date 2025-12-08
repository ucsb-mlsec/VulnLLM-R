import os

import orjson
from aiolimiter import AsyncLimiter
from datasets import Dataset
from dotenv import load_dotenv

from model_zoo import LiteLLMModel, VllmModel
from vulscan.data_process.generate_reasoning.generate import create_generate_parser
from vulscan.test.test_utils.generation_utils import (
    check_pred_cwe_correctness,
    extract_answer,
)
from vulscan.test.test_utils.utils import load_reasoning_data
from vulscan.utils.cwes import noisy_ood_cwes, clean_ood_cwes
from vulscan.utils.project_info import PROJECT_PATH
from vulscan.utils.sys_prompts import (
    deepseek_sys_prompt,
    our_cot,
    policy,
    qwq_sys_prompt_generation,
    sft_sys_prompt,
)


def run_model_dpo(
    model,
    eval_examples,
    max_tokens,
    n=1,
    system_prompt=None,
):
    outputs, answers, _, _ = model.run(
        eval_examples=eval_examples,
        system_prompt=system_prompt,
        max_tokens=max_tokens,
        n=n,
        temperature=0 if n == 1 else 0.6,
        top_p=0.9,
    )
    pred_scores_shortest, pred_scores_longest = [], []
    true_scores = []
    pred_vul_types_shortest, pred_vul_types_longest = [], []
    true_vul_types = []
    shortest_outputs, longest_outputs = [], []
    false_positive_outputs = []

    for output, answer in zip(outputs, answers):
        true_score = answer.split("#judge: ")[1].split()[0].strip()
        true_vul_type = answer.split("#type: ")[1].split()[0].strip()

        min_correct_length = float("inf")
        min_length = float("inf")
        max_length = float("-inf")
        max_length_fp = float("-inf")

        candidate_shortest_correct = None
        candidate_shortest = None
        candidate_longest = None
        candidate_false_positive = None

        best_pred_score_shortest = None
        best_pred_vul_shortest = None
        best_pred_score_longest = None
        best_pred_vul_longest = None

        # check correctness and find the shortest and longest outputs
        for i in range(len(output)):
            pred_score, pred_vul = extract_answer(output[i])
            current_length = len(output[i])

            # update the shortest correct output
            if check_pred_cwe_correctness(
                pred_score, pred_vul, true_score, true_vul_type
            ):
                if current_length < min_correct_length:
                    min_correct_length = current_length
                    candidate_shortest_correct = output[i]
                    best_pred_score_shortest = pred_score
                    best_pred_vul_shortest = pred_vul

            # update the shortest output
            if current_length < min_length:
                min_length = current_length
                candidate_shortest = output[i]
                if (
                    best_pred_score_shortest is None
                ):  # only update if the shortest correct output is not found
                    best_pred_score_shortest = pred_score
                    best_pred_vul_shortest = pred_vul

            # update the longest output
            if current_length > max_length:
                max_length = current_length
                candidate_longest = output[i]
                best_pred_score_longest = pred_score
                best_pred_vul_longest = pred_vul
            # update the false positive output
            if (current_length > max_length_fp) and not check_pred_cwe_correctness(
                pred_score, pred_vul, true_score, true_vul_type
            ):
                max_length_fp = current_length
                candidate_false_positive = output[i]
        # choose the final outputs
        final_shortest = (
            candidate_shortest_correct
            if candidate_shortest_correct is not None
            else candidate_shortest
        )

        # if the shortest correct output is not found, which is not expected
        if final_shortest is None:
            final_shortest = candidate_shortest
            if best_pred_score_shortest is None:
                pred_score, pred_vul = extract_answer(candidate_shortest)
                best_pred_score_shortest = pred_score
                best_pred_vul_shortest = pred_vul

        shortest_outputs.append(final_shortest)
        longest_outputs.append(candidate_longest)
        false_positive_outputs.append(candidate_false_positive)
        pred_scores_shortest.append(best_pred_score_shortest)
        true_scores.append(true_score)
        pred_vul_types_shortest.append(best_pred_vul_shortest)
        true_vul_types.append(true_vul_type)
        pred_scores_longest.append(best_pred_score_longest)
        pred_vul_types_longest.append(best_pred_vul_longest)

    return (
        pred_scores_shortest,
        pred_vul_types_shortest,
        shortest_outputs,
        pred_scores_longest,
        pred_vul_types_longest,
        longest_outputs,
        false_positive_outputs,
        true_scores,
        true_vul_types,
    )


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
                random_cwe=True,  # this is needed for training data
            )
        # filter out if model_answer is not None because we do not need to rerun these samples
        else:
            existing_data = [
                item for item in reasoning_data if "conversations" in item.keys()
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
        )

    # Run model to get model answer and reasoning
    system_prompt = None
    if "secmlr" in model_name:
        system_prompt = sft_sys_prompt
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
        (
            pred_score_shortest,
            pred_vul_type_shortest,
            full_outputs_shortest,
            pred_score_longest,
            pred_vul_type_longest,
            full_outputs_longest,
            false_positive_outputs,
            true_score,
            true_vul_type,
        ) = run_model_dpo(
            model,
            current_data,
            max_tokens,
            n=n,
            system_prompt=system_prompt,
        )
        assert (
            len(full_outputs_shortest) == len(current_data) == len(full_outputs_longest)
        )

        for i in range(len(current_data)):
            short_correctness = check_pred_cwe_correctness(
                pred_score_shortest[i],
                pred_vul_type_shortest[i],
                true_score[i],
                true_vul_type[i],
            )
            long_correctness = check_pred_cwe_correctness(
                pred_score_longest[i],
                pred_vul_type_longest[i],
                true_score[i],
                true_vul_type[i],
            )
            remaining_data[current_data_idx + i]["short_correct"] = short_correctness
            remaining_data[current_data_idx + i]["long_correct"] = (
                long_correctness if false_positive_outputs[i] is None else False
            )
            remaining_data[current_data_idx + i]["conversations"] = [
                {
                    "from": "system",
                    "value": system_prompt,
                },
                {"from": "human", "value": remaining_data[current_data_idx + i]["input"]},
            ]
            remaining_data[current_data_idx + i]["chosen"] = {
                "from": "gpt",
                "value": full_outputs_shortest[i],
            }
            remaining_data[current_data_idx + i]["rejected"] = {
                "from": "gpt",
                "value": false_positive_outputs[i]
                if false_positive_outputs[i] is not None
                else full_outputs_longest[i],
            }
            # check if the chosen and rejected outputs are different
            assert (
                remaining_data[current_data_idx + i]["chosen"]["value"]
                != remaining_data[current_data_idx + i]["rejected"]["value"]
            ), "chosen and rejected outputs should be different"

            remaining_data[current_data_idx + i]["pred_score_shortest"] = (
                pred_score_shortest[i]
            )
            remaining_data[current_data_idx + i]["pred_score_longest"] = (
                pred_score_longest[i]
            )
            remaining_data[current_data_idx + i]["pred_vul_type_shortest"] = (
                pred_vul_type_shortest[i]
            )
            remaining_data[current_data_idx + i]["pred_vul_type_longest"] = (
                pred_vul_type_longest[i]
            )
            remaining_data[current_data_idx + i]["true_score"] = true_score[i]
            remaining_data[current_data_idx + i]["true_vul_type"] = true_vul_type[i]
            remaining_data[current_data_idx + i]["idx"] = current_data[i]["idx"]

            acc_num += short_correctness
        print(
            f"current acc: {acc_num / (existing_data_num + current_data_idx + len(current_data))}"
        )
        save_data = existing_data + remaining_data
        save_data.insert(0, {"acc_num": acc_num})
        with open(output_path, "wb") as f:
            f.write(orjson.dumps(save_data, option=orjson.OPT_INDENT_2, default=str))

    if args.push_to_hub:
        # remove wrong data
        total_data = existing_data + remaining_data
        filter_data = [
            item for item in total_data if item["short_correct"]
        ]
        dataset = Dataset.from_list(filter_data)
        dataset = dataset.remove_columns(
            ["model_answer", "model_vul_type", "model_reasoning", "input"]
        )
        if args.push_to_hub_organization:
            dataset.push_to_hub(
                f"{args.push_to_hub_organization}/{file_name.replace('.json', '')}_dpo"
            )
        else:
            dataset.push_to_hub(f"{file_name.replace('.json', '')}_dpo")


if __name__ == "__main__":
    load_dotenv()
    parser = create_generate_parser()
    parser.add_argument("--push_to_hub", action="store_true", help="Push to hub")
    parser.add_argument(
        "--push_to_hub_organization", type=str, help="Push to hub organization"
    )
    args = parser.parse_args()
    # Additional validation
    if args.dataset_type == "noisy_dataset":
        cwe_dict = noisy_ood_cwes
    elif args.dataset_type == "clean_dataset":
        cwe_dict = clean_ood_cwes
    else:
        raise ValueError(
            f"Invalid dataset type: {args.dataset_type}. Please support cwe_dict for this dataset type."
        )

    OUTPUT_DIR = os.path.join(PROJECT_PATH, "datasets/dpo_data")
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
    )
