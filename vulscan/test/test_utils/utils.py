import argparse
import glob
import json
import os
import random

import orjson
import torch


from vulscan.utils.get_cwe_info import get_cwe_info
from vulscan.utils.sys_prompts import (
    reasoning_user_prompt,
    our_cot,
    policy,
    reduced_reasoning_user_prompt,
    addition_constition,
    addition_constition_cwe,
    long_context_reasoning_user_prompt,
)


def save_results(file_path, examples, use_wandb=False):
    # save json
    with open(file_path, "wb") as f:
        f.write(orjson.dumps(examples, option=orjson.OPT_INDENT_2, default=str))
    if use_wandb:
        import wandb
        wandb.save(file_path)


def calculate_score(tp, fp, fn, tn, test_samples_num, use_wandb, wrong_num=0):
    if tp + fp == 0:
        Precision = 0
    else:
        Precision = tp / (tp + fp)
    if tp + fn == 0:
        Recall = 0
    else:
        Recall = tp / (tp + fn)
    if Precision + Recall == 0:
        pos_F1 = 0
    else:
        pos_F1 = 2 * (Precision * Recall) / (Precision + Recall)
    if tn + fn == 0:
        neg_Precision = 0
    else:
        neg_Precision = tn / (tn + fn)
    if tn + fp == 0:
        neg_Recall = 0
        fpr = 0
    else:
        neg_Recall = tn / (tn + fp)
        fpr = fp / (fp + tn)
    if neg_Precision + neg_Recall == 0:
        neg_F1 = 0
    else:
        neg_F1 = 2 * (neg_Precision * neg_Recall) / (neg_Precision + neg_Recall)

    if fn + tp == 0:
        fnr = 0
    else:
        fnr = fn / (fn + tp)
    total_pos = tp + fn
    total_neg = tn + fp
    if total_pos + total_neg == 0:
        overall_F1 = 0
    else:
        overall_F1 = (pos_F1 + neg_F1) / 2

    result = {
        "wrong_num": wrong_num,
        "total_samples": test_samples_num,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "accuracy": (tp + tn) / test_samples_num if test_samples_num > 0 else 0,
        "pos_Precision": Precision,
        "pos_Recall": Recall,
        "positive F1": pos_F1,
        "negative F1": neg_F1,
        "overall F1": overall_F1,
    }

    # upload these results to wandb
    if use_wandb:
        import wandb
        wandb.log(
            {
                "test/false_positive_rate": fpr,
                "test/accuracy": (tp + tn) / test_samples_num,
                "test/false_negative_rate": fnr,
                "test/total_samples": test_samples_num,
                "test/overall_F1": overall_F1,
            }
        )

    return result


def set_args():
    args = argparse.ArgumentParser()
    args.add_argument("--wandb", action="store_true")
    args.add_argument("--nr", action="store_true")
    args.add_argument("--peft_path", type=str, default=None)
    args.add_argument("--seed", type=int, default=42, help="seed")
    args.add_argument("--dataset", type=str, default="human")
    args.add_argument("--output_dir", type=str, default="test_sven")
    args.add_argument("--ignore_large_functions", action="store_true", default=True)
    args.add_argument("--save", action="store_true")
    args.add_argument(
        "--requests_per_minute", type=int, default=60, help="requests per minute"
    )
    args.add_argument(
        "--test_samples_num", type=int, default=2, help="test samples num"
    )
    args.add_argument(
        "--max_tokens", type=int, default=16384, help="max tokens for each prompt"
    )
    args.add_argument("--model", type=str, default="gpt-4o-2024-11-20")
    args.add_argument("--server_url", type=str, default=None)
    args.add_argument("--api_key", type=str, default=None)
    args.add_argument("--language", type=str, default="python")
    args.add_argument(
        "--filter_long_sequence", type=int, default=16000, help="filter long sequence"
    )
    args.add_argument("--vllm", action="store_true")
    args.add_argument("--ood", action="store_true")
    args.add_argument("--quantization", action="store_true")
    args.add_argument("--from_ppo", action="store_true")
    args.add_argument("--tp", type=int, default=1, help="tensor parallel size")
    args.add_argument("--bit", type=int, default=4, help="quantization bit")
    args.add_argument("--batch_size", type=int, default=4, help="batch size")
    args = args.parse_args()
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


def load_reasoning_data(
    input_dir,
    output_path,
    ood_cwe_dict,
    model_name,
    policy,
    our_cot,
    use_our_cot,
    skip_human=True,
    random_cwe=False,
    reduced=False,
    addition_constraint=False,
    use_cwe_constraint=False,
    ood=False,
):
    reasoning_data = []
    data_num = 0
    input_dir_orig = input_dir
    for language in ood_cwe_dict.keys():
        input_dir = os.path.join(input_dir_orig, language)
        cwe_count = 0
        for json_file in glob.glob(os.path.join(input_dir, "CWE-*.json")):
            print(f"processing: {json_file}")
            current_cwe = json_file.split("/")[-1].split(".")[0]
            if ood and current_cwe not in ood_cwe_dict[language]:
                continue
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # select data that is "dataset": "primevul_pair"; only for c
                if "noisy_dataset" in input_dir:
                    data = [item for item in data if item["dataset"] == "primevul_pair"]
                # selected_samples = select_diverse_samples(data)

                # filter out testing data
                if skip_human:
                    selected_samples = [
                        item for item in data if not item.get("human", None)
                    ]
                else:
                    selected_samples = data
                for i in range(len(selected_samples)):
                    cve_data = selected_samples[i]
                    input_prompt, chosen_output = create_reasoning_test_sample(
                        cve_data,
                        model_name,
                        policy,
                        our_cot,
                        use_our_cot,
                        random_cwe=random_cwe,
                        reduced=reduced,
                        addition_constraint=addition_constraint,
                        use_cwe_constraint=use_cwe_constraint,
                    )
                    reasoning_data.append(
                        {
                            "idx": cve_data["idx"],
                            "input": input_prompt,
                            "output": chosen_output,
                            "model_answer": None,
                            "model_vul_type": None,
                            "model_reasoning": None,
                            "cwe": cve_data["CWE_ID"],
                            "correct": False,
                            "language": language,
                            "dataset": cve_data["dataset"],
                            "code": cve_data["code"],
                        }
                    )
                    data_num += 1
                cwe_count += 1
            except Exception as e:
                print(f"process {json_file} wrong: {str(e)}")
        print(f"Total CWEs: {cwe_count}")
    reasoning_data.insert(0, {"acc_num": 0})
    with open(output_path, "wb") as f:
        f.write(orjson.dumps(reasoning_data, option=orjson.OPT_INDENT_2, default=str))
    remaining_data = reasoning_data[1:]
    existing_data = []
    return remaining_data, existing_data, data_num


def create_reasoning_test_sample(
    data,
    model_name,
    policy=policy,
    cot=our_cot,
    use_our_cot=False,
    use_related_cwe=True,
    random_cwe=False,
    reduced=False,
    addition_constraint=False,
    use_cwe_constraint=False,
    use_original_cwe=True,
):
    # Create the input prompt and output for each model
    score = "yes" if data["target"] else "no"

    if use_related_cwe and "RELATED_CWE" in data.keys():
        if use_original_cwe:
            cwe_lists = data["CWE_ID"] + data["RELATED_CWE"]
        else:
            cwe_lists = data["RELATED_CWE"]
        if random_cwe:
            cwe_lists = random.sample(cwe_lists, len(cwe_lists))
    else:
        cwe_lists = data["CWE_ID"]
        print("ALART: No related CWEs are provided")
    # random.shuffle(cwe_lists)
    if policy:
        for cwe_id in cwe_lists:
            cwe_number = int(cwe_id.split("-")[-1])
            desc = get_cwe_info(cwe_number)
            if "Unknown CWE" not in desc:
                policy += f"\n- {cwe_id}: {get_cwe_info(cwe_number)}"
            # assert "Unknown CWE" not in policy, f"Unknown CWE: {cwe_id} is detected"

    # TODO: not sure if we want to add the following instruction
    # reasoning = "Please reasoning about whether the code belongs to one of the given CWE why not other given CWEs"

    if "QwQ" or "deepseek" in model_name:
        reasoning = "You should STRICTLY structure your response as follows:"
    else:
        reasoning = "Please think step by step, and output the steps, finally you should STRICTLY structure your response as follows:"

    if use_our_cot:
        reasoning = cot + reasoning
    if reduced:
        input_prompt = reduced_reasoning_user_prompt.format(
            CODE=data["code"], CWE_INFO=policy, REASONING=reasoning
        )
    else:
        if addition_constraint and data["idx"] in addition_constition:
            addition = addition_constition[data["idx"]]
        elif use_cwe_constraint and data["CWE_ID"][0] in addition_constition_cwe:
            addition = addition_constition_cwe[data["CWE_ID"][0]]
        else:
            addition = ""
        if "stack_trace" in data:
            input_prompt = long_context_reasoning_user_prompt.format(
                CODE=data["code"],
                CWE_INFO=policy,
                REASONING=reasoning,
                ADDITIONAL_CONSTRAINT=addition,
            )
        else:
            input_prompt = reasoning_user_prompt.format(
                CODE=data["code"],
                CWE_INFO=policy,
                REASONING=reasoning,
                ADDITIONAL_CONSTRAINT=addition,
            )
    chosen_type = ",".join(data["CWE_ID"]) if data["target"] else "N/A"
    output = "#judge: " + score + "\n#type: " + chosen_type

    return input_prompt, output
