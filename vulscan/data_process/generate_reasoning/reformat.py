import os

import orjson
from datasets import load_dataset

from vulscan.data_process.generate_reasoning.parser import (
    ArgumentGroup,
    ArgumentParser,
    CommonArgumentGroup,
    ProcessingArgumentGroup,
)
from vulscan.utils.sys_prompts import sft_sys_prompt
from vulscan.utils.project_info import PROJECT_PATH


class ReformatArgumentGroup(ArgumentGroup):
    def add_arguments(self, parser) -> None:
        parser.add_argument("--push_to_hub", action="store_true")
        parser.add_argument("--push_to_hub_organization", type=str, default=None)


def create_reformat_parser():
    return ArgumentParser(
        CommonArgumentGroup(), ProcessingArgumentGroup(), ReformatArgumentGroup()
    )


if __name__ == "__main__":
    parser = create_reformat_parser()
    args = parser.parse_args()

    os.chdir(PROJECT_PATH)

    short_model_name = args.model_name.split("/")[-1]
    file_name = f"{short_model_name}_{args.training_set}_len_{args.filter_all_length}_inputlen_{args.filter_input_length}.json"
    if args.file_name_prefix is not None:
        file_name = args.file_name_prefix + "_" + file_name

    input_json = os.path.join(args.input_dir, args.dataset_type, "filtered", file_name)
    output_json = os.path.join(
        args.input_dir, args.dataset_type, "formatted", file_name
    )
    os.makedirs(os.path.dirname(output_json), exist_ok=True)

    with open(input_json, "rb") as f:
        distil_data = orjson.loads(f.read())
    # change the output
    new_data = []
    for item in distil_data:
        assert item["model_reasoning"] is not None, "error"
        output = item["output"]
        reasoning = item["model_reasoning"]
        splits = reasoning.rsplit("## Final Answer", maxsplit=1)
        if len(splits) != 2:
            print(f"reasoning: {reasoning}")
            raise ValueError("reasoning error")
        if "judge:" not in splits[1].lower() or "type:" not in splits[1].lower():
            print(f"reasoning: {reasoning}")
            raise ValueError("reasoning error")
        reasoning = splits[0].strip()
        model_anwer = splits[1].strip()
        final_output = (
            "<|begin_of_thought|>\n\n" + reasoning + "\n<|end_of_thought|>\n\n"
        )
        final_output += (
            "<|begin_of_solution|>\n\n## Final Answer\n"
            + model_anwer
            + "\n<|end_of_solution|>"
        )
        new_data.append(
            {
                "conversations": [
                    {
                        "from": "user",
                        "value": item["input"],
                    },
                    {
                        "from": "assistant",
                        "value": final_output,
                    },
                ],
                "system": sft_sys_prompt,
                "idx": item["idx"],
                "cwe": item["cwe"],
                "ground_truth": item["output"],
            }
        )
    print(f"data num: {len(new_data)}")

    # Load test set indices to filter from
    test_set_path = os.path.join(PROJECT_PATH, "datasets", "test", "test_clean", "c")
    test_set_indices = set()
    for test_file in os.listdir(test_set_path):
        if test_file.endswith(".json"):
            with open(os.path.join(test_set_path, test_file), "rb") as f:
                test_data = orjson.loads(f.read())
                test_set_indices.update(item["idx"] for item in test_data)

    # Filter out items belonging to the test set
    filtered_data = [item for item in new_data if item["idx"] not in test_set_indices]
    print(f"Filtered data num (excluding test set): {len(filtered_data)}")
    with open(output_json, "wb") as f:
        f.write(orjson.dumps(filtered_data, option=orjson.OPT_INDENT_2))
    # upload to huggingface dataset
    if args.push_to_hub:
        dataset = load_dataset("json", data_files=output_json)
        if args.push_to_hub_organization:
            dataset.push_to_hub(
                f"{args.push_to_hub_organization}/{args.dataset_type}_filtered_{file_name.replace('.json', '')}"
            )
        else:
            dataset.push_to_hub(
                f"{args.dataset_type}_filtered_{file_name.replace('.json', '')}"
            )
