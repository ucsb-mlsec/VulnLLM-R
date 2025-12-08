import argparse
import os
import orjson
from tqdm import tqdm
from transformers import AutoTokenizer
from concurrent.futures import ProcessPoolExecutor
from vulscan.data_process.generate_reasoning.parser import (
    ArgumentGroup,
    ArgumentParser,
    CommonArgumentGroup,
    ProcessingArgumentGroup,
)
from vulscan.utils.project_info import PROJECT_PATH


class FilterArgumentGroup(ArgumentGroup):
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--num_processes",
            type=int,
            default=16,
            help="number of processes for parallel processing",
        )
        parser.add_argument("--filter_correct_only", action="store_true")


def create_filter_parser():
    return ArgumentParser(
        CommonArgumentGroup(), ProcessingArgumentGroup(), FilterArgumentGroup()
    )


def process_chunk(chunk_data, filter_all_length, filter_input_length):
    tokenizer = AutoTokenizer.from_pretrained("Qwen/QwQ-32B-Preview")
    processed_items = []
    errors = []

    for item in tqdm(chunk_data):
        if "**Final Answer**" in item["model_reasoning"]:
            item["model_reasoning"] = item["model_reasoning"].replace(
                "**Final Answer**", "## Final Answer"
            )
        elif "## 最终答案" in item["model_reasoning"]:
            item["model_reasoning"] = item["model_reasoning"].replace(
                "## 最终答案", "## Final Answer"
            )
        elif "**最终答案**" in item["model_reasoning"]:
            item["model_reasoning"] = item["model_reasoning"].replace(
                "**最终答案**", "## Final Answer"
            )
        elif "**最终判断**" in item["model_reasoning"]:
            item["model_reasoning"] = item["model_reasoning"].replace(
                "**最终判断**", "## Final Answer"
            )
        elif "**Final Assessment:**" in item["model_reasoning"]:
            item["model_reasoning"] = item["model_reasoning"].replace(
                "**Final Assessment:**", "## Final Answer"
            )

        if "## Final Answer" not in item["model_reasoning"]:
            errors.append(f"reasoning error for idx {item['idx']}")
            continue

        output_ids = tokenizer(
            item["input"] + item["model_reasoning"], return_tensors="pt"
        )["input_ids"]
        input_ids = tokenizer(item["input"], return_tensors="pt")["input_ids"]
        lens = len(output_ids[0])
        lens_input = len(input_ids[0])

        if lens >= filter_all_length or lens_input >= filter_input_length:
            errors.append(f"Response length is {lens} for {item['idx']}")
            continue

        processed_items.append(item)

    return processed_items, errors


def chunks(lst, n):
    chunk_size = len(lst) // n
    remainder = len(lst) % n
    result = []
    start = 0

    for i in range(n):
        # if there is a remainder, the first remainder chunks are allocated one more element
        end = start + chunk_size + (1 if i < remainder else 0)
        result.append(lst[start:end])
        start = end

    return result


if __name__ == "__main__":
    parser = create_filter_parser()
    args = parser.parse_args()

    os.chdir(PROJECT_PATH)

    short_model_name = args.model_name.split("/")[-1]
    input_file_name = (
        f"{short_model_name}_{args.training_set}.json"
        if args.file_name_prefix is None
        else f"{args.file_name_prefix}_{short_model_name}_{args.training_set}.json"
    )

    file_name = f"{short_model_name}_{args.training_set}_len_{args.filter_all_length}_inputlen_{args.filter_input_length}.json"
    if args.file_name_prefix is not None:
        file_name = args.file_name_prefix + "_" + file_name

    input_json = os.path.join(args.input_dir, args.dataset_type, input_file_name)
    if args.filter_correct_only:
        output_json = os.path.join(
            args.output_dir, args.dataset_type, "filtered_only_correct", file_name
        )
    else:
        output_json = os.path.join(
            args.output_dir, args.dataset_type, "filtered", file_name
        )

    os.makedirs(os.path.dirname(output_json), exist_ok=True)

    # preprocess the data
    assert os.path.exists(input_json)
    with open(input_json, "rb") as f:
        distil_data = orjson.loads(f.read())[1:]
    if args.filter_correct_only:
        filtered_data = [
            item for item in distil_data if item["model_reasoning"] and item["correct"]
        ]
    else:
        filtered_data = [
            item for item in distil_data if item["model_reasoning"]
        ]
    # split data into chunks
    num_processes = args.num_processes
    data_chunks = chunks(filtered_data, num_processes)

    all_processed_items = []
    all_errors = []

    # use ProcessPoolExecutor to process data
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = []

        # submit tasks
        for chunk in data_chunks:
            future = executor.submit(
                process_chunk,
                chunk,
                args.filter_all_length,
                args.filter_input_length,
            )
            futures.append(future)

        for future in futures:
            processed_items, errors = future.result()
            all_processed_items.extend(processed_items)
            all_errors.extend(errors)

    # print errors
    if all_errors:
        print("\nErrors encountered:")
        for error in all_errors:
            print(error)
    print(f"Number of original data: {len(distil_data)}")
    print(f"Number of final data: {len(all_processed_items)}")

    # save processed data
    with open(output_json, "wb") as f:
        f.write(
            orjson.dumps(all_processed_items, option=orjson.OPT_INDENT_2, default=str)
        )
