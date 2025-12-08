import argparse
import os
from datasets import load_dataset
from transformers import AutoTokenizer

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


def create_filter_parser():
    return ArgumentParser(
        CommonArgumentGroup(), ProcessingArgumentGroup(), FilterArgumentGroup()
    )


def filter_data(item, tokenizer, filter_all_length):
    output_ids = tokenizer(
        item["system"]
        + item["conversations"][0]["value"]
        + item["conversations"][1]["value"],
        return_tensors="pt",
    )["input_ids"]
    lens = len(output_ids[0])

    if lens >= filter_all_length:
        return False
    return True


if __name__ == "__main__":
    parser = create_filter_parser()
    args = parser.parse_args()
    os.chdir(PROJECT_PATH)
    # preprocess the data
    distil_data = load_dataset("NovaSky-AI/Sky-T1_data_17k")
    # filter data
    tokenizer = AutoTokenizer.from_pretrained("Qwen/QwQ-32B-Preview")
    filtered_data=distil_data.filter(
        filter_data,
        fn_kwargs={
            "tokenizer": tokenizer,
            "filter_all_length": args.filter_all_length,
        },
        num_proc=8,
    )

    filtered_data.push_to_hub("secmlr/Sky-T1_data_17k_filtered")
