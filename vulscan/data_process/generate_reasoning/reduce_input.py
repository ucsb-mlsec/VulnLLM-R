from datasets import load_dataset

from vulscan.utils.sys_prompts import qwen_sys_prompt


def reduce_input(example):
    conv = example["conversations"]
    inputs = conv[0]["value"]
    assert conv[0]["from"] == "user"
    # process inputs
    example["system"] = qwen_sys_prompt
    new_inputs = inputs.rsplit("## Additional Constraint:", maxsplit=1)[0]
    example["conversations"][0]["value"] = new_inputs
    return example


if __name__ == "__main__":
    datasets = [
        "secmlr/clean_dataset_filtered_QwQ-32B-Preview_train_len_8000_inputlen_5000",
        "secmlr/clean_dataset_filtered_together-deepseek-reasoner_train_len_8000_inputlen_5000",
        "secmlr/noisy_dataset_filtered_QwQ-32B-Preview_small_train_len_8000_inputlen_5000",
    ]
    for data_name in datasets:
        data = load_dataset(data_name)
        # for each data, we reduce the input
        data = data.map(
            reduce_input,
        )
        # save the data
        short_data_name = data_name.split("/")[-1]
        data.push_to_hub(f"secmlr/reduced_{short_data_name}")
