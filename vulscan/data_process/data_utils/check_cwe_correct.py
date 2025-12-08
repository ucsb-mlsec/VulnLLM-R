import os
from pprint import pprint

import orjson

if __name__ == "__main__":
    # data_name = "QwQ-32B-Preview"
    data_name = "deepseek-reasoner"
    # data_name = "o3-mini-2025-01-14"
    file_name = f"{data_name}_train.json"
    # preprocess the data
    origin_dataset_path = os.path.join("datasets/large_train/distil/", file_name)
    assert os.path.exists(origin_dataset_path)
    with open(origin_dataset_path, "rb") as f:
        distil_data = orjson.loads(f.read())[1:]
    cwe_ids = [
        item["cwe"][0]
        for item in distil_data
        if item["model_reasoning"] and item["correct"]
    ]
    all_cwe_ids = [item["cwe"][0] for item in distil_data]
    # calculate the correct number in each cwe
    correct_cwe_count = {}
    for cwe in cwe_ids:
        if cwe not in correct_cwe_count:
            correct_cwe_count[cwe] = 0
        correct_cwe_count[cwe] += 1
    # calculate the number in each cwe
    cwe_count = {}
    for cwe in all_cwe_ids:
        if cwe not in cwe_count:
            cwe_count[cwe] = 0
        cwe_count[cwe] += 1
    # calculate accuracy of each cwe
    sorted_cwe = sorted(correct_cwe_count.items(), key=lambda x: x[1], reverse=True)
    for idx in range(len(sorted_cwe)):
        cwe = sorted_cwe[idx][0]
        sorted_cwe[idx] = (
            sorted_cwe[idx][0],
            cwe_count[cwe],
            round(correct_cwe_count[cwe] / cwe_count[cwe], 3),
        )
    # sort the cwe_count based on value
    sorted_accuracy = sorted(sorted_cwe, key=lambda x: x[2], reverse=True)
    print(f"Number of CWEs: {len(correct_cwe_count)}")
    print(f"Number of data: {len(cwe_ids)}")
    # pretty print the cwe_count
    pprint(sorted_accuracy)
