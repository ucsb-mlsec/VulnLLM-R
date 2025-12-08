# Load and merge existing datasets: PrimeVul, Sven, CyberSecEval, SecCodePLT, and ASLEEP.

import json
import os
import re
from collections import defaultdict
from typing import Literal, List

import jsonlines
import orjson
from datasets import load_dataset
from pydantic import BaseModel, Field, ValidationError

from vulscan.utils.cwes import tmp_cwes
from vulscan.utils.get_cwe_info import get_cwe_info
from vulscan.utils.project_info import PROJECT_PATH

ProgrammingLanguage = Literal["python", "c", "cpp"]


idx = 0


def classify_by_cwe(data, language, dataset_name):
    global idx
    cwe_dict = defaultdict(list)
    for item in data:
        if (
            item["language"] == language or item["language"] == language + "pp"
        ):  # we add cpp into c
            for cwe in item["CWE_ID"]:
                cwe_number = int(cwe.split("-")[-1])
                if "Unknown CWE" in get_cwe_info(cwe_number):
                    continue
                item["dataset"] = dataset_name
                item["idx"] = idx
                idx += 1
                cwe_dict[cwe].append(item)
    return cwe_dict


def save_cwe_files(cwe_dict, save_path):
    os.makedirs(save_path, exist_ok=True)
    for cwe, items in cwe_dict.items():
        file_path = os.path.join(save_path, f"{cwe}.json")
        with open(file_path, "wb") as f:
            f.write(orjson.dumps(items, option=orjson.OPT_INDENT_2, default=str))
    print(f"Saved {len(cwe_dict)} CWE files to {save_path}")


def process_files(input_path, languages):
    combined_cwe_dict = {language: defaultdict(list) for language in languages}
    for root, dirs, files in os.walk(input_path):
        for dir_name in dirs:
            if dir_name in languages:
                continue
            file_path = os.path.join(root, dir_name, "train.json")
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for language in languages:
                    cwe_dict = classify_by_cwe(data, language, dir_name)
                    for cwe, items in cwe_dict.items():
                        combined_cwe_dict[language][cwe].extend(items)
    for language in languages:
        save_path = os.path.join(input_path, language)
        save_cwe_files(combined_cwe_dict[language], save_path)


def process_test_files(input_path, output_path, languages, dataset_name):
    combined_cwe_dict = {language: defaultdict(list) for language in languages}
    for root, dirs, files in os.walk(input_path):
        for dir_name in dirs:
            if dir_name not in dataset_name:
                continue
            file_path = os.path.join(root, dir_name, "test.json")
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for language in languages:
                    cwe_dict = classify_by_cwe(data, language, dir_name)
                    for cwe, items in cwe_dict.items():
                        combined_cwe_dict[language][cwe].extend(items)
    for language in languages:
        save_path = os.path.join(output_path, language)
        save_cwe_files(combined_cwe_dict[language], save_path)


def cwe_stat(split, data_path, dataset_name, language=""):
    data_path = os.path.join(data_path, dataset_name)

    # cal the number of different CWEs
    cwe_set = set()
    count = 0
    vul_count = 0
    with open(os.path.join(data_path, data_path, f"{split}.json"), "r") as f:
        data = json.load(f)
        for item in data:
            if item["target"] == 0:
                vul_count += 1
            if language != "":
                if item["language"] != language:
                    continue
            # item["CWE_ID"] is a list
            count += 1
            [cwe_set.add(cwe) for cwe in item["CWE_ID"]]

    print(f"CWEs in {language} {split} of {dataset_name}\n", cwe_set)
    print(
        f"Number of different CWE in {language} {split} of {dataset_name}: {len(cwe_set)}"
    )
    print(f"Number of data in {language} {split} of {dataset_name}: {count}")
    print(
        f"Number of vulnerable data in {language} {split} of {dataset_name}: {vul_count}"
    )


class CodeData(BaseModel):
    CWE_ID: list[str]
    target: int
    code: str
    language: ProgrammingLanguage = Field(
        ...,
        description="The programming language of the code",
    )


class CodeDataList(BaseModel):
    items: List[CodeData]


def validate_data_list(data_items, name):
    try:
        CodeDataList(items=data_items)
        print(f"{name} Data is valid")
        return True
    except ValidationError as e:
        print(f"Error: {e} in {name} Data")
        return False


def extract_cwe_full(text, pattern=r"(CWE-\d+)"):
    match = re.search(pattern, text)
    return match.group(1) if match else None


def process_asleep(origin_path, save_path):
    if not os.path.exists(origin_path):
        dataset = load_dataset("moyix/asleep_keyboard", "DoW")
        dataset.save_to_disk(origin_path)
    else:
        dataset = load_dataset("moyix/asleep_keyboard", data_dir=origin_path)
    data_items = []
    for item in dataset["test"]:
        scenario_id = item["scenario_id"]
        cwe_id = extract_cwe_full(scenario_id)
        if not check_cwe(cwe_id):
            continue
        data_items.append(
            {
                "CWE_ID": [cwe_id],
                "code": item["prompt"],
                "target": -1,
                "language": item["language"],
            }
        )
    with open(os.path.join(save_path, "test.json"), "wb") as f:
        f.write(orjson.dumps(data_items, option=orjson.OPT_INDENT_2, default=str))


def is_cwe_format(text, pattern=r"^CWE-\d+$"):
    if isinstance(text, list):
        return all(re.match(pattern, t) for t in text)
    return bool(re.match(pattern, text))


def check_language(data):
    file_name = data["file_name"]
    if file_name.endswith(".c"):
        return "c"
    elif (
        file_name.endswith(".cpp")
        or file_name.endswith(".cc")
        or file_name.endswith(".h")  # for header file, we assume it is cpp
        or file_name.endswith(".C")
    ):
        return "cpp"
    elif file_name.endswith(".py"):
        return "python"
    else:
        pass


def check_cwe(cwe):
    if not is_cwe_format(cwe):
        if not any(["NVD" in cwe for cwe in cwe]):
            print(f"Invalid CWE format: {cwe}")

        return False
    if isinstance(cwe, str):
        cwe = [cwe]
    for cwe_data in cwe:
        cwe_number = int(cwe_data.split("-")[-1])
        if "Unknown CWE" in get_cwe_info(cwe_number):
            return False
    return True


def process_sven(origin_path, save_path):
    # walk through the directory and process the files
    data_items = []
    for root, dirs, files in os.walk(origin_path):
        for file in files:
            if not file.endswith(".jsonl"):
                continue
            with jsonlines.open(os.path.join(root, file)) as f:
                for data in f:
                    cwe_id = data["vul_type"].upper()
                    # some data here is CWE-022, we need to convert it to CWE-22
                    if cwe_id.startswith("CWE-0"):
                        cwe_id = cwe_id.replace("CWE-0", "CWE-")
                    if not check_cwe(cwe_id):
                        continue
                    language = check_language(data)
                    data_items.append(
                        {
                            "CWE_ID": [cwe_id],
                            "code": data["func_src_before"],
                            "target": 1,
                            "language": language,
                        }
                    )
                    data_items.append(
                        {
                            "CWE_ID": [cwe_id],
                            "code": data["func_src_after"],
                            "target": 0,
                            "language": language,
                        }
                    )
    validate_data_list(data_items, name="sven")
    with open(os.path.join(save_path, "train.json"), "wb") as f:
        f.write(orjson.dumps(data_items, option=orjson.OPT_INDENT_2, default=str))


def process_cybersec(origin_path, save_path):
    with open(os.path.join(origin_path, "instruct.json"), "r") as f:
        data = json.load(f)
    data_items = []
    for item in data:
        if not check_cwe(item["cwe_identifier"]):
            continue
        data_items.append(
            {
                "CWE_ID": [item["cwe_identifier"]],
                "code": item["origin_code"],
                "target": 1,
                "language": item["language"],
            }
        )
    with open(os.path.join(save_path, "train.json"), "wb") as f:
        f.write(orjson.dumps(data_items, option=orjson.OPT_INDENT_2, default=str))


def process_primevul(origin_path, save_path, pair: bool = True, pair_idx=None):
    def process_primevul_json(file_name: str, pair_idx=None):
        split_data = []
        idx = set()
        with open(os.path.join(origin_path, file_name), "r") as f:
            for line_number, line in enumerate(f):
                item = json.loads(line)
                if not check_cwe(item["cwe"]):
                    continue
                # check pair_idx
                if pair_idx is not None:
                    if item["idx"] in pair_idx:
                        continue
                else:
                    idx.add(item["idx"])
                # write it back to the file
                split_data.append(
                    {
                        "CWE_ID": item["cwe"],
                        "code": item["func"],
                        "target": item["target"],
                        "language": "c",
                    }
                )
        validate_data_list(split_data, name=file_name)
        return split_data, idx

    insert = "_paired" if pair else ""
    train_data, train_idx = process_primevul_json(
        f"primevul_train{insert}.jsonl", pair_idx
    )
    valid_data, valid_idx = process_primevul_json(
        f"primevul_valid{insert}.jsonl", pair_idx
    )
    # concatenate the train and valid data
    train_data.extend(valid_data)
    test_data, test_idx = process_primevul_json(
        f"primevul_test{insert}.jsonl", pair_idx
    )

    with open(os.path.join(save_path, "train.json"), "wb") as fs:
        fs.write(orjson.dumps(train_data, option=orjson.OPT_INDENT_2, default=str))
    with open(os.path.join(save_path, "test.json"), "wb") as fs:
        fs.write(orjson.dumps(test_data, option=orjson.OPT_INDENT_2, default=str))
    # add idx
    if pair:
        return train_idx.union(valid_idx).union(test_idx)


def process_sec_code_plt(origin_path, save_path):
    with open(os.path.join(origin_path, "data_one.json"), "r") as f:
        data = json.load(f)
    data_items = []
    for item in data:
        if "CWE-" + item["CWE_ID"] in tmp_cwes["python"]:
            desc = item["task_description"]["description"]
            # add desc as comment in the code
            item["unittest"]["setup"] = item["unittest"]["setup"] + f"\n# {desc}\n"
        vulnerable_full = (
            item["unittest"]["setup"]
            + item["ground_truth"]["code_before"]
            + item["ground_truth"]["vulnerable_code"]
            + item["ground_truth"]["code_after"]
        )
        patched_full = (
            item["unittest"]["setup"]
            + item["ground_truth"]["code_before"]
            + item["ground_truth"]["patched_code"]
            + item["ground_truth"]["code_after"]
        )
        data_items.append(
            {
                "CWE_ID": item["CWE_ID"],
                "vulnerable_code": vulnerable_full,
                "patched_code": patched_full,
            }
        )
    # valid and test are shuffled and split from the remaining items

    # Now create data_new for each split separately
    def create_data_new(items):
        data_new = []
        for item in items:
            cwe_id = "CWE-" + item["CWE_ID"]
            if not check_cwe(cwe_id):
                continue
            data_new.append(
                {
                    "CWE_ID": [cwe_id],
                    "code": item["vulnerable_code"],
                    "target": 1,
                    "language": "python",
                }
            )
            data_new.append(
                {
                    "CWE_ID": [cwe_id],
                    "code": item["patched_code"],
                    "target": 0,
                    "language": "python",
                }
            )
        validate_data_list(data_new, name="sec_code_plt")
        return data_new

    train_data = create_data_new(data_items)
    # flip test_data label
    # for item in test_data:
    # item['target'] = 1 - item['target']
    combined_cwe_dict = {language: defaultdict(list) for language in ["python"]}
    for language in ["python"]:
        cwe_dict = classify_by_cwe(train_data, language, "seccodeplt")
        for cwe, items in cwe_dict.items():
            combined_cwe_dict[language][cwe].extend(items)
    for language in ["python"]:
        save_path = os.path.join(save_path, language)
        save_cwe_files(combined_cwe_dict[language], save_path)


if __name__ == "__main__":
    # read existing datasets and process them into different json files. check if the json files contain the need features
    data_path = os.path.join(PROJECT_PATH, "datasets/raw_dataset")
    processed_data_path = os.path.join(PROJECT_PATH, "datasets/test")

    # cwe_stat("test", processed_data_path, "primevul_nopair")

    ## our dataset
    seccodeplt_path = os.path.join(data_path, "seccodeplt")
    processed_seccodeplt_path = os.path.join(processed_data_path, "test_seccodeplt")
    os.makedirs(processed_seccodeplt_path, exist_ok=True)
    process_sec_code_plt(seccodeplt_path, processed_seccodeplt_path)
    print("Done processing seccodeplt")
    # # primevul pair
    prime_vul_path = os.path.join(data_path, "primevul")
    processed_primevul_path = os.path.join(processed_data_path, "primevul_pair")
    os.makedirs(processed_primevul_path, exist_ok=True)
    pair_idx = process_primevul(prime_vul_path, processed_primevul_path)
    print("Done processing primevul")
    # # prime not pair
    processed_primevul_nopair_path = os.path.join(
        processed_data_path, "primevul_nopair"
    )
    os.makedirs(processed_primevul_nopair_path, exist_ok=True)
    process_primevul(
        prime_vul_path, processed_primevul_nopair_path, pair=False, pair_idx=pair_idx
    )
    print("Done processing nopair primevul")

    # # sven
    processed_sven_path = os.path.join(processed_data_path, "sven")
    sven_path = os.path.join(data_path, "sven/sven/data_train_val")
    os.makedirs(processed_sven_path, exist_ok=True)
    process_sven(sven_path, processed_sven_path)
    print("Done processing sven")
    # # cyberseceval
    # cyber_path = os.path.join(data_path, "cyberseceval")
    # processed_cyber_path = os.path.join(processed_data_path, "cyberseceval")
    # os.makedirs(processed_cyber_path, exist_ok=True)
    # process_cybersec(cyber_path, processed_cyber_path)
    # print("Done processing cyberseceval")
    # CodeData.from_json(str(file_path))

    # asleep
    asleep_path = os.path.join(data_path, "asleep")
    processed_asleep_path = os.path.join(processed_data_path, "asleep")
    os.makedirs(processed_asleep_path, exist_ok=True)
    process_asleep(asleep_path, processed_asleep_path)
    print("Done processing asleep")

    # split cwe
    use_train = True
    languages = ["python"]
    if use_train:
        output_path = os.path.join(PROJECT_PATH, "datasets", "large_train")
        process_files(processed_data_path, languages)
    else:
        # dataset_name = ["primevul_pair", "primevul_nopair"]
        dataset_name = "primevul_pair"
        output_path = os.path.join(PROJECT_PATH, "all_dataset", "test_primevul_pair")

        process_test_files(processed_data_path, output_path, languages, dataset_name)
