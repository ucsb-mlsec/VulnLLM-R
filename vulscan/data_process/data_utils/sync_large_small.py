import os

import orjson

from vulscan.utils.project_info import PROJECT_PATH


def sync_large_small():
    large_dataset_path = os.path.join(
        PROJECT_PATH, "datasets/noisy_dataset/large_train/c"
    )
    small_dataset_path = os.path.join(
        PROJECT_PATH, "datasets/noisy_dataset/small_train/c"
    )
    large_files = os.listdir(large_dataset_path)
    small_files = os.listdir(small_dataset_path)
    large_files = [f for f in large_files if f.endswith(".json")]
    small_files = [f for f in small_files if f.endswith(".json")]
    for small_data_name in small_files:
        assert small_data_name in large_files, f"{small_data_name} not in large files"
        large_data_path = os.path.join(large_dataset_path, small_data_name)
        small_data_path = os.path.join(small_dataset_path, small_data_name)
        with open(small_data_path, "rb") as f:
            small_data = orjson.loads(f.read())
        with open(large_data_path, "rb") as f:
            large_data = orjson.loads(f.read())
        human_large_data = [item for item in large_data if item.get("human", None)]
        for item in small_data:
            for large_item in human_large_data:
                if item["idx"] == large_item["idx"]:
                    item["human"] = large_item["human"]
                    if "reason" in large_item:
                        item["reason"] = large_item["reason"]
                    if "RELATED_CWE" not in large_item:
                        large_item["RELATED_CWE"] = item["RELATED_CWE"]
                    break
                elif item["code"] == large_item["code"]:
                    if item["dataset"] != large_item["dataset"]:
                        continue
                    else:
                        raise "Something wrong"
        with open(small_data_path, "wb") as f:
            f.write(orjson.dumps(small_data, option=orjson.OPT_INDENT_2))
        with open(large_data_path, "wb") as f:
            f.write(orjson.dumps(large_data, option=orjson.OPT_INDENT_2))


if __name__ == "__main__":
    print("Syncing large and small snippets")
    sync_large_small()
