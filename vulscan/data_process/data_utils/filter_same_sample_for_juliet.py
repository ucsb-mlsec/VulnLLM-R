import os
import json
import re
from pathlib import Path

train_dir = Path("../../../datasets/clean_dataset/train/c")
test_dir = Path("../../../datasets/test/test_clean/c")

def normalize_code(code):
    return re.sub(r"f_.*?\(", "f(", code)

def deduplicate_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    seen = {}
    new_data = []
    duplicates_removed = 0

    for item in data:
        if isinstance(item, dict) and "code" in item and "idx" in item:
            norm = normalize_code(item["code"])
            if norm not in seen:
                seen[norm] = item
                new_data.append(item)
            else:
                duplicates_removed += 1
        else:
            new_data.append(item)

    if duplicates_removed > 0:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, indent=2, ensure_ascii=False)
        print(f"{path.name}: removed {duplicates_removed} internal duplicates")

for filename in os.listdir(train_dir):
    if filename.endswith('.json'):
        deduplicate_file(train_dir / filename)

for filename in os.listdir(test_dir):
    if filename.endswith('.json'):
        deduplicate_file(test_dir / filename)
