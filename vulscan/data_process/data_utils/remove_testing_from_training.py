# remove testing from training

import json
import os

def load_json(filepath):
    with open(filepath, 'r') as file:
        return json.load(file)

def save_json(filepath, data):
    with open(filepath, 'w') as file:
        json.dump(data, file, indent=4)

def convert_str_idx(entries):
    for entry in entries:
        if isinstance(entry['idx'], str) and entry['idx'].isdigit():
            entry['idx'] = int(entry['idx'])

def update_train_json(test_dir, train_dir):
    test_files = [f for f in os.listdir(test_dir) if f.endswith('.json')]
    train_files = [f for f in os.listdir(train_dir) if f.endswith('.json')]

    test_data = {}
    for test_file in test_files:
        test_path = os.path.join(test_dir, test_file)
        print(f"处理测试文件: {test_file}")
        test_entries = load_json(test_path)
        convert_str_idx(test_entries) 
        save_json(test_path, test_entries) 
        for entry in test_entries:
            test_data[str(entry['idx'])] = entry.get('human', 'Correct')

    for train_file in train_files:
        train_path = os.path.join(train_dir, train_file)
        print(f"处理训练文件: {train_file}")
        train_entries = load_json(train_path)
        convert_str_idx(train_entries)
        updated = False
        for entry in train_entries:
            if str(entry['idx']) in test_data and 'human' not in entry:
                entry['human'] = test_data[str(entry['idx'])]
                print(f"在文件 {train_file} 中更新了 idx: {entry['idx']}")
                updated = True
        if updated:
            save_json(train_path, train_entries)

if __name__ == "__main__":
    test_dir = "/scr/ruizhe/VulnScan-r0/datasets/noisy_dataset/test/c"
    train_dir = "/scr/ruizhe/VulnScan-r0/datasets/noisy_dataset/small_train/c"
    update_train_json(test_dir, train_dir)
