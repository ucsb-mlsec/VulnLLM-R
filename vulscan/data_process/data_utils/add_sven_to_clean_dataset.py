import argparse
import os
import json

overlap_sven_with_juliet = ['CWE-78','CWE-190','CWE-416','CWE-476']
only_sven = ['CWE-22','CWE-125','CWE-787']#,'CWE-79'
sven_cwes = overlap_sven_with_juliet + only_sven 

def main(clean_dataset_dir, sven_data_path, test_per_cwe, train_per_cwe):
    for cwe_json in os.listdir(sven_data_path):
        cwe = cwe_json.split('.')[0]
        if cwe in only_sven:
            sven_list=[]
            samples = json.load(open(os.path.join(sven_data_path, cwe_json)))
            for sample in samples:
                if sample['dataset'] == 'sven' and not sample.get('human', False): # only add SVEN samples that are not human
                    sven_list.append(sample)
            test_list = sven_list[:test_per_cwe]
            train_list = sven_list[test_per_cwe:test_per_cwe+train_per_cwe]
            with open(os.path.join(clean_dataset_dir, 'test', 'c', f'{cwe}.json'), 'w') as f:
                json.dump(test_list, f, indent=4)
            with open(os.path.join(clean_dataset_dir, 'train', 'c', f'{cwe}.json'), 'w') as f:
                json.dump(train_list, f, indent=4)
        elif cwe in overlap_sven_with_juliet:
            sven_list=[]
            samples = json.load(open(os.path.join(sven_data_path, cwe_json)))
            for sample in samples:
                if sample['dataset'] == 'sven' and not sample.get('human', False): # only add SVEN samples that are not human
                    sven_list.append(sample)
            test_list = sven_list[:test_per_cwe//2]
            train_list = sven_list[test_per_cwe//2:test_per_cwe//2+train_per_cwe//2]
            with open(os.path.join(clean_dataset_dir, 'test', 'c', f'{cwe}.json'), 'r') as f:
                test_samples = json.load(f)
                test_samples[-len(test_list):] = test_list
            with open(os.path.join(clean_dataset_dir, 'test', 'c', f'{cwe}.json'), 'w') as f:
                json.dump(test_samples, f, indent=4)
            with open(os.path.join(clean_dataset_dir, 'train', 'c', f'{cwe}.json'), 'r') as f:
                train_samples = json.load(f)
                train_samples[-len(train_list):] = train_list
            with open(os.path.join(clean_dataset_dir, 'train', 'c', f'{cwe}.json'), 'w') as f:
                json.dump(train_samples, f, indent=4)
            

# Example usage: 
# python add_sven_to_clean_dataset.py --clean_dataset_dir ../../../datasets/clean_dataset/ --sven_data_path ../../../datasets/noisy_dataset/large_train/c/ --test_per_cwe 20 --train_per_cwe 200

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--clean_dataset_dir', type=str, required=True)
    parser.add_argument('--sven_data_path', type=str, required=True)
    parser.add_argument('--test_per_cwe', type=int, required=True, help='Number of test samples per CWE, we will replace test_per_cwe//2 test samples with SVEN samples if the test CWE file is already present, otherwise, we will create a new file and fill it with test_per_cwe SVEN samples')
    parser.add_argument('--train_per_cwe', type=int, required=True, help='Number of train samples per CWE, we will replace train_per_cwe//2 train samples with SVEN samples if the train CWE file is already present, otherwise, we will create a new file and fill it with train_per_cwe SVEN samples')
    args = parser.parse_args()
    main(args.clean_dataset_dir, args.sven_data_path, args.test_per_cwe, args.train_per_cwe)