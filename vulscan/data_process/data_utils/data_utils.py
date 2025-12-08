import json
import argparse
import os
import shutil

def cwe_to_delete_num(path, threshold,total_num_to_delete):
    cwe_file_to_delete_num = {}
    total_unpaired_benign_4_cwe_above_threshold = 0
    for cwe in os.listdir(path):
        if cwe.endswith('.json'):
            with open(os.path.join(path, cwe), 'r') as f:
                data = json.load(f)
                if len(data) > threshold:
                    unpaired =  [d for d in data if d['dataset']=='primevul_nopair']
                    cwe_file_to_delete_num[cwe] = len(unpaired)
                    total_unpaired_benign_4_cwe_above_threshold += len(unpaired)
    for k in cwe_file_to_delete_num:
        cwe_file_to_delete_num[k] = round(cwe_file_to_delete_num[k]/total_unpaired_benign_4_cwe_above_threshold *total_num_to_delete)
    return cwe_file_to_delete_num
        

def main(threshold=5000, total_num_to_delete=50000, input_path=None, output_path=None):
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    total_unpaired_benign_4_cwe_above_threshold = cwe_to_delete_num(input_path, threshold,total_num_to_delete)
    for cwe in os.listdir(input_path):
        if cwe.endswith('.json') and cwe in total_unpaired_benign_4_cwe_above_threshold:
            with open(os.path.join(input_path, cwe), 'r') as f:
                data = json.load(f)
                if len(data) > threshold:
                    unpaired =  [d for d in data if d['dataset']=='primevul_nopair' and d['target']==0]
                    num_to_delete = total_unpaired_benign_4_cwe_above_threshold[cwe]
                    unpaired_to_delete = unpaired[:num_to_delete]
                    for d in unpaired_to_delete:
                        data.remove(d)
            with open(os.path.join(output_path, cwe), 'w') as f:
                json.dump(data, f, indent=4)
        else:
            shutil.copy(os.path.join(input_path, cwe), os.path.join(output_path, cwe))

related_cwe_dict = {
    'CWE-79': ['CWE-352','CWE-601','CWE-918'],
    'CWE-787': ['CWE-125','CWE-416','CWE-415'],
    'CWE-89': ['CWE-90','CWE-91','CWE-78'],
    'CWE-352': ['CWE-79','CWE-918','CWE-384'],
    'CWE-22': ['CWE-59','CWE-426','CWE-552'],
    'CWE-125': ['CWE-787','CWE-416','CWE-415'],
    'CWE-78': ['CWE-119','CWE-89','CWE-917'],
    'CWE-416': ['CWE-122','CWE-120','CWE-125'],
    'CWE-862': ['CWE-538','CWE-200','CWE-35'],
    'CWE-434': ['CWE-22','CWE-862','CWE-502'],
    'CWE-94': ['CWE-90','CWE-611','CWE-89'],
    'CWE-20': ['CWE-362','CWE-415','CWE-269'],
    'CWE-77': ['CWE-119','CWE-89','CWE-917'],
    'CWE-287': ['CWE-862','CWE-285', 'CWE-269'],
    'CWE-269': ['CWE-306','CWE-290','CWE-287'],
    'CWE-502': ['CWE-94','CWE-78','CWE-97'],
    'CWE-200': ['CWE-284','CWE-285','CWE-287'],
    'CWE-863': ['CWE-287','CWE-306','CWE-862'],
    'CWE-918': ['CWE-352','CWE-601','CWE-384'],
    'CWE-119': ['CWE-416','CWE-415','CWE-89'],
    'CWE-476': ['CWE-416','CWE-415','CWE-457'],
    'CWE-798': ['CWE-312','CWE-287','CWE-306'],
    'CWE-190': ['CWE-191','CWE-192','CWE-122'],
    'CWE-400': ['CWE-125','CWE-787', 'CWE-416'],
    'CWE-306': ['CWE-862','CWE-863','CWE-269'],
    'CWE-338': ['CWE-347','CWE-798','CWE-522'],
    'CWE-95': ['CWE-96','CWE-611','CWE-89'],
    'CWE-327': ['CWE-798','CWE-522','CWE-306'],
    'CWE-415': ['CWE-761','CWE-119','CWE-787'],
    'CWE-307': ['CWE-521','CWE-798','CWE-603'],
    'CWE-59':['CWE-269','CWE-276','CWE-284'],
    'CWE-1021':['CWE-311','CWE-532','CWE-863'],
    'CWE-122':['CWE-121','CWE-415','CWE-416'],
    'CWE-74':['CWE-125','CWE-121','CWE-122'],
    'CWE-93':['CWE-918','CWE-352','CWE-89'],
    'CWE-113':['CWE-79','CWE-918','CWE-346'],
    'CWE-88':['CWE-502', 'CWE-89','CWE-79'],
    'CWE-61':['CWE-22','CWE-427','CWE-434'],
    'CWE-295':['CWE-863','CWE-285','CWE-862'],
    'CWE-120':['CWE-124','CWE-415','CWE-416'],
    'CWE-915':['CWE-502','CWE-611','CWE-94'],
    'CWE-1333':['CWE-703','CWE-404','CWE-401'],
    'CWE-601':['CWE-352','CWE-918','CWE-502'],
    'CWE-367':['CWE-362','CWE-704','CWE-704'],
    'CWE-281':['CWE-276','CWE-250','CWE-798'],
    'CWE-179':['CWE-116','CWE-838','CWE-117'],
    'CWE-611':['CWE-89','CWE-94','CWE-78'],
    "CWE-116": ['CWE-120', 'CWE-415', 'CWE-416'],
    "CWE-703":['CWE-252','CWE-665','CWE-457'],
    "CWE-346":['CWE-352','CWE-601','CWE-79'],
    "CWE-285":['CWE-287','CWE-269','CWE-862'],
    "CWE-565":['CWE-79','CWE-352','CWE-918'],
    "CWE-134":['CWE-119','CWE-787','CWE-125'],
    "CWE-129":['CWE-134','CWE-415', 'CWE-416'],
    "CWE-369":['CWE-190','CWE-191','CWE-129'],
    "CWE-319":['CWE-352','CWE-601','CWE-918'],
    "CWE-123":['CWE-22','CWE-79','CWE-89'],
    "CWE-506":['CWE-306','CWE-862','CWE-863'],
    "CWE-90":["CWE-89","CWE-77","CWE-78"],
    "CWE-124": ["CWE-122","CWE-121","CWE-415"],
    "CWE-191": ["CWE-190","CWE-121","CWE-122"],
    "CWE-15": ["CWE-79","CWE-352","CWE-918"],
    "CWE-23": ["CWE-15","CWE-59","CWE-426"],
    "CWE-401": ["CWE-1333","CWE-703","CWE-404"],
    "CWE-252": ["CWE-703","CWE-665","CWE-457"],
    "CWE-590": ["CWE-415","CWE-416","CWE-121"],
    "CWE-761": ["CWE-415","CWE-416","CWE-121"],
    "CWE-176": ["CWE-119","CWE-787","CWE-125"],
    "CWE-426": ["CWE-22","CWE-59","CWE-552"],
    "CWE-681": ["CWE-352","CWE-601","CWE-918"],
    "CWE-775": ["CWE-125","CWE-787","CWE-416"],
    "CWE-526": ["CWE-352","CWE-601","CWE-918"],
    "CWE-121": ["CWE-122","CWE-415","CWE-416"],
    "CWE-457": ["CWE-416","CWE-415","CWE-476"],
    "CWE-843": ["CWE-352","CWE-601","CWE-918"],
    "CWE-242": ["CWE-120","CWE-134","CWE-502"],
    "CWE-667": ["CWE-352","CWE-601","CWE-918"],
    "CWE-758": ["CWE-352","CWE-601","CWE-918"],
    'CWE-347': ["CWE-327","CWE-326","CWE-798"],
    'CWE-909': ["CWE-200","CWE-285","CWE-287"],
    'CWE-835': ["CWE-908","CWE-362","CWE-667"],
    'CWE-924': ["CWE-319","CWE-347","CWE-311"],
    'CWE-617': ["CWE-404","CWE-252","CWE-125"],
    'CWE-362': ["CWE-763","CWE-404","CWE-457"],
    'CWE-552': ["CWE-918","CWE-285","CWE-601"],
    'CWE-354': ["CWE-523","CWE-798","CWE-614"],
    'CWE-704': ["CWE-476","CWE-688","CWE-253"],
    'CWE-665': ["CWE-415","CWE-252","CWE-672"],
    "CWE-288": ["CWE-522","CWE-532","CWE-319"],
    "CWE-193": ["CWE-416","CWE-134","CWE-640"],
    'CWE-834': ["CWE-367","CWE-611","CWE-703"],
    'CWE-732': ["CWE-908","CWE-457","CWE-672"],
    'CWE-345': ["CWE-918","CWE-523","CWE-829"],
    'CWE-444': ["CWE-79","CWE-532","CWE-502"],
    'CWE-772': ["CWE-362","CWE-707","CWE-667"],
    'CWE-284': ["CWE-614","CWE-79","CWE-918"],
    'CWE-770': ["CWE-212","CWE-522","CWE-276"],
    'CWE-668': ["CWE-601","CWE-502","CWE-614"],
    'CWE-824': ["CWE-119","CWE-125","CWE-190"],
    'CWE-522': ["CWE-601","CWE-285","CWE-703"],
    'CWE-754': ["CWE-416","CWE-285","CWE-476"],
    'CWE-276': ["CWE-772","CWE-672","CWE-400"],
    'CWE-672': ["CWE-401","CWE-908","CWE-400"],
    'CWE-908': ["CWE-416", "CWE-476", "CWE-775"],
    'CWE-212': ["CWE-79","CWE-502","CWE-918"],
}


def add_related_cwe(input_path = None, output_path = None):
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    for cwe_file in os.listdir(input_path):
            cwe_id= cwe_file[:-5]
            with open(f'{input_path}/{cwe_file}', 'r') as f:
                data = json.loads(f.read())
                if cwe_id in related_cwe_dict:
                    for item in data:
                        item['RELATED_CWE'] = related_cwe_dict[cwe_id]
            with open(f'{output_path}/{cwe_file}', 'w') as f:
                f.write(json.dumps(data, indent=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--threshold', type=int)
    parser.add_argument('--total_num_to_delete', type=int)
    parser.add_argument('--input_path', type=str)
    parser.add_argument('--output_path', type=str)
    args = parser.parse_args()
    if args.threshold and args.total_num_to_delete:
        main(args.threshold, args.total_num_to_delete, args.input_path, args.output_path)
    add_related_cwe(args.input_path, args.output_path)