import os
import json
import re
import argparse
from collections import defaultdict

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

def infer_cwe(crash_type, sanitizer_output):
    c = crash_type.lower()
    sanitizer_output = sanitizer_output.lower()
    # if "null-deref" in sanitizer_output:
    #     return "CWE-476"
    if "overflow" in c and "read" in c:
        return "CWE-125"
    elif "overflow" in c and "write" in c:
        return "CWE-787"
    elif "use" in c and "free" in c:
        return "CWE-416"
    elif "index out" in c:
        return "CWE-119"
    return None

# Step 1: Process new converted_data
vuln_data = []
patched_data = []
data_dir = "data_new_train"
for filename in os.listdir(data_dir):
    if not filename.endswith(".json"):
        continue
    with open(os.path.join(data_dir, filename), "r", encoding="utf-8", errors="ignore") as f:
        try:
            data = json.load(f)
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            continue



    if data.get("if_vuln_crash") != 1:
        continue

    before = data.get("function_before_patch", [])
    after = data.get("function_after_patch", [])
    trace = data.get("functions_in_stack_trace", [])

    if not before or not after:
        continue

    before_bodies = [f["function_body"] for f in before]
    after_bodies = [f["function_body"] for f in after]
    if before_bodies == after_bodies:
        continue

    if_multi_func = False
    if len(before_bodies) > 1:
        if_multi_func = True
    
    changed_func_body_list = []
    before_code = ""
    for f in before:
        body = f["function_body"]
        name = f["function_name"]
        # before_code += f"\n###Function: {name}\n"
        before_code += body + "\n"
        changed_func_body_list.append(body)
    
    after_code = ""
    for f in after:
        body = f["function_body"]
        name = f["function_name"]
        # after_code += f"\n###Function: {name}\n"
        after_code += body + "\n"
    
    
    
    base_code = ""
    # current_len = 0
    filtered_trace = []
    for f in trace:
        body = f["function_body"]
        name = f["function_name"]
        if name == "LLVMFuzzerTestOneInput":
            break
        # if body in changed_func_body_list:
        #     continue
        filtered_trace.append(f)
        # if current_len + len(body) > 10000:
        #     break
        # current_len += len(body)
        base_code += f"\nHere is a function served as context, there is no vulnerability inside it. ###Function: {name}\n"
        base_code += body + "\n"
    local_id = data.get("local_id", 0)
    crash_type = data.get("crash_type", "")
    sanitizer_output = data.get("sanitizer_output", "")
    cwe_id = infer_cwe(crash_type, sanitizer_output)
    if not cwe_id:
        continue
    related = related_cwe_dict.get(cwe_id, [])

    base_fields = {
        "CWE_ID": [cwe_id],
        "language": "c",
        "dataset": "oss-fuzz",
        "RELATED_CWE": related,
        "if_multi_func": if_multi_func,
    }
    if len(before_code+base_code) > 50000:
        continue
    # before = label 1
    vuln_data.append({
        **base_fields,
        "code": before_code,
        "target": 1,
        "idx": 1000000 + int(local_id),
        "stack_trace": filtered_trace,
    })

    found_modification_in_stack = False

    names =  [f["function_name"] for f in before]
    for n in names:
        if n in data.get("sanitizer_output", ""):
            found_modification_in_stack = True
            break
    if not found_modification_in_stack:
        continue
    # only add patched version if there is a modification in the stack trace

    # after = label 0
    patched_data.append({
        **base_fields,
        "code": after_code,
        "target": 0,
        "idx": 2000000 + int(local_id)
    })



# Step 2: Group and write
parser = argparse.ArgumentParser(description="Group converted data by CWE ID")
parser.add_argument("--vuln-dir", type=str, default="./vuln", help="Directory to store CWE grouped JSON files")
parser.add_argument("--patched-dir", type=str, default="./patched", help="Directory to store patched CWE grouped JSON files")
args = parser.parse_args()

os.makedirs(args.vuln_dir, exist_ok=True)
os.makedirs(args.patched_dir, exist_ok=True)

# Save vuln_data
grouped = defaultdict(list)
for item in vuln_data:
    for cwe in item["CWE_ID"]:
        grouped[cwe].append(item)
print("vuln data")
for cwe_id, entries in grouped.items():
    print(f"CWE {cwe_id}: {len(entries)} new entries")
    total_len = sum(len(e["code"]) for e in entries)
    avg_len = total_len / len(entries) if entries else 0
    print(f"Average code length: {avg_len:.2f} characters")
    
    cwe_path = os.path.join(args.vuln_dir, f"{cwe_id}.json")
    updated = {}

    # Load existing if any
    if os.path.exists(cwe_path):
        with open(cwe_path, "r", encoding="utf-8", errors="ignore") as f:
            for item in json.load(f):
                updated[item["idx"]] = item

    # Overwrite or add
    for item in entries:
        updated[item["idx"]] = item

    new_data = list(updated.values())

    # Only write if content changed
    if os.path.exists(cwe_path):
        with open(cwe_path, "r", encoding="utf-8", errors="ignore") as f:
            old_data = json.load(f)
        if sorted(old_data, key=lambda x: x["idx"]) == sorted(new_data, key=lambda x: x["idx"]):
            continue  # No change

    with open(cwe_path, "w", encoding="utf-8") as f:
        json.dump(new_data, f, indent=2, ensure_ascii=False)




# Save patched_data
grouped_patched = defaultdict(list)
for item in patched_data:
    for cwe in item["CWE_ID"]:
        grouped_patched[cwe].append(item)
print("patched data")
for cwe_id, entries in grouped_patched.items():
    print(f"CWE {cwe_id}: {len(entries)} new entries")
    total_len = sum(len(e["code"]) for e in entries)
    avg_len = total_len / len(entries) if entries else 0
    print(f"Average code length: {avg_len:.2f} characters")
    patched_path = os.path.join(args.patched_dir, f"{cwe_id}.json")
    updated = {}

    # Load existing data if exists
    if os.path.exists(patched_path):
        with open(patched_path, "r", encoding="utf-8", errors="ignore") as f:
            for item in json.load(f):
                updated[item["idx"]] = item

    # Overwrite or add entries
    for item in entries:
        updated[item["idx"]] = item

    new_data = list(updated.values())

    # Sort for comparison (optional but helps ensure stable comparison)
    new_data_sorted = sorted(new_data, key=lambda x: x["idx"])

    # Only write if content changed
    if os.path.exists(patched_path):
        with open(patched_path, "r", encoding="utf-8", errors="ignore") as f:
            old_data = json.load(f)
        old_data_sorted = sorted(old_data, key=lambda x: x["idx"])
        if new_data_sorted == old_data_sorted:
            continue  # No update needed

    with open(patched_path, "w", encoding="utf-8") as f:
        json.dump(new_data_sorted, f, indent=2, ensure_ascii=False)