import os
import argparse
import re
import random
import string
import json


overlapped_top25_cwe_list_in_juliet = ['CWE-78', 'CWE-416', 'CWE-476', 'CWE-190', 'CWE-400']
additional_seleted_in_juliet = [
    'CWE-338', # Weak_PRNG 
    'CWE-327', # Use_Broken_Crypto
    'CWE-367', # Time_of_Check_Time_of_Use
    'CWE-134', # Use_of_Externally_Controlled_Format_String
    'CWE-369', # Divide_by_Zero
    'CWE-121', # Stack_Buffer_Overflow
    'CWE-191', # Integer_Underflow
    'CWE-23', # Relative_Path_Traversal
    'CWE-843', # Type_Confusion
    'CWE-761',  # Free_Pointer_Not_at_Start_of_Buffer
    'CWE-526', # Info_Exposure_Environment_Variables
    'CWE-457', # Use_of_Uninitialized_Variable
    'CWE-176', # Improper_Handling_of_Unicode_Encoding 
    'CWE-758', # Reliance_on_Undefined,_Unspecified,_or_Implementation-Specific_Behavior
    'CWE-319', # Cleartext_Transmission_of_Sensitive_Information
]

ood_cwe_list = [
    'CWE-123', #Write_What_Where_Condition
    'CWE-124', #Buffer_Underwrite
    'CWE-15', #External_Control_of_System_or_Configuration_Setting
    'CWE-90', # LDAP_Injection
    'CWE-415', # Double_Free
    'CWE-775', # Missing_Release_of_File_Descriptor_or_Handle
    'CWE-681', # Incorrect_Conversion_Between_Numeric_Types
    'CWE-122', # Heap_Buffer_Overflow
    'CWE-426', # Untrusted_Search_Path 
    'CWE-242', # Use_of_Inherently_Dangerous_Function
    'CWE-252', # Unchecked_Return_Value
    'CWE-401', # Memory_Leak
    'CWE-506', # Embedded_Malicious_Code
    'CWE-590', # Free_Memory_Not_on_Heap
    'CWE-667', # Improper_Locking
    ]

train_cwe_list= overlapped_top25_cwe_list_in_juliet + additional_seleted_in_juliet
# overlap_sven_with_cwe_list = ['CWE-78','CWE-190','CWE-416','CWE-476']
# only_sven = ['CWE-22','CWE-79','CWE-89','CWE-125','CWE-787']
idx = 400000


def choose_longest_test_files_one_cwe(dir, num):
    valid_files = []

    for root, _, files in os.walk(dir):
        for file in files:
            if file.endswith(('.c', '.cpp')):  
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()

                    if not any(re.search(r'\bmain\b', line) for line in lines):
                        continue  # Skip files that contain `#include "CWE***.h"`

                    valid_files.append((file_path, len(lines)))  

                except Exception as e:
                    print(f"Unable to read {file_path}: {e}")

    valid_files.sort(key=lambda x: x[1], reverse=True)

    return [f[0] for f in valid_files[:num//2]]

def remove_comments(code):
    """
    Remove all C/C++ comments from the source code.
    Removes both multiline comments (/* ... */) and single-line comments (// ...).
    """
    # Remove multiline comments (dot matches newlines)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    # Remove single-line comments
    code = re.sub(r'//.*', '', code)
    return code

def random_func_name(length=8):
    """
    Generate a random function name.
    The new name is prefixed with 'f_' followed by random lowercase letters.
    """
    return 'f_' + ''.join(random.choices(string.ascii_lowercase, k=length))


def clean_informative_prints(code):
    # List of regex patterns to match the target lines (using MULTILINE mode)
    patterns = [
        r'^\s*printLine\("Calling good\(\)\.\.\."\);\s*$',
        r'^\s*printLine\("Finished good\(\)"\);\s*$',
        r'^\s*printLine\("Calling bad\(\)\.\.\."\);\s*$',
        r'^\s*printLine\("Finished bad\(\)"\);\s*$'
    ]
    for pattern in patterns:
        code = re.sub(pattern, '', code, flags=re.MULTILINE)
    return code

def clean_keywords(code):
    code = re.sub(r'CWE\d+', '', code, flags=re.IGNORECASE)
    code = re.sub(r'good|bad', '', code, flags=re.IGNORECASE)
    return code

def clean_namespace(code):
    namespace_pattern = re.compile(r'\b(namespace|using namespace)\s+([\w\d_]+)(?=[;\s])')
    code = namespace_pattern.sub(r'\1 _A_namespace', code)
    return code

def clean_test_file(code):
    """
    Cleans a C/C++ source file (provided as a string) by:
    
    1. Removing all comments.
    2. Randomizing all function names that contain "good" or "bad" (case-insensitive).
    
    The function uses a heuristic regular expression to locate function definitions.
    Only those functions whose names (as detected by the regex) contain 'good' or 'bad'
    (ignoring case) are randomized.
    
    Returns the cleaned code as a string.
    """
    # Remove comments first
    code = remove_comments(code)
    
    code = clean_informative_prints(code)

    code = clean_keywords(code)
    
    code = clean_namespace(code)
    
    # Heuristic regex to match function definitions.
    # It looks for a return type and a function name (an identifier) followed by a parameter list and an opening brace.
    pattern = re.compile(
        r'^\s*(?!if\b|while\b|for\b|switch\b)(?:[a-zA-Z_]\w*\s+)+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{',
        re.MULTILINE
    )
    
    # Find all candidate function names
    candidate_func_names = pattern.findall(code)
    
    # Create a mapping for functions whose names contain "good" or "bad" (ignoring case)
    mapping = {}
    for name in set(candidate_func_names):
        if re.search(r'good|bad', name, re.IGNORECASE):
            mapping[name] = random_func_name()
    
    # Replace all occurrences of the matched function names with the new random name,
    # using word boundaries to ensure only whole words are replaced.
    for orig, new in mapping.items():
        code = re.sub(r'\b' + re.escape(orig) + r'\b', new, code)
    
    return code


def process_block(lines, start_regex, remove_content):
    """
    Process the list of lines to remove a conditional block that starts with a line
    matching 'start_regex'. This function handles nested conditionals.
    
    If remove_content is True, the entire block (start directive, content, and matching #endif)
    is removed. If remove_content is False, only the start and matching #endif lines are removed,
    while preserving the inner content.
    """
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # If the current line matches the target start directive...
        if re.match(start_regex, line):
            # We have encountered the start of a target block.
            level = 1
            block_content = []
            i += 1  # Skip the starting directive line.
            # Process until the matching #endif is found.
            while i < len(lines) and level > 0:
                current_line = lines[i]
                # Increase nesting level for any conditional start
                if re.match(r'^\s*#(?:if|ifdef|ifndef)\b', current_line):
                    level += 1
                # Check for #endif
                if re.match(r'^\s*#endif\b', current_line):
                    level -= 1
                    # If this #endif closes the outermost block, skip it and break
                    if level == 0:
                        i += 1  # Skip the matching #endif line.
                        break
                    else:
                        # Inside a nested block; if we are preserving content, add this line.
                        if not remove_content:
                            block_content.append(current_line)
                        i += 1
                        continue
                else:
                    # For normal lines within the block, if we are preserving content, add them.
                    if level > 0 and not remove_content:
                        block_content.append(current_line)
                    i += 1
            # For remove_content == False, output the inner content of the block
            if not remove_content:
                result.extend(block_content)
        else:
            # If the line does not start a target block, just output it.
            result.append(line)
            i += 1
    return result

def generate_list_one_cwe(test_files, cwe_num):
    """
    For each file in test_files:
    
    1. Remove the #ifdef INCLUDEMAIN ... #endif directives (removing only the directive lines,
       leaving their inner content intact). Note: these blocks might contain other nested directives.
    2. Generate two versions of the file:
       - 'good': 
         a. Remove entire blocks guarded by #ifndef OMITBAD (i.e. remove the directive lines and
            all content inside).
         b. Remove only the directive lines for #ifndef OMITGOOD (keep the content inside intact).
       - 'bad':
         a. Remove entire blocks guarded by #ifndef OMITGOOD (i.e. remove the directive lines and
            all content inside).
         b. Remove only the directive lines for #ifndef OMITBAD (keep the content inside intact).
    3. Clean both versions of the file (i.e., randomize function names, remove comments).
    4. Save all cleaned good and bad versions of files as a list of dict, return the list.
    """
    result_list = []
    global idx
    one_sample_template =   {
    "CWE_ID": [
      "CWE-1333"
    ],
    "code": "import re\ndef get_email_domain(mail_address):\n    email_pattern = re.compile(r'^[^@]+@(.+)$')\n    match = email_pattern.match(mail_address)\n    if match:\n        return match.group(1)\n    else:\n        return None",
    "target": 1,
    "language": "c",
    "dataset": "juliet 1.3",
    "idx": 400000,
    "original_file": "CWE1333_Incorrect_Case_of_Missing_Explicit_Initialization__char_pointer_01.c",
  }

    for file in test_files:
        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        # Remove #ifdef INCLUDEMAIN blocks: remove only the directive lines, preserve the inner content.
        lines_no_include_main = process_block(lines, r'^\s*#ifdef\s+INCLUDEMAIN', remove_content=False)
        
        # Create the 'good' version:
        # Step 1: Remove entire blocks guarded by #ifndef OMITBAD (remove directives and content)
        good_lines = process_block(lines_no_include_main, r'^\s*#ifndef\s+OMITBAD', remove_content=True)
        # Step 2: Remove only the directive lines for #ifndef OMITGOOD (preserve the inner content)
        good_lines = process_block(good_lines, r'^\s*#ifndef\s+OMITGOOD', remove_content=False)
        
        # Create the 'bad' version:
        # Step 1: Remove entire blocks guarded by #ifndef OMITGOOD (remove directives and content)
        bad_lines = process_block(lines_no_include_main, r'^\s*#ifndef\s+OMITGOOD', remove_content=True)
        # Step 2: Remove only the directive lines for #ifndef OMITBAD (preserve the inner content)
        bad_lines = process_block(bad_lines, r'^\s*#ifndef\s+OMITBAD', remove_content=False)
        
        # Join the processed lines into strings.
        good_str = "".join(good_lines)
        bad_str = "".join(bad_lines)
        
        good_str = clean_test_file(good_str)
        bad_str = clean_test_file(bad_str)
        
        good_tmp_res = one_sample_template.copy()
        good_tmp_res["code"] = good_str
        good_tmp_res["target"] = 0
        good_tmp_res["idx"] = idx
        good_tmp_res["CWE_ID"] = [cwe_num]
        good_tmp_res["original_file"] = file
        idx += 1
        
        bad_tmp_res = one_sample_template.copy()
        bad_tmp_res["code"] = bad_str
        bad_tmp_res["target"] = 1
        bad_tmp_res["idx"] = idx
        bad_tmp_res["CWE_ID"] = [cwe_num]
        bad_tmp_res["original_file"] = file
        idx += 1
        
        result_list.append(good_tmp_res)
        result_list.append(bad_tmp_res)
        
    return result_list


            
    

def main(input_dir, output_dir, train_per_cwe, test_per_cwe):
    testcase_names = os.listdir(input_dir)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    if not os.path.exists(os.path.join(output_dir, 'train')):
        os.makedirs(os.path.join(output_dir, 'train'))
    if not os.path.exists(os.path.join(output_dir, 'test')):
        os.makedirs(os.path.join(output_dir, 'test'))
    for name in testcase_names:
        if name.startswith("CWE"):
            cwe_prefix = name.split("_")[0] 
            cwe_num = cwe_prefix[:3]+ "-" + cwe_prefix[3:]
            if cwe_prefix.startswith("CWE") and cwe_num in train_cwe_list:
                test_files = choose_longest_test_files_one_cwe(os.path.join(input_dir, name), train_per_cwe + test_per_cwe)
                res = generate_list_one_cwe(test_files, cwe_num)
                res_train = res[:train_per_cwe]
                res_test = res[train_per_cwe:]
                with open(os.path.join(output_dir,'train' ,cwe_num + ".json"), 'w') as f:
                    json.dump(res_train, f, indent=4)
                with open(os.path.join(output_dir,'test' ,cwe_num + ".json"), 'w') as f:
                    json.dump(res_test, f, indent=4)
            if cwe_prefix.startswith("CWE") and cwe_num in ood_cwe_list:
                test_files = choose_longest_test_files_one_cwe(os.path.join(input_dir, name), test_per_cwe)
                res = generate_list_one_cwe(test_files, cwe_num)
                with open(os.path.join(output_dir,'test' , cwe_num + ".json"), 'w') as f:
                    json.dump(res, f, indent=4)

# Example usage:
# python split_good_bad_for_juliet.py --input_dir testcases --output_dir cleaned_juliet --train_per_cwe 200 --test_per_cwe 20
                    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_dir", type=str, required=True, help="Path to the directory containing testcases of Juliet test suite")
    parser.add_argument("--output_dir", type=str, required=True, help="Path to the directory to save the output")
    parser.add_argument("--train_per_cwe", type=int, required=True, help="Number of testcases for training set per CWE, half for good and half for bad")
    parser.add_argument("--test_per_cwe", type=int, required=True, help="Number of testcases for testing set per CWE, half for good and half for bad")
    args = parser.parse_args()
    main(args.input_dir, args.output_dir, args.train_per_cwe, args.test_per_cwe)
    