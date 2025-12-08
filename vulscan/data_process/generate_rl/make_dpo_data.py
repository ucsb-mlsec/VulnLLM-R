import glob
import json
import os

import orjson

from vulscan.utils.get_cwe_info import get_cwe_info

prompt = """\
You are an advanced vulnerability detection model. Your task is to check if any vulnerability exists in a given piece of code. You need to output whether the code is vulnerable and the type of vulnerability present.

## You are given the following code snippet:
{CODE}

{CWE_INFO}

Structure your response as follows:
#judge: <yes/no>
#type: <vulnerability type>

## Example
- If the code is vulnerable to a CWE-79, you should output:
#judge: yes
#type: CWE-79

- If the code does not contain vulnerabilities related to the given CWE, you should output:
#judge: no
#type: N/A

## Your Answer:
"""
if __name__ == "__main__":
    # convert data into dpo format
    output_dir = "datasets/large_train/dpo/"
    output_path = os.path.join(output_dir, "train.json")

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    dpo_data = []
    for language in ["python", "c"]:
        input_dir = f"datasets/large_train/{language}"
        for json_file in glob.glob(os.path.join(input_dir, "*.json")):
            print(f"processing: {json_file}")
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # select data that is "dataset": "primevul_pair"
                # only for c
                # if language == "c":
                #     data = [item for item in data if item["dataset"] == "primevul_pair"]
                # selected_samples = select_diverse_samples(data)
                # for now we just choose the first 3 samples
                selected_samples = [
                    item for item in data if not item.get("human", None)
                ]
                if len(selected_samples) != len(data):
                    print(f"{json_file} contains human labeled data")
                for i in range(len(selected_samples)):
                    cve_data = selected_samples[i]
                    is_vul = "yes" if cve_data["target"] else "no"
                    isnot_vul = "yes" if not cve_data["target"] else "no"
                    policy = "You should only focusing on checking if the code contains the following cwe: "
                    for cwe_id in cve_data["CWE_ID"]:
                        # extract number
                        cwe_number = int(cwe_id.split("-")[-1])
                        policy += f"\n- {cwe_id}: {get_cwe_info(cwe_number)}"
                        assert (
                            "Unknown CWE" not in policy
                        ), f"Unknown CWE: {cwe_id} is detected"
                    input_prompt = prompt.format(
                        CODE=cve_data["code"],
                        CWE_INFO=policy,
                    )
                    chosen_type = (
                        ",".join(cve_data["CWE_ID"]) if cve_data["target"] else "N/A"
                    )
                    rejected_type = (
                        ",".join(cve_data["CWE_ID"])
                        if not cve_data["target"]
                        else "N/A"
                    )
                    chosen_output = "#judge: " + is_vul + "\n#type: " + chosen_type
                    rejected_output = (
                        "#judge: " + isnot_vul + "\n#type: " + rejected_type
                    )
                    chosen_data = [
                        {"role": "user", "content": input_prompt},
                        {"role": "assistant", "content": chosen_output},
                    ]
                    rejected_data = [
                        {"role": "user", "content": input_prompt},
                        {"role": "assistant", "content": rejected_output},
                    ]
                    dpo_data.append(
                        {
                            "chosen": chosen_data,
                            "rejected": rejected_data,
                        }
                    )
                # save the selected samples
            except Exception as e:
                print(f"process {json_file} 时出错: {str(e)}")
    with open(output_path, "wb") as f:
        f.write(orjson.dumps(dpo_data, option=orjson.OPT_INDENT_2, default=str))
