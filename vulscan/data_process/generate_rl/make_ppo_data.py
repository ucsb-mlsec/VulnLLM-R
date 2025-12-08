import argparse
import os

import orjson
from dotenv import load_dotenv
import re


def replace_single(text):
    pattern = r"## Final Answer\s*#judge:\s*<?(\w+)>?\s*#type:[^\n]*"
    return re.sub(pattern, r"\1", text)


if __name__ == "__main__":
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_name", type=str, default="Qwen/QwQ-32B-Preview")
    args = parser.parse_args()
    # model = "o3-mini-2025-01-14"
    # convert data into dpo format
    distil_dir = "datasets/large_train/distil/cleaned"
    output_dir = "datasets/large_train/ppo/"
    short_modelname = args.model_name.split("/")[-1]
    distil_path = os.path.join(distil_dir, f"{short_modelname}_train.json")
    output_path = os.path.join(output_dir, f"{short_modelname}_only_answer_train.json")
    # make sure output_dir exists
    os.makedirs(output_dir, exist_ok=True)
    with open(distil_path, "rb") as f:
        distil_data = orjson.loads(f.read())
    acc_num = distil_data[0]["acc_num"]
    distil_data = distil_data[1:]
    # change the output
    new_data = []
    for item in distil_data:
        if not item["correct"]:
            continue
        output = item["output"]
        if "yes" in output:
            new_output = "yes"
        elif "no" in output:
            new_output = "no"
        else:
            raise ValueError(f"output: {output}")

        new_input = item["input"].replace(
            "You should STRICTLY structure your response as follows:\n## Final Answer\n#judge: <yes/no>\n#type: <vulnerability type>",
            "Put yes or no in \\boxed{}.",
        )
        new_input = new_input.split("## Example")[0].strip()
        new_input = new_input.replace(
            "You are an advanced vulnerability detection model. Your task is to check if any vulnerability exists in a given piece of code. You need to output whether the code is vulnerable and the type of vulnerability present.",
            "",
        ).strip()
        inputs = new_input.split(
            "You should only focusing on checking if the code contains the following cwe: "
        )
        inputs[0] += (
            "Please check if any vulnerability exists in the above code snippet. You should only focusing on checking if the code contains the following cwe: "
        )
        new_input = inputs[0] + inputs[1]
        new_data.append(
            {
                "input": [
                    {
                        "role": "system",
                        "content": "Please reason step by step, and put your final answer within \\boxed{}.",
                    },
                    {"role": "user", "content": new_input},
                ],
                "output": new_output,
                "idx": item["idx"],
                "cwe": item["cwe"],
            }
        )
    print(f"data num: {len(new_data)}")
    with open(output_path, "wb") as f:
        f.write(orjson.dumps(new_data, option=orjson.OPT_INDENT_2))
