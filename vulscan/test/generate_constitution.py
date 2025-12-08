import argparse
import json
import os
from difflib import unified_diff

import orjson
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
from model_zoo.litellm_model import LiteLLMModel

from vulscan.utils.get_cwe_info import get_cwe_info
from vulscan.utils.project_info import PROJECT_PATH


def set_args():
    args = argparse.ArgumentParser()
    args.add_argument("--wandb", action="store_true")
    args.add_argument("--seed", type=int, default=42, help="seed")
    args.add_argument(
        "--input_dir", type=str, required=True, help="Directory with saved test results"
    )
    args.add_argument(
        "--output_dir", type=str, required=True, help="Directory to save constitution"
    )
    args.add_argument(
        "--requests_per_minute",
        type=int,
        default=10,
        help="requests per minute for API",
    )
    args.add_argument(
        "--model",
        type=str,
        default="gpt-4o-2024-11-20",
        help="model to use for constitution generation",
    )
    return args.parse_args()


def load_saved_results(input_dir):
    """Load all saved JSON results from the input directory."""
    results = []
    for filename in os.listdir(input_dir):
        if filename.endswith(".json") and "together" in filename:
            with open(os.path.join(input_dir, filename), "r") as f:
                results.append(json.load(f))
    return results


def extract_sample_pairs(results):
    for result_file in results:
        # Skip the first entry which contains summary metrics
        examples = result_file[1:]

        # Group examples by CWE_ID
        cwe_groups = {}
        for example in examples:
            cwe_id = example["cwe"]
            if isinstance(cwe_id, list):
                cwe_id = cwe_id[0] if cwe_id else "unknown"
            if cwe_id not in cwe_groups:
                cwe_groups[cwe_id] = []
            cwe_groups[cwe_id].append(example)

    return cwe_groups


def generate_diff(benign_code, vulnerable_code):
    """Generate a unified diff between benign and vulnerable code."""
    benign_lines = benign_code.splitlines(keepends=True)
    vulnerable_lines = vulnerable_code.splitlines(keepends=True)

    diff_lines = unified_diff(
        vulnerable_lines,
        benign_lines,
        fromfile="vulnerable",
        tofile="benign",
    )

    return "".join(list(diff_lines))


def generate_constitution_prompt(pair, diff, cwe):
    """Generate a prompt to ask GPT-4o for a constitution."""
    benign, vulnerable = pair
    cwe_number = int(cwe.split("-")[-1])
    prompt = """I'm showing you a pair of code samples. The first one is vulnerable, and the second one is benign (fixed). 
I'm also providing a diff between them to highlight the changes.

Based on these examples, please create a clear and concise "constitution" or set of principles that can guide an LLM to:
1. Identify when code is vulnerable
2. Specifically recognize the security vulnerability pattern shown here
3. Understand how the fix works and why it makes the code secure

Vulnerable code:

{vulnerable_code}

Benign code:

{benign_code}

Diff (showing what changed):
    
{diff}
    
CWE ID: 
- {cwe_id}: {description}

Please provide a constitution that will help an LLM accurately distinguish between vulnerable and benign code patterns like these, which means you need a constitution for vulnerable code and a constitution for benign code.
You should only focus on the **diff** and the given cwe, ignore any other potential security error""".format(
        vulnerable_code=vulnerable,
        benign_code=benign,
        diff=diff,
        cwe_id=cwe,
        description=get_cwe_info(cwe_number),
    )

    return prompt


def generate_constitution(model, sample_pairs):
    """Generate a constitution for each sample pair using GPT-4o."""
    constitutions = []
    prompts = []
    for i, pair in enumerate(sample_pairs):
        benign, vulnerable = pair
        if (benign["flag"] == "tp" or benign["flag"] == "tn") and (
            vulnerable["flag"] == "tp" or vulnerable["flag"] == "tn"
        ):
            continue
        # Get the code snippets
        benign_code = benign["input"].split("```")[1].split("```")[0]
        vulnerable_code = vulnerable["input"].split("```")[1].split("```")[0]
        cwe = vulnerable["original_vulnerability_type"][0]
        # Generate diff
        diff = generate_diff(benign_code, vulnerable_code)
        # Create prompt
        prompt = generate_constitution_prompt((benign_code, vulnerable_code), diff, cwe)

        # Query the model
        print(f"Generating constitution for pair {i+1}/{len(sample_pairs)}...")
        prompts.append({"input": prompt})
        constitutions.append(
            {
                "cwe_id": cwe,
                "benign_idx": benign["idx"],
                "vulnerable_idx": vulnerable["idx"],
                "benign_code": benign_code,
                "vulnerable_code": vulnerable_code,
                "diff": diff,
                "constitution": None,
                "benign_output": benign["output"],
                "vulnerable_output": vulnerable["output"],
                "benign_flag": benign["flag"],
                "vulnerable_flag": vulnerable["flag"],
            }
        )
    responses, _, _, _ = model.run(prompts[:100])
    for i, response in enumerate(responses):
        constitutions[i]["constitution"] = response[0]

    return constitutions


def main():
    load_dotenv()
    args = set_args()
    args.input_dir = os.path.join(PROJECT_PATH, args.input_dir)
    output_dir = os.path.join(PROJECT_PATH, args.output_dir)
    os.makedirs(args.output_dir, exist_ok=True)

    print("Loading saved results...")
    results = load_saved_results(args.input_dir)

    print("Extracting sample pairs...")
    sample_pairs = extract_sample_pairs(results)
    print(f"Found {len(sample_pairs)} benign/vulnerable pairs")

    print(f"Setting up {args.model} for constitution generation...")
    limiter = AsyncLimiter(args.requests_per_minute, 100)
    model = LiteLLMModel(
        model=args.model,
        limiter=limiter,
        temperature=0.0,
    )

    print("Generating constitutions...")
    constitutions = generate_constitution(model, sample_pairs)

    # Save constitutions
    output_file = os.path.join(
        output_dir, f"constitutions_{args.model.replace('/', '_')}.json"
    )
    with open(output_file, "wb") as f:
        f.write(orjson.dumps(constitutions, option=orjson.OPT_INDENT_2, default=str))

    print(f"Constitutions saved to {output_file}")


if __name__ == "__main__":
    main()
