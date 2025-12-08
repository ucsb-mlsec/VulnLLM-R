import difflib
import os
import re
import orjson
from dotenv import load_dotenv

from openai import OpenAI
from datasets import load_dataset
from transformers import AutoTokenizer
from together import Together

from vulscan.utils.project_info import PROJECT_PATH
import argparse

'''
system_prompt = """
You are now the code analysis expert responsible for refining the original thought process. Instead of merely summarizing, you must remove any unimportant or repetitive thinking steps while retaining the essential ones. Follow these rules carefully:

1. Input processing requirements:
   - The input has two main parts, first is a chain of thought where each step is separated by two newlines (\\n\\n)., and the second is the final solution.
   - Process only what is between <|begin_of_thought|> and <|end_of_thought|>.
   - You need to read everything, but only process the thought process part.

2. Thought refining rules:
   [1] Skip a few of unimportant, unrelated or repeated steps, and keep all others. Keep most of the steps, and only delete steps while necessary.
   [2] Retain steps that describe the overall functionality of the code, focus on key arguments of CWE type and any relevant vulnerabilities, or analysis for potential CWE for the code.
   [3] Keep important technical details, including code snippet references that validate or illustrate vulnerabilities.
   [4] Remove or skip:
       - Unimportant, unrelated, or repeated thinking steps.
       - Overly speculative or uncertain analysis.
   [5] During the checking for every step, once you decide to keep it, use the exactly original content without any modifications.
   [6] In the whole output, you need to keep the revised complete output thinking logically coherent.

3. IMPORTANT: You must not alter anything outside <|begin_of_thought|> and <|end_of_thought|> in the output.

4. Output formatting requirements:
   - Begin the output with: '<|begin_of_thought|>\n\n'
   - Write all the retained thinking steps with exactly the same original wording and sequence after <|begin_of_thought|>\n\n, preserving the original format of two newlines (\\n\\n) after each step.
   - End the thinking part with: '<|end_of_thought|>\n\n'
   - After '<|end_of_thought|>\n\n', write exactly the same final solution as the original input, with exactly the same format.

"""
'''
system_prompt = """
You are an expert in rewriting and reasoning. I will provide you with a piece of reasoning text for code patching which is needed for the repo maintain.

1. Input processing requirements:
   - The input has two main parts, first is a chain of thought where each step is separated by two newlines (\\n\\n)., and the second is the final solution.
   - Process only what is between <think> and </think>.
   - You need to read everything, but only process the thought process part.

2. Thought refining rules:
   [1]. Keep the original reasoning structure, order, and key analytical points, including reflection steps and descriptions.
   [2]. Do not indiscriminately remove important content. Avoid deleting essential reasoning or reflection.
   [3]. While ensuring the logic remains clear and no critical information is lost, remove superfluous or repetitive parts.
   [4]. You need to simplify the reasoning process, but be careful not to over-generalize it. Try to keep as much reasoning output as possible. Keep at least 300 words.
   [5]. Keep transition statements, like "Okay, let's try to figure"

3. IMPORTANT: You must not alter anything outside <think> and </think> in the output.

4. Output formatting requirements:
   - Begin the output with: '<think>\n'
   - Write all the retained thinking steps after <think>\n, preserving the original format of two newlines (\\n\\n) after each step.
   - End the thinking part with: '</think>\n'
   - After '</think>\n', write exactly the same final solution as the original input, with exactly the same format.

"""

'''
def extract_and_replace_thought(original_value, new_assistant_output):
    """
    Replaces the entire assistant message with the new assistant output,
    then removes everything between <think> and </think> (including those tags).
    """
    # Remove <think>...</think> blocks, plus any trailing newline after </think>
    pattern = r"<think>.*?</think>\n?"
    cleaned_output = re.sub(pattern, "", new_assistant_output, flags=re.DOTALL, count=1)
    return cleaned_output
'''
def extract_and_replace_thought(original_value, new_assistant_output):
    """
    deepseek format expected:
      <think>
      COT of the model
      </think>
      <think>
      The summary of the reasoning process
      </think>
    """
    blocks = re.findall(r"<think>\n(.*?)</think>", new_assistant_output, flags=re.DOTALL)
    if len(blocks) >= 2:
        summary_block = f"<think>\n{blocks[1]}</think>"
        if re.search(r"<think>\n.*?</think>", original_value, flags=re.DOTALL):
            new_value = re.sub(r"<think>\n.*?</think>", summary_block, original_value, flags=re.DOTALL, count=1)
            return new_value
        else:
            return original_value + "\n" + summary_block
    else:
        return new_assistant_output

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="deal with dataset and summarize reasoning")
    parser.add_argument(
        "--input_dataset",
        type=str,
        default="secmlr/noisy_dataset_ds_correct_together-deepseek-reasoner_small_train_len_32000_inputlen_16000",
        help="load huggingface dataset"
    )
    parser.add_argument(
        "--output_folder",
        type=str,
        default="./summarization_dataset",
        help="output file folder"
    )
    parser.add_argument(
        "--output_file",
        type=str,
        default="summarized_dataset_dsr1_noisy_dataset_ds_correct_together-deepseek-reasoner_small_train_len_32000_inputlen_16000.json",
        help="output file name"
    )
    
    args = parser.parse_args()
    
    # create output folder if it doesn't exist
    os.makedirs(args.output_folder, exist_ok=True)
    output_file = os.path.join(args.output_folder, args.output_file)
    dataset = load_dataset(args.input_dataset)
    print(f"Loaded dataset: {args.input_dataset}")

    load_dotenv(os.path.join(PROJECT_PATH, ".env"))
    # dataset = load_dataset("secmlr/noisy_dataset_filtered_QwQ-32B-Preview_small_train_len_16000_inputlen_5000")
    # dataset = load_dataset("secmlr/clean_dataset_filtered_QwQ-32B-Preview_train_len_8000_inputlen_5000")
    # dataset = load_dataset("secmlr/noisy_dataset_ds_correct_together-deepseek-reasoner_small_train_len_32000_inputlen_16000")

    # Load existing processed data if available, otherwise initialize empty list.
    # output_file = "/scr/ruizhe/VulnScan-r0/datasets/summarization_dataset/summarized_dataset_dsr1_noisy_dataset_ds_correct_together-deepseek-reasoner_small_train_len_32000_inputlen_16000.json"
    if os.path.exists(output_file):
        with open(output_file, "rb") as f:
            output_data = orjson.loads(f.read())
    else:
        output_data = []
    
    # Create a set of existing idx values for quick lookup.
    existing_ids = set()
    for ex in output_data:
        idx = ex.get("idx")
        if idx is not None:
            existing_ids.add(idx)
    
    # Initialize a BPE tokenizer (using GPT-2)
    tokenizer = AutoTokenizer.from_pretrained("gpt2")
    
    # Instantiate the client (using Together as in your code)
    client = Together()
    
    for example in dataset["train"]:
        try:
            current_idx = example.get("idx")
            if current_idx in existing_ids:
                print(f"Skipping example with idx {current_idx} (already processed).")
                continue  # Skip current example
            
            # Retain original fields
            new_example = {
                "system": example["system"],
                "idx": current_idx,
                "cwe": example["cwe"],
                "conversations": []
            }
    
            for conv in example["conversations"]:
                if conv["from"] == "user":
                    new_example["conversations"].append(conv)
                    continue
    
                if conv["from"] == "assistant":
                    original_value = conv["value"]
    
                    # Extract the chain-of-thought portion for token count check
                    thought_match = re.search(
                        # r"<\|begin_of_thought\|>\n\n(.*?)<\|end_of_thought\|>\n\n",
                        r"<think>\n(.*?)</think>",
                        original_value,
                        re.DOTALL
                    )
    
                    if thought_match:
                        old_thought = thought_match.group(1)
                        old_tokens = tokenizer.encode(old_thought, add_special_tokens=False)
                        old_token_count = len(old_tokens)
    
                        #if old_token_count > 2000:
                        if old_token_count > 0:
                            chat_completion = client.chat.completions.create(
                                messages=[
                                    {"role": "system", "content": system_prompt},
                                    {"role": "user", "content": original_value}
                                ],
                                model="deepseek-ai/DeepSeek-R1"
                            )
                            new_assistant_output = chat_completion.choices[0].message.content
    
                            new_value = extract_and_replace_thought(original_value, new_assistant_output)
    
                            # Optionally, check token count after transformation
                            new_thought_match = re.search(
                                # r"<\|begin_of_thought\|>\n\n(.*?)<\|end_of_thought\|>\n\n",
                                r"<think>\n(.*?)</think>",
                                new_value,
                                re.DOTALL
                            )
                            if new_thought_match:
                                new_thought = new_thought_match.group(1)
                                new_tokens = tokenizer.encode(new_thought, add_special_tokens=False)
                                new_token_count = len(new_tokens)
                                reduction = old_token_count - new_token_count
                                print(f"Example {current_idx} - Thought token count reduced by {reduction} "
                                      f"(old: {old_token_count}, new: {new_token_count})")
                        else:
                            new_value = original_value
                    else:
                        new_value = original_value
    
                    new_conv = {
                        "from": "assistant",
                        "value": new_value
                    }
                    new_example["conversations"].append(new_conv)
                else:
                    new_example["conversations"].append(conv)
    
            output_data.append(new_example)
            existing_ids.add(current_idx)  # update the set with the new idx
    
            # Save progress after each processed example
            with open(output_file, "wb") as f:
                f.write(orjson.dumps(output_data, option=orjson.OPT_INDENT_2))
    
        except Exception as e:
            print(f"Error processing example {example['idx']}: {str(e)}")
            output_data.append(example)
            with open(output_file, "wb") as f:
                f.write(orjson.dumps(output_data, option=orjson.OPT_INDENT_2))
    
    # Final save
    with open(output_file, "wb") as f:
        f.write(orjson.dumps(output_data, option=orjson.OPT_INDENT_2))
