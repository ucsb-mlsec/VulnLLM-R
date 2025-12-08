import asyncio
import logging
from typing import Any
import orjson
import re
from tqdm.asyncio import tqdm_asyncio
from vulscan.test.test_utils.utils import calculate_score

logger = logging.getLogger(__name__)


async def chat_function(chat, model, messages, temperature=0, top_p=1.0, max_tokens=256):
    for i in range(5):
        try:
            if "claude" in model:
                system_message = [m["content"] for m in messages if m["role"] == "system"]
                system_message = system_message[0] if system_message else ""
                user_messages = [m for m in messages if m["role"] != "system"]
                ret = await chat(model=model, system=system_message, messages=user_messages,
                                 temperature=temperature, max_tokens=max_tokens, top_p=top_p)
            elif "o3" in model:
                ret = await chat(model=model, messages=messages, max_completion_tokens=max_tokens)
            elif "deepseek-reasoner" in model:
                ret = await chat(model=model, messages=messages, max_tokens=max_tokens)
            else:
                ret = await chat(model=model, messages=messages,
                                 temperature=temperature, top_p=top_p,
                                 max_tokens=max_tokens, seed=42)
            return ret
        except Exception as e:
            print(f"failed with error {e}, retrying")
            await asyncio.sleep(10)
    return None


async def openai_batch_async_chat_completion(messages_lst, client, model, limiter, max_tokens=1024):
    tasks = [rate_limited_api_call_precise(limiter, m, model, client.chat.completions.create, max_tokens=max_tokens)
             for m in messages_lst]
    return await tqdm_asyncio.gather(*tasks)


async def claude_batch_async_chat_completion(messages_lst, client, model, limiter, max_tokens=1024):
    tasks = [rate_limited_api_call_precise(limiter, m, model, client.messages.create, max_tokens=max_tokens)
             for m in messages_lst]
    return await tqdm_asyncio.gather(*tasks)


async def rate_limited_api_call_precise(limiter, messages, model, llm_func, max_tokens=1024):
    async with limiter:
        return await chat_function(chat=llm_func, model=model, messages=messages,
                                   max_tokens=max_tokens, temperature=0, top_p=1.0)


def check_single_cwe(text):
    return len(re.findall(r"CWE-\d+", text)) == 1


def check_each_data(pred: str, gold: str):
    pred_score, pred_vul = extract_answer(pred)
    true_score, true_vul_type = extract_answer(gold)
    return check_pred_cwe_correctness(pred_score, pred_vul, true_score, true_vul_type)


def check_pred_cwe_correctness(pred_score, pred_vul_type, true_score, true_vul_type):
    if pred_score == "yes" and true_score == "yes":
        return check_single_cwe(pred_vul_type) and (
            pred_vul_type in true_vul_type or true_vul_type in pred_vul_type
        )
    elif pred_score == "no" and true_score == "no":
        return True
    return False


def extract_answer(output):
    output = output.split("## Final Answer")[-1].lower()
    pred_score, pred_vul_type = "", ""
    try:
        pred_score = output.split("#judge: ")[1].split("#type: ")[0].strip()
        pred_vul_type = output.split("#type: ")[1].split("\n")[0].strip()
    except IndexError:
        if "judge:" in output and "type:" in output:
            pred_score = output.split("judge:")[1].split("\n")[0].strip()
            pred_vul_type = output.split("type:")[1].split("\n")[0].strip()
        else:
            pred_score = "Invalid format"
    if "yes" in pred_score and "no" not in pred_score:
        pred_score = "yes"
    elif "no" in pred_score and "yes" not in pred_score:
        pred_score = "no"
    else:
        pred_score = "Invalid format"
    pred_vul_type = "N/A" if not pred_vul_type else pred_vul_type.upper()
    return pred_score, pred_vul_type


# ---- 修改点：去掉 majority vote ----
def run_default_model(model, eval_examples, max_tokens, n=1, system_prompt=None):
    return model.run(eval_examples=eval_examples, system_prompt=system_prompt,
                     max_tokens=max_tokens, n=n,
                     temperature=0 if n == 1 else 0.6, top_p=0.9)


def run_generate_model(model, eval_examples, max_tokens, n=1, system_prompt=None):
    return model.run(eval_examples=eval_examples, system_prompt=system_prompt,
                     max_tokens=max_tokens, n=n,
                     temperature=0 if n == 1 else 0.6, top_p=0.9)


def run_sft_model(model, eval_examples, max_tokens, n=1, system_prompt=None, fmt="sft", sampling_params2=None):
    temperature = 0 if n == 1 else 0.6
    top_p = 0.9
    kwargs = {}
    if "Qwen3" in model.model_name:
        kwargs = {"top_k": 20, "min_p": 0}
        temperature, top_p = 0.6, 0.95
    first_outputs, answers, latencies, completion_tokens = model.run(
        eval_examples=eval_examples, system_prompt=system_prompt,
        max_tokens=max_tokens, n=n, temperature=temperature, top_p=top_p,
        stop=["## Final Answer"], include_stop_str_in_output=True, **kwargs
    )
    new_eval_examples = []
    append_tokens = "\n<|end_of_thought|>\n<|begin_of_solution|>\n## Final Answer\n" if fmt == "sft" else "\n</think>\n## Final Answer\n"
    for i, item in enumerate(eval_examples):
        for j in range(n):
            mo = first_outputs[i][j]
            if "## Final Answer" not in mo:
                mo += append_tokens
            new_eval_examples.append({"input": item["input"], "output": item["output"], "assistant": mo})
    new_outputs, _, _, _ = model.run(eval_examples=new_eval_examples, system_prompt=system_prompt,
                                     max_tokens=200, n=1, temperature=temperature, top_p=top_p,
                                     continue_final_message=True, sampling_params2=sampling_params2, **kwargs)
    outputs = []
    for i in range(len(new_outputs)):
        if i % n == 0:
            outputs.append([])
        full_output = new_eval_examples[i]["assistant"] + new_outputs[i][0]
        outputs[-1].append(full_output)
    return outputs, answers, latencies, completion_tokens


def run_model(model, eval_examples, max_tokens, n=1, system_prompt=None, model_type="default", sampling_params2=None):
    if model_type == "default":
        outputs, answers, latencies, completion_tokens = run_default_model(model, eval_examples, max_tokens, n, system_prompt)
    elif model_type == "sft":
        outputs, answers, latencies, completion_tokens = run_sft_model(model, eval_examples, max_tokens, n, system_prompt, fmt="sft")
    elif model_type == "ds":
        outputs, answers, latencies, completion_tokens = run_sft_model(model, eval_examples, max_tokens, n, system_prompt, fmt="ds", sampling_params2=sampling_params2)
    elif model_type == "generate":
        outputs, answers, latencies, completion_tokens = run_generate_model(model, eval_examples, max_tokens, n, system_prompt)
    else:
        raise ValueError(f"Unsupported model_type {model_type}")

    # 不再挑选单一 best_output，直接返回全部 n 个回答
    return outputs, answers, latencies, completion_tokens


def evaluate_examples(model, eval_examples, use_wandb, max_tokens, system_prompt=None, n=1, model_type="default", sampling_params2=None):
    nums = len(eval_examples)
    max_tokens = max_tokens // n
    outputs, answers, latencies, completion_tokens = run_model(model, eval_examples, max_tokens, n, system_prompt, model_type, sampling_params2)

    save_output, tp, fp, fn, tn, wrong_num = [], 0, 0, 0, 0, 0
    is_aixcc = eval_examples[0]["dataset"] == "aixcc"

    for i, (pred_list, answer) in enumerate(zip(outputs, answers)):
        all_pred_info = []
        true_score = answer.split("#judge: ")[1].split()[0].strip()
        true_vul_type = answer.split("#type: ")[1].split()[0].strip()

        for pred in pred_list:
            pred_score, pred_vul = extract_answer(pred)
            all_pred_info.append({"pred_score": pred_score, "pred_vul": pred_vul, "raw": pred})

        # 默认取第一个回答统计 TP/FP（可改成更复杂策略）
        pred_score, pred_vul = all_pred_info[0]["pred_score"], all_pred_info[0]["pred_vul"]

        save_flag, is_wrong = "", False
        if pred_score == "invalid format":
            (fn if true_score == "yes" else fp).__iadd__(1)
            save_flag += "fn" if true_score == "yes" else "fp"
            wrong_num += 1
            is_wrong = True
        else:
            if pred_score == "yes" and true_score == "yes":
                if is_aixcc:
                    tp += 1; save_flag += "tp"
                elif not check_single_cwe(pred_vul):
                    fn += 1; wrong_num += 1; save_flag += "fn"; is_wrong = True
                elif pred_vul in true_vul_type or true_vul_type in pred_vul:
                    tp += 1; save_flag += "tp"
                else:
                    fn += 1; save_flag += "fn"
            elif pred_score == "yes" and true_score == "no":
                fp += 1; save_flag += "fp"
            elif pred_score == "no" and true_score == "yes":
                fn += 1; save_flag += "fn"
            elif pred_score == "no" and true_score == "no":
                tn += 1; save_flag += "tn"
            else:
                (fn if true_score == "yes" else fp).__iadd__(1)
                save_flag += "fn" if true_score == "yes" else "fp"
                wrong_num += 1; is_wrong = True

        save_output.append({
            "idx": eval_examples[i]["idx"], "dataset": eval_examples[i]["dataset"],
            "input": eval_examples[i]["input"], "output_all": all_pred_info,
            "true_score": true_score, "true_vul_type": true_vul_type,
            "flag": save_flag, "is_wrong": is_wrong,
            "latency": latencies[i] / nums, "completion_tokens": completion_tokens["output_token"][i]
        })

    result = calculate_score(tp, fp, fn, tn, nums, use_wandb, wrong_num)
    print(orjson.dumps(result, option=orjson.OPT_INDENT_2).decode())
    return result, save_output
