import asyncio
import logging
from typing import Any

import orjson
import re
from tqdm.asyncio import tqdm_asyncio

from vulscan.test.test_utils.utils import calculate_score

logger = logging.getLogger(__name__)


async def chat_function(
    chat, model, messages, temperature=0, top_p=1.0, max_tokens=256
):
    for i in range(5):
        # sleep for a while to avoid rate limit
        try:
            if "claude" in model:
                # extract system message
                system_message = [
                    message["content"]
                    for message in messages
                    if message["role"] == "system"
                ]
                system_message = system_message[0] if system_message else ""
                user_messages = [
                    message for message in messages if message["role"] != "system"
                ]
                ret = await chat(
                    model=model,
                    system=system_message,
                    messages=user_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    top_p=top_p,
                )
            elif "o3" in model:
                ret = await chat(
                    model=model, messages=messages, max_completion_tokens=max_tokens
                )
            elif "deepseek-reasoner" in model:
                ret = await chat(model=model, messages=messages, max_tokens=max_tokens)
            else:
                ret = await chat(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    top_p=top_p,
                    max_tokens=max_tokens,
                    seed=42,
                )
            return ret
        except Exception as e:
            print(f"failed with error {e}, retrying")
            await asyncio.sleep(10)
            continue
    return None


async def openai_batch_async_chat_completion(
    messages_lst: list[list[dict[str, str]]],
    client,
    model,
    limiter,
    max_tokens: int | None = 1024,
) -> tuple[Any]:
    tasks = [
        rate_limited_api_call_precise(
            limiter,
            messages,
            model,
            client.chat.completions.create,
            max_tokens=max_tokens,
        )
        for messages in messages_lst
    ]
    return await tqdm_asyncio.gather(*tasks)


async def claude_batch_async_chat_completion(
    messages_lst: list[list[dict[str, str]]], client, model, limiter, max_tokens=1024
) -> tuple[Any]:
    tasks = [
        rate_limited_api_call_precise(
            limiter, messages, model, client.messages.create, max_tokens=max_tokens
        )
        for messages in messages_lst
    ]
    return await tqdm_asyncio.gather(*tasks)


async def rate_limited_api_call_precise(
    limiter, messages, model, llm_func, max_tokens=1024
):
    async with limiter:
        return await chat_function(
            chat=llm_func,
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=0,
            top_p=1.0,
        )


def check_single_cwe(text):
    matches = re.findall(r"CWE-\d+", text)
    if len(matches) == 1:
        return True
    return None


def check_each_data(pred: str, gold: str):
    pred_score, pred_vul = extract_answer(pred)
    true_score, true_vul_type = extract_answer(gold)
    ret = check_pred_cwe_correctness(pred_score, pred_vul, true_score, true_vul_type)
    return ret


def check_pred_cwe_correctness(pred_score, pred_vul_type, true_score, true_vul_type):
    if pred_score == "yes" and true_score == "yes":
        if check_single_cwe(pred_vul_type) and (
            pred_vul_type in true_vul_type or true_vul_type in pred_vul_type
        ):
            return True
    elif pred_score == "no" and true_score == "no":
        return True
    return False


def extract_answer(output):
    output = output.split("## Final Answer")[-1]
    output = output.lower()
    pred_score = ""
    pred_vul_type = ""
    try:
        pred_score = output.split("#judge: ")[1].split("#type: ")[0].strip()
        pred_vul_type = output.split("#type: ")[1].split("\n")[0].strip()
    except IndexError:
        if "judge:" in output and "type:" in output:
            pred_score = output.split("judge:")[1].split("\n")[0].strip()
            pred_vul_type = output.split("type:")[1].split("\n")[0].strip()
        else:
            pred_score = "Invalid format"
    finally:
        if "yes" in pred_score and "no" not in pred_score:
            pred_score = "yes"
        elif "no" in pred_score and "yes" not in pred_score:
            pred_score = "no"
        else:
            logger.debug("Error detected in output:")
            logger.debug(output)
            pred_score = "Invalid format"
        pred_vul_type = "N/A" if not pred_vul_type else pred_vul_type.upper()
    return pred_score, pred_vul_type


def majority_vote(pred_scores):
    vote = {"yes": 0, "no": 0, "Invalid format": 0}
    vul_types = {}
    preds_by_answer = {"yes": [], "no": [], "Invalid format": []}
    best_output = pred_scores[0]
    for pred in pred_scores:
        pred_score, pred_vul_type = extract_answer(pred)
        vote[pred_score] += 1
        preds_by_answer[pred_score].append(pred)

        if pred_score == "yes":
            if pred_vul_type in vul_types:
                vul_types[pred_vul_type] += 1
            else:
                vul_types[pred_vul_type] = 1

    if vote["yes"] > vote["no"]:
        # find the most common vul type
        if vul_types:
            max_count = 0
            best_vul_type = ""
            for vul_type, count in vul_types.items():
                if count > max_count:
                    max_count = count
                    best_vul_type = vul_type

            # find the first "yes" with the best vul type
            for pred in preds_by_answer["yes"]:
                _, pred_vul = extract_answer(pred)
                if pred_vul == best_vul_type:
                    best_output = pred
                    break
        else:
            # if no vul type, return the first "yes"
            best_output = preds_by_answer["yes"][0] if preds_by_answer["yes"] else "yes"

    elif vote["yes"] < vote["no"]:
        # return the first "no"
        best_output = preds_by_answer["no"][0] if preds_by_answer["no"] else "no"

    else:
        if preds_by_answer["yes"]:
            best_output = preds_by_answer["yes"][0]
        elif preds_by_answer["no"]:
            best_output = preds_by_answer["no"][0]

    return [best_output]


def run_default_model(model, eval_examples, max_tokens, n=1, system_prompt=None):
    outputs, answers, latencies, completion_tokens = model.run(
        eval_examples=eval_examples,
        system_prompt=system_prompt,
        max_tokens=max_tokens,
        n=n,
        temperature=0 if n == 1 else 0.6,
        top_p=0.9,
    )
    # do majority vote
    if n > 1:
        new_outputs = []
        for i in range(len(outputs)):
            new_outputs.append(majority_vote(outputs[i]))
        outputs = new_outputs
    return outputs, answers, latencies, completion_tokens


def run_generate_model(model, eval_examples, max_tokens, n=1, system_prompt=None):
    outputs, answers, latencies, completion_tokens = model.run(
        eval_examples=eval_examples,
        system_prompt=system_prompt,
        max_tokens=max_tokens,
        n=n,
        temperature=0 if n == 1 else 0.6,
        top_p=0.9,
    )
    return outputs, answers, latencies, completion_tokens


def run_sft_model(
    model,
    eval_examples,
    max_tokens,
    n=1,
    system_prompt=None,
    fmt="sft",
    sampling_params2=None,
):
    temperature = 0 if n == 1 else 0.6
    top_p = 0.9
    kwargs = {}
    if "Qwen3" in model.model_name:
        kwargs = {
            "top_k": 20,
            "min_p": 0,
        }
        temperature = 0.6
        top_p = 0.95
    first_outputs, answers, latencies, completion_tokens = model.run(
        eval_examples=eval_examples,
        system_prompt=system_prompt,
        max_tokens=max_tokens,
        n=n,
        temperature=temperature,
        top_p=top_p,
        stop=["## Final Answer"],
        include_stop_str_in_output=True,
        **kwargs,
    )
    # generate again with ## Final Answer
    new_eval_examples = []
    if fmt == "sft":
        append_tokens = "\n<|end_of_thought|>\n<|begin_of_solution|>\n## Final Answer\n"
    elif fmt == "ds":
        append_tokens = "\n</think>\n## Final Answer\n"
    else:
        raise ValueError(f"format {fmt} is not supported")
    for i, item in enumerate(eval_examples):
        for j in range(n):
            model_output = first_outputs[i][j]
            if "## Final Answer" not in model_output:
                model_output += append_tokens

            new_item = {
                "input": item["input"],
                "output": item["output"],
                "assistant": model_output,
            }
            new_eval_examples.append(new_item)
    new_outputs, _, _, _ = model.run(
        eval_examples=new_eval_examples,
        system_prompt=system_prompt,
        max_tokens=200,
        n=1,
        temperature=temperature,
        top_p=top_p,
        continue_final_message=True,
        sampling_params2=sampling_params2,
        **kwargs,
    )
    # convert back to original format
    outputs = []
    for i in range(len(new_outputs)):
        if i % n == 0:
            outputs.append([])
        full_output = new_eval_examples[i]["assistant"] + new_outputs[i][0]
        outputs[-1].append(full_output)
        # do majority vote
    if n > 1:
        new_outputs = []
        for i in range(len(outputs)):
            new_outputs.append(majority_vote(outputs[i]))
        outputs = new_outputs
    return outputs, answers, latencies, completion_tokens


def run_model(
    model,
    eval_examples,
    max_tokens,
    n=1,
    system_prompt=None,
    model_type="default",
    sampling_params2=None,
):
    # model.run with a parameter n -> random sample n times
    # vllm auto adjust batch size
    if model_type == "default":
        outputs, answers, latencies, completion_tokens = run_default_model(
            model, eval_examples, max_tokens, n, system_prompt
        )
    elif model_type == "sft":
        outputs, answers, latencies, completion_tokens = run_sft_model(
            model, eval_examples, max_tokens, n, system_prompt, fmt="sft"
        )
    elif model_type == "ds":
        outputs, answers, latencies, completion_tokens = run_sft_model(
            model,
            eval_examples,
            max_tokens,
            n,
            system_prompt,
            fmt="ds",
            sampling_params2=sampling_params2,
        )
    elif model_type == "generate":
        outputs, answers, latencies, completion_tokens = run_generate_model(
            model, eval_examples, max_tokens, n, system_prompt
        )
    else:
        raise ValueError(f"model type {model_type} is not supported")
    pred_scores, true_scores, pred_vul_types, true_vul_types = [], [], [], []
    best_outputs = []
    final_latencies = []
    final_completion_tokens = []
    # support multiple answers
    for output, answer, latency, completion_token in zip(
        outputs, answers, latencies, completion_tokens["output_token"]
    ):
        candidate_answer = output[0]
        true_score = answer.split("#judge: ")[1].split()[0].strip()
        true_vul_type = answer.split("#type: ")[1].split()[0].strip()
        if not candidate_answer:
            candidate_answer = "Invalid format"
            best_pred_score = "Invalid format"
            best_pred_vul = "N/A"
        else:
            best_pred_score, best_pred_vul = extract_answer(output[0])
        # find the best answer
        min_both_correct_length = float(
            "inf"
        )  # TODO: should you initialize it as the length of the answer[0]?
        # find the best answer with both correct score and vul type
        min_score_correct_length = float("inf")
        for i in range(1, len(output)):
            pred_score, pred_vul = extract_answer(output[i])
            current_length = len(output[i])
            # check if the answer is correct
            if check_pred_cwe_correctness(
                pred_score, pred_vul, true_score, true_vul_type
            ):
                if current_length < min_both_correct_length:
                    min_both_correct_length = current_length
                    candidate_answer = output[i]
                    best_pred_score = pred_score
                    best_pred_vul = pred_vul
            # check if the answer has correct score
            elif pred_score == true_score and min_both_correct_length == float("inf"):
                if current_length < min_score_correct_length:
                    min_score_correct_length = current_length
                    # update the best answer
                    candidate_answer = output[i]
                    best_pred_score = pred_score
                    best_pred_vul = pred_vul

        best_outputs.append(candidate_answer)
        pred_scores.append(best_pred_score)
        true_scores.append(true_score)
        pred_vul_types.append(best_pred_vul)
        true_vul_types.append(true_vul_type)
        final_latencies.append(latency)
        final_completion_tokens.append(completion_token)
    return (
        pred_scores,
        true_scores,
        pred_vul_types,
        true_vul_types,
        best_outputs,
        final_latencies,
        final_completion_tokens,
    )


def evaluate_examples(
    model,
    eval_examples,
    use_wandb,
    max_tokens,
    system_prompt=None,
    n=1,
    model_type="default",
    sampling_params2=None,
):
    save_output = []
    fp = 0
    fn = 0
    tp = 0
    tn = 0
    nums = len(eval_examples)
    is_aixcc = eval_examples[0]["dataset"] == "aixcc"
    wrong_num = 0
    # align max tokens
    max_tokens = max_tokens // n
    (
        pred_score,
        true_score,
        pred_vul_type,
        true_vul_type,
        full_outputs,
        latencies,
        completion_tokens,
    ) = run_model(
        model,
        eval_examples,
        max_tokens,
        system_prompt=system_prompt,
        n=n,
        model_type=model_type,
        sampling_params2=sampling_params2,
    )
    for i in range(nums):
        save_flag = ""
        is_wrong = False
        pred = pred_score[i].lower()
        if pred == "invalid format":
            if true_score[i] == "yes":
                fn += 1
                save_flag += "fn"
            else:
                fp += 1
                save_flag += "fp"
            wrong_num += 1
            is_wrong = True
        else:
            # remove space
            pred = pred.replace(" ", "")
            # calculate false positive and false negative
            # calculate accuracy
            if pred == "yes" and true_score[i] == "yes":
                if is_aixcc:
                    tp += 1
                    save_flag += "tp"
                else:
                    if not check_single_cwe(pred_vul_type[i]):
                        fn += 1
                        wrong_num += 1
                        save_flag += "fn"
                        is_wrong = True
                    elif (
                        pred_vul_type[i] in true_vul_type[i]
                        or true_vul_type[i] in pred_vul_type[i]
                    ):
                        tp += 1
                        save_flag += "tp"
                    else:
                        fn += 1
                        save_flag += "fn"
            elif pred == "yes" and true_score[i] == "no":
                fp += 1
                save_flag += "fp"
            elif pred == "no" and true_score[i] == "yes":
                fn += 1
                save_flag += "fn"
            elif pred == "no" and true_score[i] == "no":
                tn += 1
                save_flag += "tn"
            else:
                logger.debug(f"wrong score detected in {i}th example")
                if true_score[i] == "yes":
                    fn += 1
                    save_flag += "fn"
                else:
                    fp += 1
                    save_flag += "fp"
                wrong_num += 1
                is_wrong = True

        save_output.append(
            {
                "input": eval_examples[i]["input"],
                "output": full_outputs[i],
                "is_vulnerable": true_score[i],
                "predicted_is_vulnerable": pred_score[i],
                "vulnerability_type": true_vul_type[i],
                "original_vulnerability_type": eval_examples[i]["cwe"],
                "predicted_vulnerability_type": pred_vul_type[i],
                "flag": save_flag,
                "is_wrong": is_wrong,
                "idx": eval_examples[i]["idx"],
                "dataset": eval_examples[i]["dataset"],
                # we need latency and completion tokens
                "latency": latencies[i] / nums,
                "completion_tokens": completion_tokens[i],
            }
        )
    result = calculate_score(tp, fp, fn, tn, nums, use_wandb, wrong_num)
    print(orjson.dumps(result, option=orjson.OPT_INDENT_2).decode())

    print("wrong: {}".format(result["wrong_num"]))
    print("fpr: {:.3f}".format(result["false_positive_rate"]))
    print("fnr: {:.3f}".format(result["false_negative_rate"]))
    print("Vul F1: {:.3f}".format(result["positive F1"]))
    print("Benign F1: {:.3f}".format(result["negative F1"]))
    print("Overall F1: {:.3f}".format(result["overall F1"]))
    print("Latency: {:.3f}".format(latencies[-1] / nums))
    return result, save_output
