import argparse
import os
import sys
import pandas as pd
from transformers import set_seed
from dotenv import load_dotenv
from vllm import SamplingParams

from model_zoo.vllm_model import VllmModel
from vulscan.test.test_utils.new_generation_utils import run_default_model
from vulscan.test.test_utils.utils import save_results
from vulscan.utils.project_info import PROJECT_PATH

# 手动导入 compute_score
sys.path.append("/scratch/yuzhou/ella_vul/VulnScan-r0/vulscan/rl_train/verl/verl/utils/reward_score")
from vd import compute_score


def set_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset_path", type=str, required=True)
    parser.add_argument("--output_dir", type=str, required=True)
    parser.add_argument("--model", type=str, required=True)
    parser.add_argument("--max_tokens", type=int, default=16384)
    parser.add_argument("--batch_size", type=int, default=4)
    parser.add_argument("--tp", type=int, default=1)
    parser.add_argument("--n", type=int, default=4, help="每题生成多少个回答")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--save", action="store_true")
    return parser.parse_args()


def main():
    load_dotenv()
    args = set_args()
    save_dir = os.path.join(PROJECT_PATH, args.output_dir)
    os.makedirs(save_dir, exist_ok=True)
    set_seed(args.seed)

    # 读取 Parquet 数据
    df = pd.read_parquet(args.dataset_path)

    eval_examples = [
        {
            "prompt": row["prompt"],
            "input": row["prompt"][0]["content"],
            "output": row["reward_model"]["ground_truth"],
            "idx": row["extra_info"]["idx"],
            "dataset": row["extra_info"].get("dataset", "unknown"),
        }
        for _, row in df.iterrows()
    ]

    # 初始化模型
    sampling_params = SamplingParams(
        max_tokens=args.max_tokens,
        temperature=0.6,
        top_p=0.95,
        top_k=20,
        min_p=0,
    )
    model = VllmModel(
        model=args.model,
        sampling_params=sampling_params,
        num_gpus=args.tp,
        seed=args.seed,
    )

    # 获取所有回答
    outputs, answers, latencies, completion_tokens = run_default_model(
        model, eval_examples, args.max_tokens, args.n, system_prompt=None
    )

    results_to_save = []
    kept_rows = []
    filtered_count = 0

    for i, ex in enumerate(eval_examples):
        answer_list = []
        for ans in outputs[i]:
            score_info = compute_score(ans, ex["output"])
            answer_list.append({
                "text": ans,
                "score": score_info["score"],
                "pred_score": score_info["pred_score"],
                "true_score": score_info["true_score"],
                "pred_vul": score_info["pred_vul_type"],
                "true_vul": score_info["true_vul_type"],
            })

        # 判断是否需要跳过
        all_one = all(ans["score"] == 1.0 for ans in answer_list)
        skipped = False
        if all_one:
            skipped = True
            filtered_count += 1
        else:
            kept_rows.append(df.iloc[i])

        results_to_save.append({
            "idx": ex["idx"],
            "dataset": ex["dataset"],
            "prompt": ex["prompt"],
            "answers": answer_list,
            "latency": latencies[i],
            "completion_tokens": completion_tokens["output_token"][i],
            "skipped": skipped
        })

    print(f"总样本: {len(eval_examples)} | 被跳过(全部1.0): {filtered_count} | 保留: {len(kept_rows)}")

    if args.save:
        # 保存完整 JSON（含 skipped 样本）
        json_path = os.path.join(save_dir, f"rl_eval_run_model_all_answers_n{args.n}.json")
        save_results(json_path, results_to_save)
        print(f"已保存完整评估结果到 {json_path} (含 skipped 样本)")

        # 保存 Parquet（只包含未 skipped 的样本）
        new_output_dir = "/scratch/yuzhou/ella_vul/VulnScan-r0/vulscan/rl_train/verl/recipe/vulscan_dapo/data"
        filtered_df = pd.DataFrame(kept_rows)
        parquet_path = os.path.join(new_output_dir, "filtered_dataset.parquet")
        filtered_df.to_parquet(parquet_path, index=False)
        print(f"已保存过滤后的训练数据集到 {parquet_path} (仅未 skipped)")

    # 打印前 2 条结果
    print("\nExample Outputs :(first 2 outputs)")
    for i in range(min(2, len(results_to_save))):
        r = results_to_save[i]
        status = "SKIPPED" if r["skipped"] else "KEPT"
        print(f"\n[Sample {i}] Idx: {r['idx']} | {status}")
        for j, ans in enumerate(r["answers"]):
            print(f"  Answer {j+1}: Score={ans['score']}, Text={ans['text'][:180]}")
        print("-" * 60)


if __name__ == "__main__":
    main()
