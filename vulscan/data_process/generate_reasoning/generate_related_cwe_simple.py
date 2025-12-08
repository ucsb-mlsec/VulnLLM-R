import os
import sys
from typing import List, Dict, Any
import glob

import orjson
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
from tqdm import tqdm

from model_zoo import LiteLLMModel, VllmModel
from vulscan.utils.project_info import PROJECT_PATH
from vulscan.utils.sys_prompts import qwen_sys_prompt, deepseek_sys_prompt
from vulscan.test.test_utils.generation_utils import run_model


def create_related_cwe_prompt(code: str, language: str) -> str:
    prompt = f"""You are an expert in software security and vulnerability analysis. 
Your task is to analyze the given code snippet and identify all potentially related CWEs (Common Weakness Enumeration).

## Code Snippet:
```{language}
{code}
```

## Task:
Analyze this code and list all CWEs that could potentially be occurred in this code.
Consider:
1. Direct vulnerabilities that might exist in this specific code
2. Related vulnerability patterns that commonly co-occur with the code patterns shown

## Output Format:
Provide a JSON array of CWE IDs in the following format:
["CWE-XX", "CWE-YY", "CWE-ZZ"]

Include any potential related CWEs you identify (better less than 4 CWEs).
Only include the CWE IDs, no explanations needed.
"""
    return prompt


def parse_related_cwes(model_output: str) -> List[str]:
    """解析模型输出，提取CWE列表"""
    try:
        # 尝试找到JSON数组
        import re
        json_match = re.search(r'\[.*?]', model_output, re.DOTALL)
        if json_match:
            cwes = orjson.loads(json_match.group())
            # 验证格式
            if isinstance(cwes, list) and all(isinstance(cwe, str) and cwe.startswith("CWE-") for cwe in cwes):
                return cwes
    except:
        pass
    
    # 如果JSON解析失败，尝试正则匹配
    import re
    cwe_pattern = r'CWE-\d+'
    cwes = re.findall(cwe_pattern, model_output)
    return list(set(cwes))  # 去重


def load_dataset_files(dataset_dir: str, languages: List[str]) -> List[Dict[str, Any]]:
    all_data = []
    
    for lang in languages:
        lang_dir = os.path.join(dataset_dir, lang)
        if not os.path.exists(lang_dir):
            print(f"Warning: Language directory {lang_dir} does not exist")
            continue
            
        json_files = glob.glob(os.path.join(lang_dir, "*.json"))
        
        for json_file in json_files:
            with open(json_file, "rb") as f:
                data = orjson.loads(f.read())
                
            # 添加文件来源信息
            for item in data:
                item["source_file"] = json_file
                item["language"] = lang
                all_data.append(item)
    
    return all_data


def main():
    load_dotenv()
    
    # 命令行参数
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_name", type=str, required=True)
    parser.add_argument("--dataset_type", type=str, default="test/function_level")
    parser.add_argument("--languages", nargs="+", default=["c", "python", "java"])
    parser.add_argument("--batch_size", type=int, default=20)
    parser.add_argument("--max_tokens", type=int, default=2048)
    parser.add_argument("--server_url", type=str, default=None)
    parser.add_argument("--tp", type=int, default=2)
    parser.add_argument("--requests_per_minute", type=int, default=60)
    parser.add_argument("--only_vulnerable", action="store_true", help="Only process vulnerable samples")
    parser.add_argument("--output_dir", type=str, default=None)
    
    args = parser.parse_args()
    
    # 设置路径
    dataset_dir = os.path.join(PROJECT_PATH, "datasets", args.dataset_type)
    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = os.path.join(PROJECT_PATH, "datasets/related_cwe_data")
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    # 加载数据
    print(f"Loading data from {dataset_dir}")
    all_data = load_dataset_files(dataset_dir, args.languages)
    print(f"Loaded {len(all_data)} samples")
    
    # 过滤只处理有漏洞的样本
    if args.only_vulnerable:
        all_data = [item for item in all_data if item.get("target", 0) == 1]
        print(f"Filtered to {len(all_data)} vulnerable samples")
    
    # 准备输出文件
    short_model_name = args.model_name.split("/")[-1]
    output_filename = f"related_cwe_{short_model_name}_{args.dataset_type.replace('/', '_')}.json"
    if args.only_vulnerable:
        output_filename = output_filename.replace(".json", "_vulnerable_only.json")
    output_path = os.path.join(output_dir, output_filename)
    
    # 检查已有结果
    existing_results = {}
    if os.path.exists(output_path):
        with open(output_path, "rb") as f:
            existing_data = orjson.loads(f.read())
            existing_results = {item["idx"]: item for item in existing_data}
            print(f"Found {len(existing_results)} existing results")
    
    # 准备模型
    system_prompt = None
    if "deepseek" in args.model_name.lower():
        system_prompt = deepseek_sys_prompt
    elif "qwen" in args.model_name.lower() or "qwq" in args.model_name.lower():
        system_prompt = qwen_sys_prompt
    
    limiter = AsyncLimiter(args.requests_per_minute, 60)
    
    if "gpt" in args.model_name or "claude" in args.model_name:
        model = LiteLLMModel(model=args.model_name, limiter=limiter)
    elif args.server_url:
        model = LiteLLMModel(model=args.model_name, server_url=args.server_url, limiter=limiter)
    else:
        model = VllmModel(model=args.model_name, num_gpus=args.tp)
    
    # 批量处理
    results = []
    for i in tqdm(range(0, len(all_data), args.batch_size), desc="Processing batches"):
        batch = all_data[i:i+args.batch_size]
        
        # 跳过已处理的
        batch_to_process = []
        for item in batch:
            if item["idx"] not in existing_results:
                batch_to_process.append(item)
        
        if not batch_to_process:
            continue
        
        # 准备提示词
        prompts = []
        for item in batch_to_process:
            prompt = create_related_cwe_prompt(
                item["code"], 
                item["language"]
            )
            prompts.append({"prompt": prompt})
        
        # 运行模型
        _, _, _, _, full_outputs, _, _ = run_model(
            model,
            prompts,
            args.max_tokens,
            n=1,
            system_prompt=system_prompt,
            model_type="generate",
        )
        
        # 解析结果
        for item, output in zip(batch_to_process, full_outputs):
            related_cwes = parse_related_cwes(output)
            
            result = {
                "idx": item["idx"],
                "code": item["code"],
                "language": item["language"],
                "original_cwe": item.get("CWE_ID", []),
                "target": item.get("target", 0),
                "related_cwes": related_cwes,
                "model_output": output,
                "source_file": item["source_file"],
            }
            
            # 如果原始数据有RELATED_CWE字段
            if "RELATED_CWE" in item:
                result["ground_truth_related_cwes"] = item["RELATED_CWE"]
            
            results.append(result)
            existing_results[result["idx"]] = result
        
        # 定期保存
        if len(results) % 100 == 0:
            all_results = list(existing_results.values())
            all_results.sort(key=lambda x: x["idx"])
            
            with open(output_path, "wb") as f:
                f.write(orjson.dumps(all_results, option=orjson.OPT_INDENT_2))
    
    # 最终保存
    all_results = list(existing_results.values())
    all_results.sort(key=lambda x: x["idx"])
    
    with open(output_path, "wb") as f:
        f.write(orjson.dumps(all_results, option=orjson.OPT_INDENT_2))
    
    print(f"\nGeneration completed. Total results: {len(all_results)}")
    
    # 统计信息
    if all_results:
        avg_related_cwes = sum(len(r["related_cwes"]) for r in all_results) / len(all_results)
        print(f"Average related CWEs per sample: {avg_related_cwes:.2f}")
        
        # 如果有ground truth，计算准确率
        with_gt = [r for r in all_results if "ground_truth_related_cwes" in r]
        if with_gt:
            matches = 0
            for r in with_gt:
                pred_set = set(r["related_cwes"])
                gt_set = set(r["ground_truth_related_cwes"])
                if gt_set.issubset(pred_set):
                    matches += 1
            print(f"Ground truth coverage: {matches}/{len(with_gt)} ({matches/len(with_gt)*100:.1f}%)")


if __name__ == "__main__":
    main() 