import os
import sys
from typing import List, Dict, Any

import orjson
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv

from model_zoo import LiteLLMModel, VllmModel
from vulscan.data_process.generate_reasoning.parser import (
    ArgumentGroup,
    ArgumentParser,
    CommonArgumentGroup,
)
from vulscan.test.test_utils.generation_utils import run_model
from vulscan.utils.project_info import PROJECT_PATH
from vulscan.utils.sys_prompts import qwen_sys_prompt, deepseek_sys_prompt


class GenerateRelatedCWEArgumentGroup(ArgumentGroup):
    def add_arguments(self, parser) -> None:
        parser.add_argument("--tp", type=int, default=2)
        parser.add_argument("--max_tokens", type=int, default=2048)
        parser.add_argument("--batch_size", type=int, default=50)
        parser.add_argument("--server_url", type=str, default=None)
        parser.add_argument("--together_deepseek", action="store_true", default=False)
        parser.add_argument("--n", type=int, default=1)
        parser.add_argument(
            "--requests_per_minute", type=int, default=60, help="requests per minute"
        )
        parser.add_argument(
            "--language",
            type=str,
            nargs="+",
            default=["c", "python", "java"],
            help="language of the dataset",
        )
        parser.add_argument(
            "--only_correct",
            action="store_true",
            default=False,
            help="Only process samples that were correctly predicted",
        )


def create_generate_parser():
    return ArgumentParser(CommonArgumentGroup(), GenerateRelatedCWEArgumentGroup())


def create_related_cwe_prompt(code: str, language: str) -> str:
    prompt = f"""You are an expert in software security and vulnerability analysis. 
Your task is to analyze the given code snippet and identify all potentially related CWEs (Common Weakness Enumeration).

## Code Language: {language}

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
"""
    return prompt


def parse_related_cwes(model_output: str) -> List[str]:
    """解析模型输出，提取CWE列表"""
    try:
        # 尝试找到JSON数组
        import re
        json_match = re.search(r'\[.*?\]', model_output, re.DOTALL)
        if json_match:
            cwes = orjson.loads(json_match.group())
            # 验证格式
            if isinstance(cwes, list) and all(isinstance(cwe, str) and cwe.startswith("CWE-") for cwe in cwes):
                return cwes
    except:
        pass
    
    # 如果JSON解析失败，尝试正则匹配
    cwe_pattern = r'CWE-\d+'
    cwes = re.findall(cwe_pattern, model_output)
    return list(set(cwes))  # 去重


def load_input_data(input_path: str, only_correct: bool = False) -> List[Dict[str, Any]]:
    """加载输入数据"""
    with open(input_path, "rb") as f:
        data = orjson.loads(f.read())
    
    # 如果第一个元素包含acc_num，则跳过
    if data and isinstance(data[0], dict) and "acc_num" in data[0]:
        data = data[1:]
    
    # 如果只处理正确的样本
    if only_correct:
        data = [item for item in data if item.get("correct", False)]
    
    return data


def generate_related_cwes(
    model_name: str,
    dataset_type: str,
    input_path: str,
    output_dir: str,
    server_url: str = None,
    tp: int = 2,
    max_tokens: int = 2048,
    batch_size: int = 50,
    n: int = 1,
    only_correct: bool = False,
    limiter: AsyncLimiter = None,
    together_deepseek: bool = False,
):
    """生成相关CWE的主函数"""
    # 准备输出路径
    short_model_name = model_name.split("/")[-1]
    output_filename = f"related_cwe_{short_model_name}.json"
    if only_correct:
        output_filename = f"related_cwe_{short_model_name}_correct_only.json"
    
    output_path = os.path.join(output_dir, dataset_type, output_filename)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # 加载数据
    print(f"Loading data from {input_path}")
    data = load_input_data(input_path, only_correct)
    print(f"Loaded {len(data)} samples")
    
    # 检查是否已有部分结果
    existing_results = {}
    if os.path.exists(output_path):
        with open(output_path, "rb") as f:
            existing_data = orjson.loads(f.read())
            existing_results = {item["idx"]: item for item in existing_data}
            print(f"Found {len(existing_results)} existing results")
    
    # 准备模型
    system_prompt = None
    if "deepseek" in model_name.lower():
        system_prompt = deepseek_sys_prompt
    elif "qwen" in model_name.lower() or "qwq" in model_name.lower():
        system_prompt = qwen_sys_prompt
    
    if "gpt" in model_name or "claude" in model_name or "deepseek-reasoner" in model_name:
        model = LiteLLMModel(
            model=model_name,
            limiter=limiter,
            together_deepseek=together_deepseek,
        )
    elif server_url:
        model = LiteLLMModel(
            model=model_name, 
            server_url=server_url, 
            limiter=limiter
        )
    else:
        model = VllmModel(model=model_name, num_gpus=tp)
    
    # 处理数据
    results = []
    for i in range(0, len(data), batch_size):
        batch = data[i:i+batch_size]
        
        # 跳过已处理的样本
        batch_to_process = []
        batch_indices = []
        for j, item in enumerate(batch):
            if item["idx"] not in existing_results:
                batch_to_process.append(item)
                batch_indices.append(i + j)
        
        if not batch_to_process:
            continue
        
        print(f"Processing batch {i//batch_size + 1}/{(len(data) + batch_size - 1)//batch_size}")
        
        # 准备提示词
        prompts = []
        for item in batch_to_process:
            prompt = create_related_cwe_prompt(item["code"], item["language"])
            prompts.append({"prompt": prompt})
        
        # 运行模型
        _, _, _, _, full_outputs, _, _ = run_model(
            model,
            prompts,
            max_tokens,
            n=n,
            system_prompt=system_prompt,
            model_type="generate",
        )
        
        # 解析结果
        for j, (item, output) in enumerate(zip(batch_to_process, full_outputs)):
            related_cwes = parse_related_cwes(output)
            
            result = {
                "idx": item["idx"],
                "code": item["code"],
                "language": item["language"],
                "original_cwe": item.get("CWE_ID", []),
                "predicted_cwe": item.get("model_vul_type", "N/A"),
                "related_cwes": related_cwes,
                "model_output": output,
                "correct": item.get("correct", False),
            }
            
            # 如果原始数据中有RELATED_CWE字段，也保存下来用于比较
            if "RELATED_CWE" in item:
                result["ground_truth_related_cwes"] = item["RELATED_CWE"]
            
            results.append(result)
            existing_results[result["idx"]] = result
        
        # 保存中间结果
        all_results = list(existing_results.values())
        all_results.sort(key=lambda x: x["idx"])
        
        with open(output_path, "wb") as f:
            f.write(orjson.dumps(all_results, option=orjson.OPT_INDENT_2))
        
        print(f"Saved {len(all_results)} results to {output_path}")
    
    print(f"Generation completed. Total results: {len(existing_results)}")
    
    # 计算一些统计信息
    if results:
        avg_related_cwes = sum(len(r["related_cwes"]) for r in results) / len(results)
        print(f"Average related CWEs per sample: {avg_related_cwes:.2f}")
        
        if only_correct:
            print(f"Processed {len(results)} correctly predicted samples")


if __name__ == "__main__":
    load_dotenv()
    
    parser = create_generate_parser()
    args = parser.parse_args()
    
    OUTPUT_DIR = os.path.join(PROJECT_PATH, "datasets/related_cwe_data")
    
    if args.input_path:
        input_path = args.input_path
    else:
        input_path = os.path.join(
            PROJECT_PATH, 
            f"datasets/reasoning_data/{args.dataset_type}",
            f"{args.model_name.split('/')[-1]}_{args.training_set}.json"
        )
    
    # 创建限流器
    limiter = AsyncLimiter(args.requests_per_minute, 60)
    
    # 生成相关CWE
    generate_related_cwes(
        model_name=args.model_name,
        dataset_type=args.dataset_type,
        input_path=input_path,
        output_dir=OUTPUT_DIR,
        server_url=args.server_url,
        tp=args.tp,
        max_tokens=args.max_tokens,
        batch_size=args.batch_size,
        n=args.n,
        only_correct=args.only_correct,
        limiter=limiter,
        together_deepseek=args.together_deepseek,
    ) 