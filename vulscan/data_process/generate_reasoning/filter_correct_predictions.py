import os
import sys
from typing import List, Dict, Any
import argparse

import orjson
from dotenv import load_dotenv

from vulscan.utils.project_info import PROJECT_PATH


def load_reasoning_results(file_path: str) -> List[Dict[str, Any]]:
    """加载推理结果数据"""
    with open(file_path, "rb") as f:
        data = orjson.loads(f.read())
    
    # 如果第一个元素包含acc_num，则跳过
    if data and isinstance(data[0], dict) and "acc_num" in data[0]:
        acc_info = data[0]
        data = data[1:]
        print(f"Accuracy: {acc_info['acc_num']}/{len(data)} = {acc_info['acc_num']/len(data)*100:.2f}%")
    
    return data


def filter_correct_predictions(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """筛选模型判断正确的数据"""
    correct_data = [item for item in data if item.get("correct", False)]
    print(f"Filtered {len(correct_data)} correct predictions from {len(data)} total samples")
    return correct_data


def create_training_data(
    correct_data: List[Dict[str, Any]], 
    output_format: str = "sft"
) -> List[Dict[str, Any]]:
    """将正确预测的数据转换为训练格式"""
    training_data = []
    
    for item in correct_data:
        if output_format == "sft":
            # SFT格式：包含完整的推理过程
            training_item = {
                "idx": item["idx"],
                "code": item["code"],
                "language": item["language"],
                "cwe_id": item.get("CWE_ID", []),
                "target": item["target"],
                "prompt": item["prompt"],
                "reasoning": item["model_reasoning"],
                "answer": item["model_answer"],
                "predicted_cwe": item["model_vul_type"],
            }
            
            # 如果有相关CWE信息，也加入
            if "RELATED_CWE" in item:
                training_item["related_cwes"] = item["RELATED_CWE"]
                
        elif output_format == "dpo":
            # DPO格式：需要正例和负例
            # 这里只处理正例，负例需要另外生成
            training_item = {
                "idx": item["idx"],
                "prompt": item["prompt"],
                "chosen": item["model_reasoning"],
                "rejected": None,  # 需要后续填充
            }
            
        elif output_format == "related_cwe":
            # 用于训练相关CWE预测的格式
            training_item = {
                "idx": item["idx"],
                "code": item["code"],
                "language": item["language"],
                "primary_cwe": item.get("CWE_ID", []),
                "related_cwes": item.get("RELATED_CWE", []),
                "reasoning": item["model_reasoning"],
            }
        
        training_data.append(training_item)
    
    return training_data


def analyze_cwe_distribution(data: List[Dict[str, Any]]) -> Dict[str, int]:
    """分析CWE分布"""
    cwe_counts = {}
    
    for item in data:
        cwes = item.get("CWE_ID", [])
        for cwe in cwes:
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    
    # 按频率排序
    sorted_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)
    
    print("\nCWE Distribution:")
    print("-" * 40)
    for cwe, count in sorted_cwes[:20]:  # 只显示前20个
        print(f"{cwe}: {count}")
    
    return dict(sorted_cwes)


def main():
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Filter and process correct predictions")
    parser.add_argument("--input_file", type=str, required=True, help="Input reasoning results file")
    parser.add_argument("--output_dir", type=str, default=None, help="Output directory")
    parser.add_argument("--output_format", type=str, choices=["sft", "dpo", "related_cwe", "raw"], 
                       default="sft", help="Output format for training data")
    parser.add_argument("--analyze_only", action="store_true", help="Only analyze data without saving")
    parser.add_argument("--min_reasoning_length", type=int, default=100, 
                       help="Minimum reasoning length to include")
    parser.add_argument("--languages", nargs="+", default=None, 
                       help="Filter by programming languages")
    
    args = parser.parse_args()
    
    # 加载数据
    print(f"Loading data from {args.input_file}")
    data = load_reasoning_results(args.input_file)
    
    # 筛选正确的预测
    correct_data = filter_correct_predictions(data)
    
    # 按语言筛选
    if args.languages:
        correct_data = [
            item for item in correct_data 
            if item.get("language", "").lower() in [lang.lower() for lang in args.languages]
        ]
        print(f"Filtered to {len(correct_data)} samples for languages: {args.languages}")
    
    # 按推理长度筛选
    if args.min_reasoning_length > 0:
        correct_data = [
            item for item in correct_data 
            if len(item.get("model_reasoning", "")) >= args.min_reasoning_length
        ]
        print(f"Filtered to {len(correct_data)} samples with reasoning length >= {args.min_reasoning_length}")
    
    # 分析CWE分布
    cwe_distribution = analyze_cwe_distribution(correct_data)
    
    # 如果只是分析，到此结束
    if args.analyze_only:
        return
    
    # 转换为训练格式
    if args.output_format != "raw":
        training_data = create_training_data(correct_data, args.output_format)
    else:
        training_data = correct_data
    
    # 保存结果
    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = os.path.join(PROJECT_PATH, "datasets/filtered_data")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # 生成输出文件名
    base_name = os.path.basename(args.input_file).replace(".json", "")
    output_filename = f"{base_name}_correct_{args.output_format}.json"
    output_path = os.path.join(output_dir, output_filename)
    
    # 保存数据
    with open(output_path, "wb") as f:
        f.write(orjson.dumps(training_data, option=orjson.OPT_INDENT_2))
    
    print(f"\nSaved {len(training_data)} training samples to {output_path}")
    
    # 保存统计信息
    stats = {
        "total_samples": len(data),
        "correct_samples": len(correct_data),
        "filtered_samples": len(training_data),
        "accuracy": len(correct_data) / len(data) * 100,
        "cwe_distribution": cwe_distribution,
        "languages": list(set(item.get("language", "") for item in training_data)),
    }
    
    stats_path = output_path.replace(".json", "_stats.json")
    with open(stats_path, "wb") as f:
        f.write(orjson.dumps(stats, option=orjson.OPT_INDENT_2))
    
    print(f"Saved statistics to {stats_path}")


if __name__ == "__main__":
    main() 