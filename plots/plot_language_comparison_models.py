from pathlib import Path
import argparse
import matplotlib.pyplot as plt
import orjson
import numpy as np
from collections import defaultdict

from vulscan.utils.project_info import PROJECT_PATH, parse_test_json_filename


def calculate_overall_f1_from_confusion_matrix(tp, tn, fp, fn):
    if tp + fp == 0:
        precision_pos = 0
    else:
        precision_pos = tp / (tp + fp)

    if tp + fn == 0:
        recall_pos = 0
    else:
        recall_pos = tp / (tp + fn)

    if precision_pos + recall_pos == 0:
        pos_F1 = 0
    else:
        pos_F1 = 2 * (precision_pos * recall_pos) / (precision_pos + recall_pos)

    if tn + fn == 0:
        neg_precision = 0
    else:
        neg_precision = tn / (tn + fn)

    if tn + fp == 0:
        neg_recall = 0
    else:
        neg_recall = tn / (tn + fp)

    if neg_precision + neg_recall == 0:
        neg_F1 = 0
    else:
        neg_F1 = 2 * (neg_precision * neg_recall) / (neg_precision + neg_recall)

    overall_F1 = (pos_F1 + neg_F1) / 2

    return overall_F1


def aggregate_results_for_model_and_language(model_files):
    """对一个模型的特定语言文件进行聚合计算F1 - 聚合混淆矩阵后按utils.py方式计算F1"""
    total_tp = 0
    total_tn = 0
    total_fp = 0
    total_fn = 0

    for file_path in model_files:
        with open(file_path, "rb") as f:
            json_data = orjson.loads(f.read())

        for item in json_data[1:]:
            flag = item.get("flag", "")
            if flag == "tp":
                total_tp += 1
            elif flag == "tn":
                total_tn += 1
            elif flag == "fp":
                total_fp += 1
            elif flag == "fn":
                total_fn += 1

    overall_f1 = calculate_overall_f1_from_confusion_matrix(
        total_tp, total_tn, total_fp, total_fn
    )

    print(f"    Aggregated: TP={total_tp}, TN={total_tn}, FP={total_fp}, FN={total_fn}")
    print(f"    Overall F1 = {overall_f1:.4f}")

    return overall_f1


def generate_colors(n):
    """Generate n distinct colors using a color palette."""
    base_colors = [
        "#FF6B6B",  # Red
        "#45B7D1",  # Blue
        "#96CEB4",  # Sage green
        "#4ECDC4",  # Teal
        "#DDA0DD",  # Purple
        "#95A5A6",  # Gray
        "#F39C12",  # Orange
        "#3498DB",  # Light blue
        "#E74C3C",  # Dark red
        "#2ECC71",  # Green
        "#9B59B6",  # Violet
        "#1ABC9C",  # Turquoise
        "#34495E",  # Dark gray
        "#F1C40F",  # Yellow
        "#E67E22",  # Dark orange
    ]
    # Cycle through colors if we need more
    return [base_colors[i % len(base_colors)] for i in range(n)]


def plot_language_comparison_models_only(results_dir: str = None):
    ROOT = Path(PROJECT_PATH) / "results"
    if results_dir:
        RESULTS_DIR = Path(results_dir)
    else:
        RESULTS_DIR = ROOT / Path("./test_data")
    PLOT_SAVE_DIR = Path("./results")
    PLOT_SAVE_DIR.mkdir(exist_ok=True, parents=True)
    save_name = "language_comparison_models.pdf"

    print(f"Reading results from: {RESULTS_DIR}")

    # Name mapping for display (optional - if not found, use original name)
    name_mapping = {
        "VulnLLM-R-7B": "VulnLLM-R-7B",
        "o3": "o3",
        "claude-3-7-sonnet-20250219": "Claude-3.7-Sonnet",
        "together-deepseek-reasoner": "DeepSeek-R1",
        "QwQ-32B": "QwQ-32B",
        "Qwen2.5-7B-Instruct": "Qwen2.5-7B",
    }

    languages = ["python", "c", "java"]

    # Collect data files, categorized by model and language
    # First pass: discover all models
    model_language_files = defaultdict(list)
    discovered_models = set()

    for json_file in RESULTS_DIR.glob("*.json"):
        # Skip unwanted files
        if (
            "ood" in json_file.name
            or "own_cot" in json_file.name
            or "DSFormat" in json_file.name
        ):
            continue

        data = parse_test_json_filename(json_file.name)
        if data["cot"] != "cot":
            continue
        if data["ood"] != "full":
            continue
        if data["n"] != "1":
            continue
        if data["seq_len"] != "8192":
            continue
        if data:
            model_name_parsed = data["model_shortname"]
            language = data["language"]

            if language in languages:
                key = (model_name_parsed, language)
                model_language_files[key].append(json_file)
                discovered_models.add(model_name_parsed)

    # Sort models alphabetically, but put VulnLLM-R-7B first if present
    all_models_orig = sorted(discovered_models)
    if "VulnLLM-R-7B" in all_models_orig:
        all_models_orig.remove("VulnLLM-R-7B")
        all_models_orig.insert(0, "VulnLLM-R-7B")

    # Map to display names
    all_models_display = [name_mapping.get(m, m) for m in all_models_orig]

    print(f"Discovered {len(all_models_orig)} models: {all_models_orig}")
    print(f"Display names: {all_models_display}")

    # Calculate F1 scores for each model-language combination
    results_data = {}

    # Process all discovered models
    for model_orig in all_models_orig:
        model_display = name_mapping.get(model_orig, model_orig)
        for language in languages:
            key = (model_orig, language)

            if key in model_language_files and model_language_files[key]:
                # Has actual data, perform aggregation
                f1_score = aggregate_results_for_model_and_language(
                    model_language_files[key]
                )
                print(
                    f"Model {model_display} ({model_orig}), Language {language}: {len(model_language_files[key])} files, F1 = {f1_score:.4f}"
                )
            else:
                # No data found for this language
                f1_score = 0.0
                print(
                    f"Model {model_display} ({model_orig}), Language {language}: No data files found, F1 = 0.0000"
                )

            results_data[(model_display, language)] = f1_score

    # Create single figure - adjust width based on number of models
    fig_width = max(10, 2 + len(all_models_orig) * 1.5)
    fig, ax = plt.subplots(figsize=(fig_width, 6), dpi=200)

    # Set background to pure white
    ax.set_facecolor('white')
    fig.patch.set_facecolor('white')

    # Generate colors dynamically
    model_colors = generate_colors(len(all_models_display))

    # Prepare data matrix
    data_matrix = []
    for model in all_models_display:
        model_scores = []
        for language in languages:
            score = results_data.get((model, language), 0.0)
            model_scores.append(score)
        data_matrix.append(model_scores)

    data_matrix = np.array(data_matrix)

    # Set bar parameters - adjust based on number of models
    num_models = len(all_models_display)
    bar_width = min(0.12, 0.8 / num_models)
    x_positions = np.arange(len(languages)) * (num_models * bar_width + 0.3)

    # Draw bars for each model
    bars_for_legend = []
    for i, model in enumerate(all_models_display):
        model_data = data_matrix[i]
        # Replace 0 values with a small value for visibility
        model_data_adjusted = np.where(model_data == 0, 0.01, model_data)

        # Special handling for VulnLLM-R-7B
        if model == "VulnLLM-R-7B":
            edge_width = 2.5
            alpha_val = 0.9
        else:
            edge_width = 1.5
            alpha_val = 0.85

        bars = ax.bar(
            x_positions + i * bar_width,
            model_data_adjusted,
            bar_width,
            label=model,
            color=model_colors[i],
            edgecolor="black",
            alpha=alpha_val,
            linewidth=edge_width,
        )
        bars_for_legend.append(bars[0])

    # Set chart properties
    ax.set_xlabel("Programming Language", fontsize=16, fontweight="bold")
    ax.set_ylabel("Overall F1 Score", fontsize=16, fontweight="bold")
    ax.set_title("Model Comparison", fontsize=20, fontweight="bold", pad=10)

    # Set x-axis labels
    ax.set_xticks(x_positions + bar_width * (num_models - 1) / 2)
    ax.set_xticklabels(languages, fontsize=12)

    # Set y-axis
    ax.set_ylim(0, 1.0)
    ax.tick_params(axis="y", labelsize=12)

    # Add grid
    ax.grid(True, alpha=0.25, axis="y", linestyle="--", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)

    # Add horizontal reference lines
    for y_val in [0.2, 0.4, 0.6, 0.8]:
        ax.axhline(
            y=y_val, color="gray", linestyle=":", alpha=0.3, linewidth=0.5, zorder=1
        )

    # Add legend - adjust position based on number of models
    if num_models > 8:
        ax.legend(
            bars_for_legend,
            all_models_display,
            loc="upper left",
            bbox_to_anchor=(1.02, 1),
            fontsize=9,
            frameon=True,
            fancybox=False,
            edgecolor="black",
            facecolor="white",
            borderpad=0.5,
            framealpha=0.95,
        )
    else:
        ax.legend(
            bars_for_legend,
            all_models_display,
            loc="upper right",
            fontsize=10,
            frameon=True,
            fancybox=False,
            edgecolor="black",
            facecolor="white",
            borderpad=0.5,
            framealpha=0.95,
        )

    # Set border style
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_linewidth(1.5)
    ax.spines["bottom"].set_linewidth(1.5)

    # Adjust layout
    plt.tight_layout()

    # Save figure
    plt.savefig(PLOT_SAVE_DIR / save_name, dpi=200, bbox_inches="tight")

    # Show figure
    plt.show()

    # Print results summary
    print("\n" + "="*100)
    print("Model Comparison Results Summary")
    print("="*100)
    print(f"{'Model':<25}", end="")
    for lang in languages:
        print(f"{lang.upper():<12}", end="")
    print()
    print("-"*80)

    for model in all_models_display:
        print(f"{model:<25}", end="")
        for language in languages:
            score = results_data.get((model, language), 0.0)
            print(f"{score:.4f}      ", end="")
        print()

    print("="*100)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot language comparison for all models")
    parser.add_argument(
        "--results-dir",
        type=str,
        default=None,
        help="Path to results directory containing JSON files (default: results/test_data)"
    )
    args = parser.parse_args()

    plot_language_comparison_models_only(results_dir=args.results_dir)
