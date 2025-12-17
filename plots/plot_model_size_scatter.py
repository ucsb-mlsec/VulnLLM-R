from pathlib import Path
import argparse
import matplotlib.pyplot as plt
import numpy as np
import orjson
import pandas as pd
from collections import defaultdict

from adjustText import adjust_text
from matplotlib.path import get_path_collection_extents

from vulscan.utils.project_info import PROJECT_PATH, parse_test_json_filename


def get_bounding_boxes_scatter_plot(sc, ax):
    """Function to return a list of bounding boxes in data coordinates
    for a scatter plot
    https://stackoverflow.com/a/55007838/3502079
    """
    ax.figure.canvas.draw()  # need to draw before the transforms are set.
    transform = sc.get_transform()
    transOffset = sc.get_offset_transform()
    offsets = sc._offsets
    paths = sc.get_paths()
    transforms = sc.get_transforms()

    if not transform.is_affine:
        paths = [transform.transform_path_non_affine(p) for p in paths]
        transform = transform.get_affine()
    if not transOffset.is_affine:
        offsets = transOffset.transform_non_affine(offsets)
        transOffset = transOffset.get_affine()

    if isinstance(offsets, np.ma.MaskedArray):
        offsets = offsets.filled(np.nan)

    bboxes = []

    if len(paths) and len(offsets):
        if len(paths) < len(offsets):
            # for usual scatters you have one path, but several offsets
            paths = [paths[0]] * len(offsets)
        if len(transforms) < len(offsets):
            # often you may have a single scatter size, but several offsets
            transforms = [transforms[0]] * len(offsets)

        for p, o, t in zip(paths, offsets, transforms):
            result = get_path_collection_extents(
                transform.frozen(), [p], [t], [o], transOffset.frozen()
            )

            bboxes.append(result.transformed(ax.transData.inverted()))
            # bboxes.append(result.inverse_transformed(ax.transData))

    return bboxes


def calculate_overall_f1_from_confusion_matrix(tp, tn, fp, fn):
    """Calculate overall F1 score using macro-averaged F1 (consistent with utils.py)"""

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


def aggregate_results_for_model(model_files):
    """Aggregate all files for a model and calculate F1 by aggregating confusion matrix"""
    total_tp = 0
    total_tn = 0
    total_fp = 0
    total_fn = 0

    for file_path in model_files:
        with open(file_path, "rb") as f:
            json_data = orjson.loads(f.read())

        # Skip the first stats entry, start counting confusion matrix from second entry
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

    # Calculate F1 using the same method as utils.py
    overall_f1 = calculate_overall_f1_from_confusion_matrix(
        total_tp, total_tn, total_fp, total_fn
    )

    print(f"    Aggregated: TP={total_tp}, TN={total_tn}, FP={total_fp}, FN={total_fn}")
    print(f"    Overall F1 = {overall_f1:.4f}")

    return overall_f1


def plot_model_size_scatter(results_dir: str = None):
    """Plot model size vs overall F1 scatter chart"""
    ROOT = Path(PROJECT_PATH) / "results"
    if results_dir:
        RESULTS_DIR = Path(results_dir)
    else:
        RESULTS_DIR = ROOT / Path("./test_data")
    PLOT_SAVE_DIR = Path("./results")
    PLOT_SAVE_DIR.mkdir(exist_ok=True, parents=True)

    print(f"Reading results from: {RESULTS_DIR}")

    # Name mapping for display (optional - if not found, use original name)
    name_mapping = {
        "VulnLLM-R-7B": "VulnLLM-R-7B",
        "o3": "o3",
        "claude-3-7-sonnet-20250219": "Claude-3.7-Sonnet",
        "together-deepseek-reasoner": "DeepSeek-R1",
        "QwQ-32B": "QwQ-32B",
        "Qwen2.5-7B-Instruct": "Qwen2.5-7B",
        "Qwen2.5-Coder-7B-Instruct": "Qwen2.5-Coder-7B",
        "Qwen3-8B": "Qwen3-8B",
        "Qwen3-32B": "Qwen3-32B",
        "DeepCoder-14B-Preview": "DeepCoder-14B",
        "Sky-T1-32B-Flash": "Sky-T1-32B",
        "Qwen2.5-72B-Instruct": "Qwen2.5-72B",
    }

    # Model size info mapping (for models that need size/position info)
    model_size_info = {
        "VulnLLM-R-7B": {"size": "7B", "position": 7, "marker": "s"},
        "Qwen2.5-7B-Instruct": {"size": "7B", "position": 7, "marker": "*"},
        "Qwen2.5-Coder-7B-Instruct": {"size": "7B", "position": 7, "marker": "*"},
        "Qwen3-8B": {"size": "8B", "position": 8, "marker": "*"},
        "DeepCoder-14B-Preview": {"size": "14B", "position": 14, "marker": "p"},
        "QwQ-32B": {"size": "32B", "position": 32, "marker": "*"},
        "Qwen3-32B": {"size": "32B", "position": 32, "marker": "*"},
        "Sky-T1-32B-Flash": {"size": "32B", "position": 32, "marker": "h"},
        "Qwen2.5-72B-Instruct": {"size": "70B", "position": 70, "marker": "*"},
        "together-deepseek-reasoner": {"size": "650B", "position": 650, "marker": "p"},
        "o3": {"size": "N/A", "position": 1200, "marker": "X"},
        "claude-3-7-sonnet-20250219": {"size": "N/A", "position": 1200, "marker": "H"},
    }

    # Collect data files, discover all models dynamically
    model_files = defaultdict(list)
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
            model_name = data["model_shortname"]
            model_files[model_name].append(json_file)
            discovered_models.add(model_name)

    # Sort models alphabetically, but put VulnLLM-R-7B first if present
    all_models = sorted(discovered_models)
    if "VulnLLM-R-7B" in all_models:
        all_models.remove("VulnLLM-R-7B")
        all_models.insert(0, "VulnLLM-R-7B")

    print(f"Discovered {len(all_models)} models: {all_models}")

    # Calculate F1 scores for each model
    results = []

    for model_name in all_models:
        if model_name in model_files and model_files[model_name]:
            overall_f1 = aggregate_results_for_model(model_files[model_name])
            display_name = name_mapping.get(model_name, model_name)

            # Get size info, use defaults if not found
            if model_name in model_size_info:
                size_info = model_size_info[model_name]
            else:
                # Default size info for unknown models
                size_info = {"size": "N/A", "position": 1200, "marker": "o"}

            print(f"Model {display_name} ({model_name}): {len(model_files[model_name])} files, F1 = {overall_f1:.4f}")

            results.append(
                {
                    "model": model_name,
                    "display_name": display_name,
                    "size_label": size_info["size"],
                    "position": size_info["position"],
                    "marker": size_info["marker"],
                    "overall_f1": overall_f1,
                }
            )

    # Convert to DataFrame
    df = pd.DataFrame(results)
    df = df.sort_values("position")

    # Create professional chart
    fig, ax = plt.subplots(figsize=(10, 8), dpi=200)

    # Define color mapping - vivid colors
    color_map = {
        "VulnLLM-R-7B": "#FF6B6B",  # Red to highlight our model
        "7B": "#45B7D1",
        "8B": "#45B7D1",
        "14B": "#FFEAA7",
        "32B": "#DDA0DD",
        "70B": "#96CEB4",
        "650B": "#FF9F43",
        "N/A": "#95A5A6",
    }

    # Draw scatter plot
    scatter_objects = []
    for i, row in df.iterrows():
        if row["display_name"] == "VulnLLM-R-7B":
            color = color_map["VulnLLM-R-7B"]
            edge_width = 3
            scatter_size = 600
        else:
            color = color_map.get(row["size_label"], "#95A5A6")
            edge_width = 2
            scatter_size = 450

        scatter = ax.scatter(
            row["position"],
            row["overall_f1"],
            marker=row["marker"],
            s=scatter_size,
            c=color,
            edgecolors="black",
            linewidth=edge_width,
            alpha=0.85,
            zorder=3,
        )
        scatter_objects.append(scatter)
    # change x tick to log scale
    ax.set_xscale("log")
    texts = []
    for i, row in df.iterrows():
        font_weight = "bold" if row["display_name"] == "VulnLLM-R-7B" else "normal"
        fontsize = 14
        texts.append(
            plt.text(
                row["position"],
                row["overall_f1"],
                row["display_name"],
                fontdict={
                    "fontsize": fontsize,
                    "fontweight": font_weight,
                    "rotation": 0,
                },
            )
        )
    bbs = []
    for point in scatter_objects:
        bbs += get_bounding_boxes_scatter_plot(point, ax)
    adjust_text(
        texts,
        objects=bbs,
        arrowprops=dict(
            arrowstyle="wedge,tail_width=2.5,shrink_factor=0.5",
            connectionstyle="arc3,rad=-0.05",
            color="grey",
            alpha=0.5,
        ),
    )

    # Set x-axis labels - use original position as tick location, display size_label
    unique_positions = sorted(df["position"].unique())
    size_labels = []
    for pos in unique_positions:
        # Get the size_label of the first model at this position
        size_label = df[df["position"] == pos]["size_label"].iloc[0]
        size_labels.append(size_label)

    ax.set_xticks(unique_positions)
    ax.set_xticklabels(size_labels, fontsize=20, fontweight="medium")
    ax.tick_params(axis="y", labelsize=20)

    # Set title and labels
    ax.set_xlabel("Model Size", fontsize=24, fontweight="bold", labelpad=10)
    ax.set_ylabel("Overall F1 Score", fontsize=24, fontweight="bold", labelpad=10)

    # Set grid style
    ax.grid(True, alpha=0.25, linestyle="--", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)

    # Set y-axis range and format
    ax.set_ylim(-0.02, 0.85)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f"{y:.1f}"))

    # Add horizontal reference lines
    for y_val in [0.2, 0.4, 0.6, 0.8]:
        ax.axhline(
            y=y_val, color="gray", linestyle=":", alpha=0.3, linewidth=0.5, zorder=1
        )

    # Set border style
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_linewidth(1.5)
    ax.spines["bottom"].set_linewidth(1.5)

    # Adjust layout
    plt.tight_layout()

    # Save figure
    plt.savefig(
        PLOT_SAVE_DIR / "model_size_vs_f1_scatter.pdf", dpi=400, bbox_inches="tight"
    )
    # Show figure
    plt.show()

    # Print results table
    print("\nModel Performance Summary:")
    print("=" * 80)
    print(
        f"{'Original Name':<30} {'Display Name':<20} {'Size':<15} {'F1':<10} {'Marker':<8}"
    )
    print("=" * 80)
    for _, row in df.iterrows():
        print(
            f"{row['model']:<30} {row['display_name']:<20} {row['size_label']:<15} {row['overall_f1']:.4f} {row['marker']:<8}"
        )
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot model size vs F1 scatter chart")
    parser.add_argument(
        "--results-dir",
        type=str,
        default=None,
        help="Path to results directory containing JSON files (default: results/test_data)"
    )
    args = parser.parse_args()

    plot_model_size_scatter(results_dir=args.results_dir)
