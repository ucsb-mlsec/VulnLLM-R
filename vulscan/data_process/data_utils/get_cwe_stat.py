import os
import re
import json
import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt


def analyze_cwe_files(directory, primevul=False):
    cwe_stats = defaultdict(lambda: {"benign": 0, "vulnerable": 0})

    for filename in os.listdir(directory):
        if filename.startswith("CWE-") and filename.endswith(".json"):

            cwe_number = re.search(r"CWE-(\d+)", filename).group(1)

            file_path = os.path.join(directory, filename)
            with open(file_path, "r") as f:
                data = json.load(f)

                for item in data:
                    if primevul:
                        # if "sven" not in item["dataset"]:
                        #     continue
                        if "primevul" not in item["dataset"]:
                            continue
                    if item["target"] == 0:
                        cwe_stats[cwe_number]["benign"] += 1
                    elif item["target"] == 1:
                        cwe_stats[cwe_number]["vulnerable"] += 1

    return cwe_stats


def plot_distribution(cwe_stats, title_suffix=""):
    cwe_numbers = sorted(cwe_stats.keys(), key=int)
    benign_counts = [cwe_stats[cwe]["benign"] for cwe in cwe_numbers]
    vulnerable_counts = [cwe_stats[cwe]["vulnerable"] for cwe in cwe_numbers]

    plt.figure(figsize=(20, 12))

    x = range(len(cwe_numbers))
    width = 0.45

    plt.bar(
        [i - width / 2 for i in x],
        benign_counts,
        width,
        label="Benign",
        color="blue",
        alpha=0.6,
    )
    plt.bar(
        [i + width / 2 for i in x],
        vulnerable_counts,
        width,
        label="Vulnerable",
        color="red",
        alpha=0.6,
    )

    plt.title(
        f"Distribution of Benign and Vulnerable Cases by CWE{title_suffix}", fontsize=14
    )
    plt.xlabel("CWE Number", fontsize=12)
    plt.ylabel("Count", fontsize=12)

    plt.xticks(x, [f"CWE-{cwe}" for cwe in cwe_numbers], rotation=45)

    plt.legend()

    plt.tight_layout()

    plt.show()
    plt.close()


def filter_cwe_stats(cwe_stats, threshold=None, method="percentile", percentile=50):
    total_samples = {
        cwe: stats["benign"] + stats["vulnerable"] for cwe, stats in cwe_stats.items()
    }

    if threshold is None:
        if method == "percentile":
            threshold = np.percentile(list(total_samples.values()), percentile)

    filtered_stats = {
        cwe: stats
        for cwe, stats in cwe_stats.items()
        if total_samples[cwe] <= threshold
    }

    return filtered_stats, threshold


def print_statistics(cwe_stats):
    # print("\nDetailed statistics for each CWE:")
    # print("-" * 50)

    total_benign = 0
    total_vulnerable = 0

    for cwe in sorted(cwe_stats.keys(), key=int):
        benign = cwe_stats[cwe]["benign"]
        vulnerable = cwe_stats[cwe]["vulnerable"]

        total_benign += benign
        total_vulnerable += vulnerable

        # print(f"CWE-{cwe}:")
        # print(f"  Benign: {benign}")
        # print(f"  Vulnerable: {vulnerable}")
        # print(f"  Total: {total}")
        # print("-" * 50)

    print("\nOverall statistics:")
    print(f"\nTotal number of CWEs: {len(cwe_stats)}")
    print(f"Total benign cases: {total_benign}")
    print(f"Total vulnerable cases: {total_vulnerable}")
    print(f"Total cases: {total_benign + total_vulnerable}")


def draw_cwe_stat(data_path, primevul=False):

    cwe_stats = analyze_cwe_files(data_path, primevul)

    print_statistics(cwe_stats)
    return cwe_stats.keys()

    # plot_distribution(cwe_stats)
    #
    # filtered_stats, threshold = filter_cwe_stats(
    #     cwe_stats, method="percentile", percentile=50
    # )
    # print("\n=== Filtered Statistics ===")
    # plot_distribution(filtered_stats, title_suffix=" (Filtered)")


if __name__ == "__main__":
    data_path = "/Users/wenboguo/Desktop/gitProjects/VulnScan-r0/datasets/noisy_dataset/small_train/c"
    # data_path = "/Users/wenboguo/Desktop/gitProjects/VulnScan-r0/datasets/clean_dataset/train/c"
    cwes_train = draw_cwe_stat(data_path, primevul=True)

    # data_path = "/Users/wenboguo/Desktop/gitProjects/VulnScan-r0/datasets/test/test_clean/c"
    data_path = "/Users/wenboguo/Desktop/gitProjects/VulnScan-r0/datasets/test/test_primevul_pair/c"
    cwes = draw_cwe_stat(data_path, primevul=False)

    # Compute differences and common files
    files_dir1 = set(cwes)
    files_dir2 = set(cwes_train)

    print(len(files_dir1 - files_dir2))
    print(files_dir2 - files_dir1)
    print(files_dir1 & files_dir2)

    # draw_cwe_stat(data_path, primevul=True)
