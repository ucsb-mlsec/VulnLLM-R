import argparse
import os

import orjson

from vulscan.test.test_utils.generation_utils import extract_answer, check_single_cwe
from vulscan.utils.project_info import PROJECT_PATH
from vulscan.test.test_utils.utils import calculate_score


def test_existing_json(json_file):
    # use orjson
    with open(json_file, "rb") as f:
        data = orjson.loads(f.read())
    metrics = data[0]

    # Initialize overall counters
    fn, fp, tp, tn, wrong_num = 0, 0, 0, 0, 0
    data_num = len(data) - 1

    only_binary = True
    # Create dictionary to track metrics by dataset
    dataset_metrics = {}

    for item in data[1:]:
        true_score = item["is_vulnerable"]
        true_vul_type = item["vulnerability_type"]
        pred_score, pred_vul_type = extract_answer(item["output"])
        dataset = item["dataset"]

        # Initialize dataset counters if not exists
        if dataset not in dataset_metrics:
            dataset_metrics[dataset] = {
                "fn": 0, "fp": 0, "tp": 0, "tn": 0,
                "wrong_num": 0, "count": 0, "fn_w": 0, "fn_c": 0
            }

        dataset_metrics[dataset]["count"] += 1

        pred = pred_score.lower()
        if pred == "invalid format":
            if true_score == "yes":
                fn += 1
                dataset_metrics[dataset]["fn"] += 1
            else:
                fp += 1
                dataset_metrics[dataset]["fp"] += 1
            wrong_num += 1
            dataset_metrics[dataset]["wrong_num"] += 1
        else:
            # remove space
            pred = pred.replace(" ", "")
            # calculate false positive and false negative
            # calculate accuracy
            if pred == "yes" and true_score == "yes":
                if only_binary:
                    tp += 1
                    dataset_metrics[dataset]["tp"] += 1
                    continue
                if pred_vul_type in true_vul_type or true_vul_type in pred_vul_type:
                    tp += 1
                    dataset_metrics[dataset]["tp"] += 1
                elif not check_single_cwe(pred_vul_type):
                    fn += 1
                    dataset_metrics[dataset]["fn"] += 1
                    dataset_metrics[dataset]["fn_w"] += 1
                    wrong_num += 1
                    dataset_metrics[dataset]["wrong_num"] += 1
                else:
                    fn += 1
                    dataset_metrics[dataset]["fn"] += 1
                    dataset_metrics[dataset]["fn_w"] += 1
            elif pred == "yes" and true_score == "no":
                fp += 1
                dataset_metrics[dataset]["fp"] += 1
            elif pred == "no" and true_score == "yes":
                fn += 1
                dataset_metrics[dataset]["fn"] += 1
                dataset_metrics[dataset]["fn_c"] += 1
            elif pred == "no" and true_score == "no":
                tn += 1
                dataset_metrics[dataset]["tn"] += 1
            else:
                print("wrong score detected in example")
                if true_score == "yes":
                    fn += 1
                    dataset_metrics[dataset]["fn"] += 1
                else:
                    fp += 1
                    dataset_metrics[dataset]["fp"] += 1
                wrong_num += 1
                dataset_metrics[dataset]["wrong_num"] += 1

    # Calculate metrics for each dataset
    # print("Original metrics:")
    # print("wrong: {}".format(metrics["wrong_num"]))
    # print("fpr: {:.3f}".format(metrics["false_positive_rate"]))
    # print("fnr: {:.3f}".format(metrics["false_negative_rate"]))
    # print("Benign F1: {:.3f}".format(metrics["positive F1"]))
    # print("Vul F1: {:.3f}".format(metrics["negative F1"]))
    # print("Overall F1: {:.3f}".format(metrics["overall F1"]))

    print("\nNew overall result:")
    result = calculate_score(tp, fp, fn, tn, data_num, False, wrong_num)
    print("wrong: {}".format(result["wrong_num"]))
    print("fpr: {:.3f}".format(result["false_positive_rate"]))
    print("fnr: {:.3f}".format(result["false_negative_rate"]))
    print("Benign F1: {:.3f}".format(result["positive F1"]))
    print("Vul F1: {:.3f}".format(result["negative F1"]))
    print("Overall F1: {:.3f}".format(result["overall F1"]))

    # Print per-dataset metrics
    # print("\nMetrics by dataset:")
    # for dataset, counts in dataset_metrics.items():
    #     ds_result = calculate_score(
    #         counts["tp"], counts["fp"], counts["fn"], counts["tn"],
    #         counts["count"], False, counts["wrong_num"]
    #     )
    #     print(f"\n--- Dataset: {dataset} (samples: {counts['count']}) ---")
    #     print("wrong: {}".format(ds_result["wrong_num"]))
    #     print("fpr: {:.3f}".format(ds_result["false_positive_rate"]))
    #     print("fnr: {:.3f}".format(ds_result["false_negative_rate"]))
    #     print("Benign F1: {:.3f}".format(ds_result["positive F1"]))
    #     print("Vul F1: {:.3f}".format(ds_result["negative F1"]))
    #     print("Overall F1: {:.3f}".format(ds_result["overall F1"]))
    #     print("fn with wrong prediction for cwe tpyes: {}".format(counts["fn_w"]))
    #     print("fn with wrong prediction for yes or no: {}".format(counts["fn_c"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json_file", type=str, required=True, nargs = "+",)
    args = parser.parse_args()
    os.chdir(PROJECT_PATH)
    for json_file in args.json_file:
        print(f"\n\nProcessing {json_file}...")
        print("=" * 50)
        print("\n\n")
        test_existing_json(json_file)
