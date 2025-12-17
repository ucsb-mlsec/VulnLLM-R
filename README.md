# VulnLLM-R: Specialized Reasoning LLM for Vulnerability Detection

* **Paper:** [arXiv:2512.07533](https://arxiv.org/abs/2512.07533)
* **Code & Data:** [GitHub](https://github.com/ucsb-mlsec/VulnLLM-R)
* **Demo:** [Web demo](https://huggingface.co/spaces/UCSB-SURFI/VulnLLM-R)
* **Model:** [7B Model](https://huggingface.co/UCSB-SURFI/VulnLLM-R-7B)

<img width="400" alt="model_size_vs_f1_scatter_01" src="https://github.com/user-attachments/assets/fc9e6942-14f8-4f34-8229-74596b05c7c5" />

## Environment and dataset

### 🛠️ Create environment

- git clone the repository

```shell
git clone https://github.com/ucsb-mlsec/VulnLLM-R.git
```

- Create a new conda environment

```shell
conda create -n vulnscan python=3.11
conda activate vulnscan
```

- Install the required packages

```shell
pip install -e .
```

- Install LLaMA-Factory

```shell
cd vulscan/train/LLaMA-Factory
pip install -e .
```

- Install model_zoo

```shell
cd ../../../vulscan/model_zoo
pip install -e .
```

## For Reproducing Our Results

```shell
# for reproduce VulnLLM-R-7B's results
python -m vulscan.test.test --output_dir results/test_data --dataset_path ./datasets/test/function_level/ ./datasets/test/repo_level/ --language python c java --model UCSB-SURFI/VulnLLM-R-7B --requests_per_minute 1000 --save --use_cot --batch_size 4 --tp 2 --vllm --max_tokens 8192 --random_cwe
```

## Existing Distilled Datasets

- [Distill-DeepSeek](https://huggingface.co/datasets/UCSB-SURFI/Distill-DeepSeek)
- [Distill-QwQ](https://huggingface.co/datasets/UCSB-SURFI/Distill-QwQ)

We also provide the reduced reasoning version of the distilled datasets:

- [Reduced-Distill-DeepSeek](https://huggingface.co/datasets/UCSB-SURFI/Reduced-Distill-DeepSeek)
- [Reduced-Distill-QwQ](https://huggingface.co/datasets/UCSB-SURFI/Reduced-Distill-QwQ)

### 📚 Construct training and testing datasets

Merge existing function-level vulnerability detection datasets:
PrimeVul [<a href="https://github.com/DLVulDet/PrimeVul">1</a>],
SecCodePLT [<a href="http://seccodeplt.github.io/">2</a>],
Juliet [<a href="https://samate.nist.gov/SARD/test-suites/112">3</a>],
and Sven [<a href="https://github.com/eth-sri/sven">4</a>].
Within these datasets, PrimeVul has the most complicated functions.
We create two training sets: clean (without PrimeVul) and noisy (with PrimeVul),
so we can train on relatively simple datasets and test on the complex PrimeVul dataset.
Note that we name the training set with PrimeVul as noisy not means the dataset is noisy.
It is a relatively arbitrary name we used at the beginning.

- After download all the datasets, ```vulscan/data_process/data_utils``` has a set of scripts to process and merge the
  datasets.
    - ```raw_to_us.py```: Merge the raw data into our dataset and remove redundant data
    - ```check_cwe_correct.py```: Compute the accuracy for each CWE category
    - ```split_good_bad_for_juliet.py```: Extract data from the raw Juliet 1.3 dataset and convert it into the required
      format, which forms part of our c clean_dataset
    - ```add_sven_to_clean_dataset.py```: Extract data from the Sven dataset, forming part of our C clean dataset
    - ```sync_large_small.py```: Synchronize the modifications of noisy_dataset/large_train/c to
      noisy_dataset/small_train/c
    - ```remove_testing_from_training.py```: Add the `human` tag to each data, meaning the point has been verified by
      human and used as testing data
      -```data_utils.py```: Add the related_cwe field to dataset.
- The merged data will be saved in
    - ``datasets/clean_dataset``: the training data without PrimeVul
        - ``datasets/clean_dataset/python`` has the data from SVEN and SecCodePLT
        - ``datasets/clean_dataset/c`` has the data from Juliet and SVEN
    - ``datasets/noisy_dataset``
        - ``datasets/noisy_dataset/small_train``: Contains the training data from PrimeVul and SVEN with selected CWEs (
          we use the PrimeVul data in this dataset as the training)
        - ``datasets/noisy_dataset/large_train``: Contains the training data from PrimeVul and SVEN and SecCodePLT with
          more CWEs (This dataset can later be used to train larger models)
        - ``datasets/noisy_dataset/test``: A small testing set from PrimeVul verified by human
    - ``datasets/test``
        - ``datasets/test/test_clean``: The testing data from SVEN and SecCodePLT and Juliet; with OOD CWEs that are not
          part of the training set
        - ``datasets/test/test_primevul_pair``: The original PrimeVul testing data
- Dataset statistics; can run ``vulscan/data_process/data_utils/get_cwe_stat.py`` to get the histogram of the dataset

| Dataset                       | Language | Train/test | CWE         | # Benign | # Vuln. | average length |
|-------------------------------|----------|------------|-------------|----------|---------|----------------|
| Clean (seccodeplt)            | Python   | Train      | 20          | 1281     | 1281    | 741            |
| Clean (juliet)                | C/C++    | Train      | 22          | 1716     | 1653    | 3689           |
| Hard (primevul filtered)      | C/C++    | Train      | 26          | 2717     | 2952    | 4689           |
| Long Context (Oss-fuzz)       | C/C++    | Train      | 3           | 475      | 604     | 12761          |
| Simple (seccodeplt)           | Python   | Test       | 24 (6 ood)  | 74       | 74      | 814            |
| Simple (juliet)               | C/C++    | Test       | 38 (14 ood) | 358      | 376     | 2575           |
| Hard (PrimeVul, SecLLMHolmes) | C/C++    | Test       | 13 (5 ood)  | 145      | 152     | 4545           |
| Long Context (Oss-fuzz)       | C/C++    | Test       | 3 (0 ood)   | 0        | 320     | 18929          |
| primevul test (noisy)         | C/C++    | Test       | 56 (34 ood) | 421      | 422     | 5341           |

| PrimeVul (Noisy) | C/C++ | Small train | 27 | 45561 | 3593 |
| PrimeVul (Noisy) | C/C++ | Test | 56 (37 ood) | 421 | 421 |

### 🤔 Generate reasoning data for training

After constructing the datasets, we will generate reasoning data for our training set.
We will query the DeepSeek-r1 and QwQ reasoning model to generate the reasoning data and filter out the ones with very
long reasoning chains.
The code for generating reasoning data is in `vulscan/data_process/generate_reasoning` and the reasoning data will be
saved
in `datasets/reasoning_data`.

```shell
cd ./VulnScan-r0
export PYTHONPATH=$PYTHONPATH:$PWD
cd vulscan/data_process/generate_reasoning
```

`generate_reasoning/generate.py` is the main script for generating reasoning data.
For each data point, it will generate n reasoning data samples and select the one with the correct answer and shortest
length.
Examples of running it with the QwQ and DeepSeek-r1 models (using the together.AI API, which is slower but more stable
than the official API) are as follows:

```shell
python generate.py \
--tp 2 \
--dataset_type clean_dataset \
--batch_size 200 \
--n 8 \
--training_set train \
--model_name Qwen/QwQ-32B

# or
python generate.py \
--dataset_type noisy_dataset \
--batch_size 200 \
--n 8 \
--training_set small_train \
--model_name together-deepseek-reasoner \
--together_deepseek
```

After generating the raw reasoning data, we can further use another model to summarize them and make them shorter
without breaking the structure

```shell
python extract_reasoning.py
```

We can further filter the reasoning data based on certain length with `generate_reasoning/filter.py`; `num_processes`
are changes according to your number of CPU cores.

```shell
python filter.py \
--dataset_type noisy_dataset \
--training_set small_train \
--model_name Qwen/QwQ-32B \ 
--filter_input_length 16000 \
--filter_all_length 32000 \
--num_processes 16 \
--filter_correct_only # for filtering wrong predictions
# --model_name together-deepseek-reasoner \
```

Finally, we will need to reformat the generated reasoning data for the target model that we will train (Qwen-Instruct).

```shell
python reformat_ds.py \
--dataset_type noisy_dataset \
--training_set small_train \
--model_name Qwen/QwQ-32B \
--filter_input_length 16000 \
--filter_all_length 32000 \
--push_to_hub \
--push_to_hub_organization secmlr \
--filter_correct_only 
```

`archive` has some python scripts that are not useful. For example, `reformat_ds.py` is used to reformat the dataset for
the deepseek model, but we always encountered the format issue when fine-tuning deepseek models.

# for dpo dataset

python generate_dpo.py \
--tp 2 --dataset_type clean_dataset \
--batch_size 200 --n 8 --training_set train \
--model secmlr/VD-QWQ-Clean-8k_qwen2_7B_full_sft_1e-5

## 🤖 SFT and DPO Training

refer to [`vulscan/train/README.md`](vulscan/train/README.md) for more details

results will be saved in `results/test_qwen/results.json` directory.

## 🔍 Test the trained models

If you want to reproduce our results, you can run the following command:

```shell
./vulscan/test/run_test.sh test.log
```

```shell
# open-source model
python -m vulscan.test.test --output_dir results/one_of_4 \
--dataset_path ./datasets/test/test_clean ./datasets/test/test_primevul_pair \
--language c python --model Qwen/Qwen2.5-7B-Instruct \
--requests_per_minute 100 --save --use_cot \
--use_policy --batch_size 4 --tp 2 --vllm --max_tokens 16384 \
--random_cwe

# api model
python -m vulscan.test.test --output_dir results/one_of_4 \
--dataset_path ./datasets/test/test_clean ./datasets/test/test_primevul_pair \
--language c python --model o3-mini-2025-01-14 \
--requests_per_minute 100 --save --use_cot \
--use_policy --batch_size 4 --max_tokens 16384 --random_cwe

# local saved model
python -m vulscan.test.test --output_dir results/one_of_4 \
--dataset_path ./datasets/test/test_clean ./datasets/test/test_primevul_pair \
--language c python \
--model vulscan/train/result/VD-QWQ-Clean-16k/qwen2_7B_full_sft_1e-5 \
--requests_per_minute 100 --save --use_cot --use_policy \
--batch_size 4 --tp 2 --vllm --max_tokens 16384 --random_cwe

# our model
python -m vulscan.test.test --output_dir results/one_of_4 \
--dataset_path ./datasets/test/test_clean ./datasets/test/test_primevul_pair \
--language c python \
--model secmlr/VD-QWQ-Noisy-Small-8k_qwen2_7B_full_sft_1e-5 --revision aa3235b \
--requests_per_minute 100 --save --use_cot --use_policy \
--batch_size 4 --tp 2 --vllm --max_tokens 16384 \
--random_cwe # whether to randomize the order of cwe and related cwes
```

After testing, model responses and performance will be saved in `results/test_data` directory.
If you want to calculate the performance according to the model responses, you can run the following command:

```shell
python -m vulscan.test.test_existing_json \
--json_file results/test_data/datasets_test_test_clean__cot_c_policy_QwQ-32B-Preview.json # the results file
```

```shell
python generate_constitution.py --model gpt-4o --input_dir results/train --output_dir results/train/constitution
```

## Citation

```bibtex
@article{nie2025vulnllmrspecializedreasoningllm,
      title={VulnLLM-R: Specialized Reasoning LLM with Agent Scaffold for Vulnerability Detection}, 
      author={Yuzhou Nie and Hongwei Li and Chengquan Guo and Ruizhe Jiang and Zhun Wang and Bo Li and Dawn Song and Wenbo Guo},
      year={2025},
      journal={arXiv preprint arXiv:2512.07533},
      url={https://arxiv.org/abs/2512.07533}, 
}
```
