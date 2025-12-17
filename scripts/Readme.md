- Use a json file to specify the models and dataset

```shell
python train_test.py --models_config models.json
```

- Use command line arguments to specify the models and dataset

```shell 
python train_test.py \
   --model_list Qwen/Qwen2.5-7B-Instruct meta-llama/Llama-2-7b-hf \
   --dataset VD-Distill-QwQ \
   --run_name model_sft_1e-5
```

- One model and one dataset

```shell
python train_test.py \
  --model_name_or_path Qwen/Qwen2.5-7B-Instruct \
  --dataset VD-Distill-QwQ \
  --run_name qwen2_7B_full_sft_1e-5 \
  --nproc_per_node 4

```