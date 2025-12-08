import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from tqdm import trange  # for progress display in synchronous loops

from model_zoo.language_model import LanguageModel


class HuggingFaceModel(LanguageModel):
    def __init__(
        self,
        model,
        tokenizer=None,
        temperature=None,
        do_sample=False,
        top_k=None,
        top_p=None,
        batch_size=8,
        seed=42,
        quantization=False,
        quantization_config=None,
        torch_dtype=None,
        **kwargs,
    ):
        """
        Initialize the HFLLMModel with a Hugging Face model.

        Parameters:
            model (str): The model identifier or path to the pretrained model.
            tokenizer (AutoTokenizer, optional): If provided, use this tokenizer; otherwise, load one automatically.
            **kwargs: Additional configuration parameters (e.g., torch_dtype, quantization_config, etc.)
        """
        # Load the Hugging Face model for causal language modeling.
        self.model = AutoModelForCausalLM.from_pretrained(
            model,
            device_map="auto",
            torch_dtype=torch_dtype,  # e.g., torch.float16
            quantization_config=quantization_config,  # e.g., BitsAndBytesConfig(...)
            attn_implementation="flash_attention_2" if not quantization else None,
            use_cache=True,
            low_cpu_mem_usage=True,
            trust_remote_code=True,
        )
        # Load the corresponding tokenizer if not provided.
        if tokenizer is None:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model.name_or_path)
            # Set pad token to eos token (common for causal LM models)
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id
            # Use left-padding (often more efficient for batched inference)
            self.tokenizer.padding_side = "left"
        else:
            self.tokenizer = tokenizer

        self.batch_size = batch_size
        self.seed = seed
        vars(self).update(kwargs)

        if self.seed is not None:
            torch.manual_seed(self.seed)
        self.model.eval()
        self.model.generation_config.do_sample = do_sample
        self.model.generation_config.top_k = top_k
        self.model.generation_config.top_p = top_p
        self.model.generation_config.temperature = temperature

    def __str__(self):
        return f"HuggingFaceModel(model={self.model.config._name_or_path})"

    def __repr__(self):
        return str(self)

    def config_model(self, **kwargs):
        generation_config_keys = {"do_sample", "top_k", "top_p", "temperature"}

        for key, value in kwargs.items():
            if key in generation_config_keys:
                setattr(self.model.generation_config, key, value)
            else:
                setattr(self, key, value)

        return self  # Allow method chaining

    def run(
        self,
        eval_examples=[],
        system_prompt=None,
        temperature=None,
        top_p=None,
        top_k=None,
        do_sample=False,
        max_tokens=1024,
        batch_size=None,
        n=1,
        **kwargs,
    ):
        """
        Run the model on a list of evaluation examples.

        Parameters:
            eval_examples (list): A list of dictionaries, each with keys "input" and "output".
            system_prompt (str): A system prompt to include in the messages (optional).
            temperature (float): Sampling temperature.
            top_p (float): Top-p nucleus sampling value.
            max_tokens (int): Maximum new tokens to generate.
            batch_size (int): Batch size for inference.
            n (int): Number of samples to generate.

        Returns:
            A tuple (outputs, answers, reasoning_output) where:
              - outputs: The generated outputs from the model.
              - answers: The expected answers from the evaluation examples.
              - reasoning_output: Additional reasoning output (if self.reasoning is True). Thjs is always empty for Hugging Face models.
        """
        all_outputs = []
        answers = []
        messages = []
        batch_size = batch_size or self.batch_size
        

        orig_do_sample = self.model.generation_config.do_sample
        self.model.generation_config.do_sample = do_sample

        orig_temperature = self.model.generation_config.temperature
        if temperature is not None:
            self.model.generation_config.temperature = temperature

        orig_top_p = self.model.generation_config.top_p
        if top_p is not None:
            self.model.generation_config.top_p = top_p

        orig_top_k = self.model.generation_config.top_k
        if top_k is not None:
            self.model.generation_config.top_k = top_k

        for example in eval_examples:
            if system_prompt:
                messages.append(
                    [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": example["input"]},
                    ]
                )
            else:
                messages.append([{"role": "user", "content": example["input"]}])
            answers.append(example["output"])

        tokens = {"input_tokens": [], "output_tokens": []}
        input_data = self.tokenizer.apply_chat_template(
            messages,
            padding=True,
            return_tensors="pt",
            return_dict=True,
            add_generation_prompt=True,
        )
        num_examples = len(messages)
        tokens["input_tokens"].extend([len(ids) for ids in input_data["input_ids"]])
        with torch.no_grad():
            for batch_idx in trange(
                0, num_examples, batch_size, desc="Running Batches"
            ):
                # Slice batch input IDs and attention mask.
                batch_input_ids = input_data["input_ids"][
                    batch_idx : batch_idx + batch_size
                ].to("cuda")
                batch_attention_mask = input_data["attention_mask"][
                    batch_idx : batch_idx + batch_size
                ].to("cuda")

                output_ids = self.model.generate(
                    input_ids=batch_input_ids,
                    attention_mask=batch_attention_mask,
                    max_new_tokens=max_tokens,
                    pad_token_id=self.tokenizer.eos_token_id,
                    num_return_sequences=n,
                    temperature=temperature,
                    do_sample=do_sample if n == 1 else True,
                )
                prompt_length = batch_input_ids.shape[1]
                generated_ids = output_ids[:, prompt_length:]
                batch_outputs = self.tokenizer.batch_decode(
                    generated_ids,
                    skip_special_tokens=True,
                )
                all_outputs.extend(batch_outputs)
                tokens["output_tokens"].extend([len(g_ids) for g_ids in generated_ids])


        if not all(all_outputs):
            print("empty response detected")

        # Reset the generation_config to the original value.
        self.model.generation_config.do_sample = orig_do_sample
        self.model.generation_config.temperature = orig_temperature
        self.model.generation_config.top_p = orig_top_p
        self.model.generation_config.top_k = orig_top_k

        latencies = [-1 for _ in range(len(messages))] #dummy latencies

        return all_outputs, answers, latencies, tokens

    def query_once(
        self,
        messages,
        temperature=None,
        top_p=None,
        top_k=None,
        do_sample=False,
        max_tokens=None,
        **kwargs,
    ):
        """
        A single query using the Hugging Face model's generate method.

        Parameters:
            messages (list): A list of message dictionaries representing the conversation.
                             Example: [{"role": "user", "content": "Hello, how are you?"}]
            temperature (float, optional): Sampling temperature. Defaults to self.model.generation_config.temperature.
            top_p (float, optional): Top-p nucleus sampling parameter. Defaults to 1.0.
            max_tokens (int, optional): Maximum tokens to generate. Defaults to 256.
            **kwargs: Additional keyword arguments to pass to the generate method.

        Returns:
            str or None: The decoded response from the model, or None if an error occurs.
        """
        orig_do_sample = self.model.generation_config.do_sample
        self.model.generation_config.do_sample = do_sample

        orig_temperature = self.model.generation_config.temperature
        if temperature is not None:
            self.model.generation_config.temperature = temperature

        orig_top_p = self.model.generation_config.top_p
        if top_p is not None:
            self.model.generation_config.top_p = top_p

        orig_top_k = self.model.generation_config.top_k
        if top_k is not None:
            self.model.generation_config.top_k = top_k

        try:
            # Use the tokenizer to apply the chat template and prepare input tensors.
            # Here we wrap messages in a list to create a batch of one query.
            input_data = self.tokenizer.apply_chat_template(
                [messages],
                padding=True,
                return_tensors="pt",
                return_dict=True,
                add_generation_prompt=True,
            )
            # Move the inputs to the appropriate device (assumed "cuda").
            input_ids = input_data["input_ids"].to("cuda")
            attention_mask = input_data["attention_mask"].to("cuda")

            # Generate output tokens using the model.
            output_ids = self.model.generate(
                input_ids=input_ids,
                attention_mask=attention_mask,
                max_new_tokens=max_tokens or 256,
                pad_token_id=self.tokenizer.eos_token_id,
                **kwargs,
            )
            # Skip the prompt tokens and decode only the newly generated tokens.
            prompt_length = input_ids.shape[1]
            generated_ids = output_ids[:, prompt_length:]
            decoded_output = self.tokenizer.decode(
                generated_ids[0], skip_special_tokens=True
            )
            return decoded_output
        except Exception as e:
            print(f"⚠️ query_once encountered an error: {e}")
            return None
        finally:
            # Reset the generation_config to the original value.
            self.model.generation_config.do_sample = orig_do_sample
            self.model.generation_config.temperature = orig_temperature
            self.model.generation_config.top_p = orig_top_p
            self.model.generation_config.top_k = orig_top_k
