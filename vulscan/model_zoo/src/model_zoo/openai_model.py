import asyncio
import time

from openai import AsyncOpenAI
from tqdm.asyncio import tqdm_asyncio

from model_zoo.language_model import LanguageModel


class OpenAIModel(LanguageModel):
    def __init__(
        self,
        model,
        server_url=None,
        api_key=None,
        limiter=None,
        temperature=0,
        seed=42,
        **kwargs,
    ):
        super().__init__(model)
        self.benchmark = None
        self.client = AsyncOpenAI(base_url=server_url, api_key=api_key)
        self.limiter = limiter
        self.temperature = temperature
        self.seed = seed
        vars(self).update(kwargs)

    def __str__(self):
        return f"OpenAI(model={self.model_name})"

    def __repr__(self):
        return str(self)

    def config_model(self, **kwargs):
        vars(self).update(kwargs)
        # Return self to allow chaining of methods
        return self

    def run(
        self,
        eval_examples,
        system_prompt=None,
        temperature=0,
        top_p=1.0,
        max_tokens=1024,
        n=1,
        **kwargs,
    ):
        """
        Run the model on a list of evaluation examples.

        Parameters:
            eval_examples (list): A list of dictionaries with keys "input" and "output".
            system_prompt (str): The system prompt.
            temperature (float): Sampling temperature.
            top_p (float): Top-p nucleus sampling.
            max_tokens (int): Maximum tokens to generate.
            n (int): Number of responses to generate.

        Returns:
            tuple: (all_outputs, answers, reasoning_output) where:
                - all_outputs: List of model outputs.
                - answers: List of expected answers.
                - reasoning_output: Additional reasoning output (if applicable).
        """
        all_outputs = []
        answers = []
        messages = []

        # Construct the messages and answers list from the evaluation examples
        for example in eval_examples:
            if system_prompt:
                # If a system prompt is provided, include it in the conversation
                messages.append(
                    [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": example["input"]},
                    ]
                )
            else:
                # Otherwise, only include the user message
                messages.append([{"role": "user", "content": example["input"]}])
            answers.append(example["output"] if "output" in example else None)

        # Run asynchronous batch chat completions
        temperature = temperature or self.temperature
        resps, latencies = asyncio.run(
            self.batch_chat_completion(
                messages,
                temperature=temperature,
                top_p=top_p,
                max_tokens=max_tokens,
                n=n,
            )
        )

        tokens = {"input_token": [], "output_token": []}

        # Process each response, extract generated text (and reasoning if applicable)
        for outputs in resps:
            if outputs:
                try:
                    content = [out.message.content for out in outputs.choices]
                except Exception as _:
                    content = [""] * n
                # Extract reasoning if available (now only deepseek-reasoner)
                # try:
                #     reasoning = [
                #         out.message.reasoning_content for out in outputs.choices
                #     ]
                #     # one special case in Claude reasoning, they basically repeat the reasoning in content...
                #     # so we need to remove the remaining part in content
                #     content = [f"{r}\n\n{c}" for r, c in zip(reasoning, content)]
                # except Exception:
                #     pass
                try:
                    tokens["input_token"].append(outputs.usage.prompt_tokens)
                    tokens["output_token"].append(outputs.usage.completion_tokens)
                except Exception as _:
                    tokens["input_token"].append(0)
                    tokens["output_token"].append(0)
                all_outputs.append(content)
            else:
                all_outputs.append([""])
                tokens["input_token"].append(0)
                tokens["output_token"].append(0)

        if not all(all_outputs):
            print("empty response detected")
        if not latencies:
            latencies = [-1 for _ in all_outputs]

        return all_outputs, answers, latencies, tokens

    async def batch_chat_completion(
        self,
        messages_lst,
        temperature=None,
        top_p=1.0,
        max_tokens=None,
        n=1,
    ):
        """
        Run asynchronous batch requests for chat completion.
        """
        if not self.limiter:
            raise ValueError(
                "Limiter is not set. Please set the limiter using config_model() before running batch completion."
            )

        tasks = [
            self.__rate_limited_api_call__(
                message,
                temperature=temperature,
                top_p=top_p,
                max_tokens=max_tokens,
                n=n,
            )
            for message in messages_lst
        ]
        start_time = time.perf_counter()  # Record start time
        results = await tqdm_asyncio.gather(
            *tasks, desc="🔥 Running Async Batch Requests"
        )
        end_time = time.perf_counter()  # Record end time
        # Calculate latencies for each task
        latencies = [end_time - start_time] * len(
            results
        )  # Use the same latency for all tasks
        return results, latencies

    async def __rate_limited_api_call__(
        self,
        messages,
        temperature=None,
        top_p=1.0,
        max_tokens=None,
        n=1,
    ):
        """
        Ensure the API call is rate-limited using the provided limiter.
        """
        async with self.limiter:
            result = await self.__chat_function__(
                chat=self.client.chat.completions.create,
                messages=messages,
                temperature=temperature,
                top_p=top_p,
                max_tokens=max_tokens,
                n=n,
            )
            return result

    async def __chat_function__(
        self,
        chat,
        messages,
        temperature=None,
        top_p=1.0,
        max_tokens=None,
        n=1,
    ):
        """
        Internal chat function with retry logic.
        """

        # Use the default litellm API
        for i in range(5):
            try:
                ret = await chat(
                    model=self.model_name,
                    messages=messages,
                    temperature=temperature or self.temperature,
                    top_p=top_p,
                    max_tokens=max_tokens or 256,
                    seed=self.seed or 42,
                    n=n,
                )
                return ret
            except Exception as e:
                print(f"⚠️ Failed with error {e}, retrying in 10s...")
                await asyncio.sleep(10)
                continue
        return None

    def query_once(
        self, messages, temperature=None, top_p=None, max_tokens=None, **kwargs
    ):
        """
        A single synchronous query.

        Parameters:
            messages (list): A list of message dictionaries representing the conversation.
                             Example: [{"role": "user", "content": "Hello, how are you?"}]
            temperature (float, optional): Sampling temperature. Defaults to self.temperature.
            top_p (float, optional): Top-p nucleus sampling parameter. Defaults to 1.0.
            max_tokens (int, optional): Maximum tokens to generate. Defaults to 256.

        Returns:
            dict or None: The API response from the synchronous call, or None if an error occurs.
        """

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=temperature or self.temperature,
                top_p=top_p or 1.0,
                max_tokens=max_tokens,
                seed=self.seed or 42,
                **kwargs,
            )
            return response
        except Exception as e:
            print(f"⚠️ sync_chat encountered an error: {e}")
            return None
