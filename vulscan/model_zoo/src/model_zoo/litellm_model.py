import asyncio
import time

import litellm
import re
from tqdm.asyncio import tqdm_asyncio

from model_zoo.language_model import LanguageModel

litellm.drop_params = True


class LiteLLMModel(LanguageModel):
    def __init__(
        self,
        model,
        server_url=None,
        api_key=None,
        limiter=None,
        temperature=0,
        seed=42,
        together_deepseek=False,
        **kwargs,
    ):
        super().__init__(model)
        self.server_url = server_url
        if self.server_url:
            litellm.api_base = self.server_url
        self.api_key = api_key
        if api_key:
            litellm.api_key = api_key
        self.limiter = limiter
        self.temperature = temperature
        self.seed = seed
        # Flag to use temporary DeepSeek-R1 calls via the Together package
        self.together_deepseek = together_deepseek
        vars(self).update(kwargs)

    def __str__(self):
        return f"LiteLLMModel(model={self.model_name})"

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
        temperature=None,
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
        if hasattr(self, "reasoning_effort"):
            temperature = 1
            reasoning_effort = self.reasoning_effort
            top_p = None
        else:
            temperature = temperature or self.temperature
            reasoning_effort = None
        resps, latencies = asyncio.run(
            self.batch_chat_completion(
                messages,
                temperature=temperature or self.temperature,
                top_p=top_p,
                max_tokens=max_tokens,
                n=n,
                reasoning_effort=reasoning_effort,
            )
        )

        tokens = {"input_token": [], "output_token": []}

        # Process each response, extract generated text (and reasoning if applicable)
        for outputs in resps:
            if outputs:
                try:
                    content = [out["message"]["content"] for out in outputs["choices"]]
                except Exception:
                    content = [""] * n
                # Extract reasoning if available (now only deepseek-reasoner)
                try:
                    reasoning = [
                        out["message"]["reasoning_content"]
                        for out in outputs["choices"]
                    ]
                    # one special case in Claude reasoning, they basically repeat the reasoning in content...
                    # so we need to remove the remaining part in content
                    if "claude" in self.model_name:
                        content = [
                            "## Final Answer" + c.split("## Final Answer")[-1]
                            if "## Final Answer" in c
                            else c
                            for c in content
                        ]
                    content = [f"{r}\n\n{c}" for r, c in zip(reasoning, content)]
                except Exception:
                    pass
                try:
                    tokens["input_token"].append(outputs.usage.prompt_tokens)
                    tokens["output_token"].append(outputs.usage.completion_tokens)
                except Exception:
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
            latencies = [-1 for _ in resps]

        return all_outputs, answers, latencies, tokens

    async def batch_chat_completion(
        self,
        messages_lst,
        temperature=None,
        top_p=1.0,
        max_tokens=None,
        n=1,
        reasoning_effort=None,
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
                reasoning_effort=reasoning_effort,
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
        reasoning_effort=None,
    ):
        """
        Ensure the API call is rate-limited using the provided limiter.
        """
        async with self.limiter:
            result = await self.__chat_function__(
                chat=litellm.acompletion,
                messages=messages,
                temperature=temperature,
                top_p=top_p,
                max_tokens=max_tokens,
                n=n,
                reasoning_effort=reasoning_effort,
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
        reasoning_effort=None,
    ):
        """
        Internal chat function with retry logic.
        If together_deepseek is True, it uses the temporary DeepSeek-R1 API via Together.
        """
        # Use the temporary DeepSeek-R1 API if the flag is set
        if self.together_deepseek:
            for i in range(5):
                try:
                    # Run the synchronous deepseek call in a separate thread
                    ret = await asyncio.to_thread(
                        self._together_deepseek_chat,
                        messages,
                        temperature or self.temperature,
                        top_p,
                        max_tokens or 256,
                        n,
                    )
                    return ret
                except Exception as e:
                    print(
                        f"⚠️ DeepSeek-R1 call failed with error {e}, retrying in 10s..."
                    )
                    await asyncio.sleep(10)
                    continue
            return None
        else:
            # Use the default litellm API
            for i in range(5):
                try:
                    ret = await chat(
                        model=self.model_name,
                        api_key=self.api_key,
                        messages=messages,
                        temperature=temperature or self.temperature,
                        top_p=top_p,
                        max_tokens=max_tokens or 256,
                        seed=self.seed or 42,
                        n=n,
                        reasoning_effort=reasoning_effort,
                    )
                    return ret
                except Exception as e:
                    print(f"⚠️ Failed with error {e}, retrying in 10s...")
                    await asyncio.sleep(10)
                    continue
            return None

    def _together_deepseek_chat(self, messages, temperature, top_p, max_tokens, n):
        """
        Temporary method to call the deepseek-ai/DeepSeek-R1 model using the Together package.
        Note: The parameters temperature, top_p, max_tokens, and n are not used in this temporary implementation.
        """
        from together import Together

        client = Together()
        response = client.chat.completions.create(
            model="deepseek-ai/DeepSeek-R1",
            messages=messages,  # Using the provided messages
            n=n,  # Number of completions to generate
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
        )
        # Convert the response to a structure similar to litellm's response format
        choices = []
        try:
            for choice in response.choices:
                content = choice.message.content
                reasoning_content_match = re.search(
                    r"<think>(.*?)</think>", content, re.DOTALL
                )

                if reasoning_content_match:
                    reasoning_content = reasoning_content_match.group(1).strip()
                else:
                    reasoning_content = ""

                content = re.sub(
                    r"<think>.*?</think>", "", content, flags=re.DOTALL
                ).strip()

                choices.append(
                    {
                        "message": {
                            "content": content,
                            "reasoning_content": reasoning_content,
                        }
                    }
                )
        except Exception as e:
            print(f"Error processing Together response: {e}")
            return None
        return {"choices": choices}

    def query_once(
        self, messages, temperature=None, top_p=None, max_tokens=None, **kwargs
    ):
        """
        A single synchronous query.
        If together_deepseek is True, it uses the temporary DeepSeek-R1 API via Together.

        Parameters:
            messages (list): A list of message dictionaries representing the conversation.
                             Example: [{"role": "user", "content": "Hello, how are you?"}]
            temperature (float, optional): Sampling temperature. Defaults to self.temperature.
            top_p (float, optional): Top-p nucleus sampling parameter. Defaults to 1.0.
            max_tokens (int, optional): Maximum tokens to generate. Defaults to 256.

        Returns:
            dict or None: The API response from the synchronous call, or None if an error occurs.
        """
        if self.together_deepseek:
            try:
                from together import Together

                client = Together()
                response = client.chat.completions.create(
                    model="deepseek-ai/DeepSeek-R1",
                    messages=messages,
                )
                choices = []
                for choice in response.choices:
                    content = choice.message.content
                    reasoning_content_match = re.search(
                        r"<think>(.*?)</think>", content, re.DOTALL
                    )

                    if reasoning_content_match:
                        reasoning_content = reasoning_content_match.group(1).strip()
                    else:
                        reasoning_content = ""

                    content = re.sub(
                        r"<think>.*?</think>", "", content, flags=re.DOTALL
                    ).strip()

                    choices.append(
                        {
                            "message": {
                                "content": content,
                                "reasoning_content": reasoning_content,
                            }
                        }
                    )
                    return {"choices": choices}
            except Exception as e:
                print(f"⚠️ sync DeepSeek-R1 call encountered an error: {e}")
                return None
        else:
            try:
                response = litellm.completion(
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
