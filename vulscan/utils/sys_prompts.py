sft_sys_prompt = (
    "Your role as an assistant involves thoroughly exploring questions through a systematic long \
        thinking process before providing the final precise and accurate solutions. This requires \
        engaging in a comprehensive cycle of analysis, summarizing, exploration, reassessment, reflection, \
        backtracing, and iteration to develop well-considered thinking process. \
        Please structure your response into two main sections: Thought and Solution. \
        In the Thought section, detail your reasoning process using the specified format: \
        <|begin_of_thought|> {thought with steps separated with '\n\n'} \
        <|end_of_thought|> \
        Each step should include detailed considerations such as analisying questions, summarizing \
        relevant findings, brainstorming new ideas, verifying the accuracy of the current steps, refining \
        any errors, and revisiting previous steps. \
        In the Solution section, based on various attempts, explorations, and reflections from the Thought \
        section, systematically present the final solution that you deem correct. The solution should \
        remain a logical, accurate, concise expression style and detail necessary step needed to reach the \
        conclusion, formatted as follows: \
        <|begin_of_solution|> \
        {final formatted, precise, and clear solution} \
        <|end_of_solution|> \
        Now, try to solve the following question through the above guidelines:"
)

qwen_sys_prompt = "You are a helpful and harmless assistant. You are Qwen developed by Alibaba. You should think step-by-step."
qwq_sys_prompt_generation = "You are a helpful and harmless assistant. You are Qwen developed by Alibaba. You should reason about the program states and think step-by-step."

default_sys_prompt = "You are a helpful assistant. You should think step-by-step."

deepseek_sys_prompt = (
    "You are a helpful and harmless code assistant. You should think step-by-step."
)

our_cot = """Please think step by step and follow the following procedure.
Step 1: understand the code and identify key instructions and program states; 
Step 2: come up with the constraints on the identified instructions or states to decide if the code is vulnerable; 
Step 3: Predict the actual program states and decide if it follows the constraints; 
Step 4: Tell whether the code is vulnerable based on the analysis above
\n     
"""

policy = "You should only focus on checking and reasoning if the code contains one of the following CWEs:"
new_policy = "You should only focus on checking and reasoning if the code contains one of the following CWEs, or other cwe if you think it is more relevant:"
long_context_reasoning_user_prompt = """\
You are an advanced vulnerability detection model. \
Your task is to check if a specific vulnerability exists in a given piece of code. \
The code may contain a long context, which is the stack trace of the function. \
They are separated by "// context" and "// target function". \
You need to output whether the target function is vulnerable and the type of vulnerability present with cwe id (CWE-xx). \
\n
## You are given the following code snippet:
```
{CODE}
```
\n
{CWE_INFO}
\n
{REASONING} 
\n
## Final Answer
#judge: <yes/no>
#type: <vulnerability type>

## Additional Constraint:
- If `#judge: yes`, then `#type:` **must contain exactly one CWE**.
- If `#judge: yes`, the model must output **only the most probable CWE** related to the given code snippet.
{ADDITIONAL_CONSTRAINT}

## Example
- If the target function is vulnerable to a CWE-79, you should finally output:
## Final Answer
#judge: yes
#type: CWE-79

- If the target function does not contain vulnerabilities related to the given CWE, you should finally output:
## Final Answer
#judge: no
#type: N/A
"""
reasoning_user_prompt = """\
You are an advanced vulnerability detection model. \
Your task is to check if a specific vulnerability exists in a given piece of code. \
You need to output whether the code is vulnerable and the type of vulnerability present with cwe id (CWE-xx). \
\n
## You are given the following code snippet:
```
{CODE}
```
\n
{CWE_INFO}
\n
{REASONING} 
\n
## Final Answer
#judge: <yes/no>
#type: <vulnerability type>

## Additional Constraint:
- If `#judge: yes`, then `#type:` **must contain exactly one CWE**.
- If `#judge: yes`, the model must output **only the most probable CWE** related to the given code snippet.
{ADDITIONAL_CONSTRAINT}

## Example
- If the code is vulnerable to a CWE-79, you should finally output:
## Final Answer
#judge: yes
#type: CWE-79

- If the code does not contain vulnerabilities related to the given CWE, you should finally output:
## Final Answer
#judge: no
#type: N/A
"""

reduced_reasoning_user_prompt = """\
You are an advanced vulnerability detection model. \
Your task is to check if a specific vulnerability exists in a given piece of code. \
You need to output whether the code is vulnerable and the type of vulnerability present with cwe id (CWE-xx). \
\n
## You are given the following code snippet:
```
{CODE}
```
\n
{CWE_INFO}
\n
{REASONING} 
\n
## Final Answer
#judge: <yes/no>
#type: <vulnerability type>
"""


addition_constition = {
    # 150078: "- Always check that strings allocated and populated from external sources are properly null-terminated. Especially when exact-sized memory allocation is used, to prevent out-of-bounds reads when the string is later processed.",
    142258: "Check if the function is designed to return a status code indicating success or failure. A `void` return type may indicate a lack of error handling or permission checks.",
    142257: "Check if the function is designed to return a status code indicating success or failure. A `void` return type may indicate a lack of error handling or permission checks.",
    402262: "Ensure that format strings are fixed and not influenced by external input.",
    400077: "Look for arithmetic operations, especially decrement operations that are performed on variables that can potentially hold minimum integer values.",
    149585: "- Confirm that the code includes checks for absolute paths, using security flags. \
   - Verify that the code correctly identifies and handles absolute paths by setting errors and returning failure codes when such paths are detected.",
    401142: "- Identify the use of strong, well-regarded cryptographic algorithms, and understand that the use of such algorithms mitigates vulnerabilities like CWE-327 by providing adequate cryptographic strength.",
    401248: "- Identify that the benign code does not perform a separate check before using the resource, and understand that by directly attempting to use the resource, the code avoids the window of opportunity for a race condition.",
    402701: "Note the absence of conditional logic that prevents the exposure of environment variables. If the code always executes the output of an environment variable without any checks, it is likely vulnerable.",
    400260: "Ensure that both lower and upper bounds are checked before using an index to access an array, and recognize the addition of a condition of data size as a fix.",
    402960: "Recognize code that uses static, predefined strings for file paths, ensuring that no external input can influence the path construction.",
    402054: "Verify that the code includes checks to validate inputs before they are used in division operations. This includes ensuring the divisor is not zero or close to zero.",
    401380: "Ensure that input values are validated and constrained within safe limits before being used to control resource consumption.",
    10816: "Ensure that memory allocation and deallocation are handled correctly, with no operations on pointers after deallocation, and verify that any deallocated pointers are not used in subsequent operations.",
    400518: "Ensure that all elements of an array or structure are initialized before any use. This can be achieved by initializing the entire array in a loop before any other operations.",
    3545: "Ensure that pointers are validated before they are dereferenced. This includes checking if a pointer is `NULL` and handling such cases appropriately, often using conditional statements or error-handling constructs.",
    # There's two 400933, this is for cwe-758, while adding this prompt won't affect the other one's correctness (which is in cwe-319).
    400933: "Identify code patterns where objects are used without proper initialization. Specifically, look for instances where a pointer is dereferenced to access or copy data from an uninitialized object.",
    403190: "Prefer index-based traversal over pointer arithmetic when iterating through a buffer. This ensures that the original pointer remains unchanged and can be safely freed.",
    401604: "Ensure that the type of data being accessed is consistent with the type of the variable it is pointing to.",
    150082: "Ensure that any operation involving buffers or arrays checks the boundaries before accessing elements. Look for conditions where the code might access elements beyond the allocated memory.",
    2674: "Ensure that input is validated before being used in arithmetic operations. This includes checking that the input is within a safe range to prevent overflow.",
    149978: "Identify code sections where data is written to buffers. Pay attention to calculations involving buffer sizes and offsets. Look for operations that modify buffer pointers or indices, especially in loops or conditional statements.",
}

# still need to be tested whether the prompts work
addition_constition_cwe = {
    "CWE-134": "Ensure that format strings are fixed and not influenced by external input.",  # Use of Externally-Controlled Format String
    "CWE-191": "Look for arithmetic operations, especially decrement operations that are performed on variables that can potentially hold minimum integer values.",  # Integer Underflow
    "CWE-22": "Confirm that the code includes checks for absolute paths, using security flags, and verify that the code correctly identifies and handles absolute paths by setting errors and returning failure codes when such paths are detected.",  # Path Traversal
    "CWE-327": "Identify the use of strong, well-regarded cryptographic algorithms, and understand that the use of such algorithms mitigates vulnerabilities by providing adequate cryptographic strength.",  # Use of a Broken or Risky Cryptographic Algorithm
    "CWE-367": "Identify that the benign code does not perform a separate check before using the resource, and understand that by directly attempting to use the resource, the code avoids the window of opportunity for a race condition.",  # TOCTOU Race Condition
    "CWE-526": "Note the absence of conditional logic that prevents the exposure of environment variables. If the code always executes the output of an environment variable without any checks, it is likely vulnerable.",  # Cleartext Storage of Sensitive Information in an Environment Variable
    "CWE-121": "Ensure that both lower and upper bounds are checked before using an index to access an array, and recognize the addition of a condition of data size as a fix.",  # Stack-based Buffer Overflow
    "CWE-23": "Recognize code that uses static, predefined strings for file paths, ensuring that no external input can influence the path construction.",  # Relative Path Traversal
    "CWE-369": "Verify that the code includes checks to validate inputs before they are used in division operations. This includes ensuring the divisor is not zero or close to zero.",  # Divide By Zero
    "CWE-400": "Ensure that input values are validated and constrained within safe limits before being used to control resource consumption.",  # Uncontrolled Resource Consumption
    "CWE-416": "Ensure that memory allocation and deallocation are handled correctly, with no operations on pointers after deallocation, and verify that any deallocated pointers are not used in subsequent operations.",  # Use After Free
    "CWE-457": "Ensure that all elements of an array or structure are initialized before any use. This can be achieved by initializing the entire array in a loop before any other operations.",  # Use of Uninitialized Variable
    "CWE-476": "Ensure that pointers are validated before they are dereferenced. This includes checking if a pointer is `NULL` and handling such cases appropriately, often using conditional statements or error-handling constructs.",  # NULL Pointer Dereference
    "CWE-758": "Identify code patterns where objects are used without proper initialization. Specifically, look for instances where a pointer is dereferenced to access or copy data from an uninitialized object.",  # Reliance on Undefined, Unspecified, or Implementation-Defined Behavior
    "CWE-761": "Prefer index-based traversal over pointer arithmetic when iterating through a buffer. This ensures that the original pointer remains unchanged and can be safely freed.",  # Free of Pointer not at Start of Buffer
    "CWE-843": "Ensure that the type of data being accessed is consistent with the type of the variable it is pointing to.",  # Type Confusion
    "CWE-125": "Ensure that any operation involving buffers or arrays checks the boundaries before accessing elements. Look for conditions where the code might access elements beyond the allocated memory.",  # Out-of-bounds Read
    "CWE-190": "Ensure that input is validated before being used in arithmetic operations. This includes checking that the input is within a safe range to prevent overflow.",  # Integer Overflow or Wraparound
    "CWE-787": "Identify code sections where data is written to buffers. Pay attention to calculations involving buffer sizes and offsets. Look for operations that modify buffer pointers or indices, especially in loops or conditional statements.",  # Out-of-bounds Write
    # "CWE-338": "", # Use of Cryptographically Weak Pseudo-Random Number Generator
    # "CWE-176": "", # Improper Handling of Unicode Encoding
    # "CWE-319": "", # Cleartext Transmission of Sensitive Information
}
