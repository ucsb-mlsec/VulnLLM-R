from vulscan.utils.get_cwe_info import get_cwe_info
from vulscan.utils.sys_prompts import (
    reasoning_user_prompt,
    reduced_reasoning_user_prompt,
)


def create_example_vul(
    cve_data,
    use_policy=False,
    use_free_policy=False,
    use_own_cot=False,
    reduced=False,
):
    is_vul = "yes" if cve_data["target"] else "no"
    if use_policy or use_free_policy:
        policy = (
            "You should only focusing on checking if the code contains the following cwe: "
            if not use_free_policy
            else "A possible related cwe: "
        )
        for cwe_id in cve_data["CWE_ID"]:
            # extract number
            cwe_number = int(cwe_id.split("-")[-1])
            policy += f"\n- {cwe_id}: {get_cwe_info(cwe_number)}"
            assert "Unknown CWE" not in policy, f"Unknown CWE: {cwe_id} is detected"
    else:
        policy = ""
    if use_own_cot:
        instruction = """\
Please think step by step and follow the following procedure.
Step 1: understand the code and identify key instructions and program states 
Step 2: come up with the constraints on the identified instructions or states to decide if the code is vulnerable 
Step 3: Predict the actual program states and decide if it follows the constraints 
Step 4: Tell whether the code is vulnerable based on the analysis above 

Finally you should STRICTLY structure your results as follows:
"""
    else:
        instruction = "You should STRICTLY structure your response as follows:"
    if cve_data["CWE_ID"] is None:
        pass
    if len(cve_data["CWE_ID"]) > 1:
        pass
    vul_type = ",".join(cve_data["CWE_ID"]) if cve_data["target"] else "N/A"
    output = "#judge: " + is_vul + "\n#type: " + vul_type
    if reduced:
        formatted_prompt = reduced_reasoning_user_prompt.format(
            CODE=cve_data["code"], CWE_INFO=policy, REASONING=instruction
        )
    else:
        formatted_prompt = reasoning_user_prompt.format(
            CODE=cve_data["code"], CWE_INFO=policy, REASONING=instruction
        )
    return formatted_prompt, output
