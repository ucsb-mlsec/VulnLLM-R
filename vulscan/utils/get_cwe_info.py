import os

import pandas as pd

from vulscan.utils.project_info import PROJECT_PATH

cwe_descriptions = None


def _init_cwe_descriptions():
    global cwe_descriptions
    cwe_df = pd.read_csv(os.path.join(PROJECT_PATH, "datasets/cwe-details.csv"))
    cwe_descriptions = {}
    for _, row in cwe_df.iterrows():
        if pd.isna(row["Extended Description"]):
            cwe_descriptions[row["CWE-ID"]] = row["Name"] + ". " + row['Description']
        else:
            cwe_descriptions[row["CWE-ID"]] = row["Name"] + ". " + row["Extended Description"]


def get_cwe_info(cwe_id: int) -> str:
    """
    Describe the CWE with the given ID.

    Args:
        cwe_id: The ID of the CWE to describe.

    Returns:
        A string containing the description of the CWE.

    Example:
    input: 120
    output: 'Buffer Copy without Checking Size of Input (Classic Buffer Overflow)'
    """
    if cwe_descriptions is None:
        _init_cwe_descriptions()

    return cwe_descriptions.get(cwe_id, "Unknown CWE")
