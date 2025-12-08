import os

PROJECT_PATH = os.path.realpath(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


def parse_test_json_filename(filename):
    import re

    # Extract dataset, language, and model information from filename
    pattern = r"(?P<seq_len>\d+)__(?P<n>\d+)__(?P<dataset>[^_]+(?:_[^_]+)*)__(?P<ood>[^_]+(?:_[^_]+)*)__(?P<cot>[^_]+(?:_[^_]+)*)__(?P<language>[^_]+(?:_[^_]+)*)__(?P<policy>[^_]+(?:_[^_]+)*)__(?P<model_shortname>[\w.-]+)\.json"
    match = re.match(pattern, filename)
    if match:
        return match.groupdict()
    else:
        return None
