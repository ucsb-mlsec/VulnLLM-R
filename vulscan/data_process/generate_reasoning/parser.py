import argparse


class ArgumentGroup:
    """Base class for argument groups"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        pass


class CommonArgumentGroup(ArgumentGroup):
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add arguments that are common across all scripts"""

        parser.add_argument("--output_dir", type=str, default="datasets/reasoning_data")
        parser.add_argument("--input_dir", type=str, default="datasets/reasoning_data")
        parser.add_argument(
            "--dataset_type",
            type=str,
            default="clean_dataset",
            choices=["noisy_dataset", "clean_dataset", "ossfuzz_dataset", "redteam_dataset"],
        )
        parser.add_argument(
            "--training_set",
            type=str,
            default="train",
            choices=["train", "large_train", "small_train", "java"],
        )
        parser.add_argument("--model_name", type=str, default="Qwen/QwQ-32B")
        parser.add_argument("--file_name_prefix", type=str, default=None)


class ProcessingArgumentGroup(ArgumentGroup):
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--filter_all_length", type=int, default=8000, choices=[16000, 8000, 32000]
        )
        parser.add_argument("--filter_input_length", type=int, default=5000)


def _validate_dataset_training_set(args: argparse.Namespace):
    """Validate dataset type and training set combination"""
    if args.dataset_type == "noisy_dataset" and args.training_set == "train":
        raise ValueError(
            "For noisy_dataset, --training_set should be large_train or small_train"
        )


class ArgumentParser:
    """Configurable argument parser that supports multiple argument groups"""

    def __init__(self, *groups: ArgumentGroup):
        self.parser = argparse.ArgumentParser()
        self.groups = groups
        self._add_arguments()

    def _add_arguments(self) -> None:
        for group in self.groups:
            group.add_arguments(self.parser)

    def add_argument(self, *args, **kwargs):
        self.parser.add_argument(*args, **kwargs)

    def parse_args(self):
        args = self.parser.parse_args()
        _validate_dataset_training_set(args)
        return args
