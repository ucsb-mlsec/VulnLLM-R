from setuptools import setup, find_packages

setup(
    name="vulscan",
    version="0.1.0",
    description="Vulnerability scanning and analysis tools",
    author="SecMLR Team",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "wandb~=0.19.5",
        "aiolimiter~=1.2.1",
        "python-dotenv~=1.0.1",
        "orjson~=3.10.6",
        "PyYAML~=6.0.2",
        "loguru~=0.7.3",
        "deepspeed~=0.16.3",
        "liger-kernel==0.5.2",
    ],
    extras_require={
        "dev": [
            "pytest",
            "black",
            "isort",
            "flake8",
        ],
        "visual": [
            "matplotlib",
            "seaborn",
        ],
    },
)
