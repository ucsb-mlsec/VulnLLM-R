#!/bin/bash

set -e

echo "Current directory: $(pwd)"
# should under ./VulnScan-r0

# Check if the correct number of arguments is provided
if [ $# -ne 1 ]; then
    echo "Usage: ./scripts/run_codeql.sh <dataset>"
    echo "Supported datasets: seccodeplt, juliet"
    echo "Example usage: ./scripts/run_codeql.sh seccodeplt or ./scripts/run_codeql.sh juliet"
    exit 1
fi

# Read the argument
DATASET=$1

# Check if CodeQL is already installed
if [ ! -d "$HOME/codeql-home" ]; then
    echo "CodeQL not found. Running setup..."
    ./baseline/codeql/codeql_setup.sh
else
    echo "CodeQL already exists in $HOME/codeql. Skipping setup."
fi

#  CodeQL command
if [ "$DATASET" == "seccodeplt" ]; then
    # Python dataset
    python ./baseline/codeql/codel_analyze_data/covert_to_file.py
    cd ./baseline/codeql/codel_analyze_data/python
    create_cmd="codeql database create codeqldb --language=python --overwrite"
    analyze_cmd="codeql database analyze codeqldb --rerun \$HOME/codeql-home/codeql-repo/python/ql/src/codeql-suites/python-code-scanning.qls --format=csv --output=./codeql_seccodeplt.csv"
elif [ "$DATASET" == "juliet" ]; then
    # C
    cd ./baseline/codeql/codel_analyze_data/c
    create_cmd="codeql database create codeqldb --language=cpp -c \"x86_64-w64-mingw32-gcc -c $(ls CWE*.c) $(ls CWE*.cpp)\" --overwrite"
    # manually run: codeql database create codeqldb --language=cpp -c "x86_64-w64-mingw32-gcc -c $(ls CWE*.c) $(ls CWE*.cpp)" --overwrite
    analyze_cmd="codeql database analyze codeqldb --rerun \$HOME/codeql-home/codeql-repo/cpp/ql/src/codeql-suites/cpp-code-scanning.qls --format=csv --output=./codeql_juliet.csv"
    # manually run: codeql database analyze codeqldb --rerun $HOME/codeql-home/codeql-repo/cpp/ql/src/codeql-suites/cpp-code-scanning.qls --format=csv --output=./codeql_juliet.csv
fi

echo "Running: $create_cmd"
eval $create_cmd
if [ $? -ne 0 ]; then
    echo "Error running CodeQL create command"
    exit 1
fi

echo "Running: $analyze_cmd"
eval $analyze_cmd
if [ $? -ne 0 ]; then
    echo "Error running CodeQL analyze command"
    exit 1
fi

rm -f *.o

cd ../..
echo "Current directory: $(pwd)"
python calculate_results.py --dataset $DATASET