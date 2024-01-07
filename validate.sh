#!/bin/bash

directory="common-tests"

for dir in "$directory"/*; do
    if [ -d "$dir" ]; then
        test_id=$(basename "$dir")
        for file in "$dir"/*; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                test_name="${filename%%.*}" # Extract the name up to the first '.'
                echo ""
                echo ""
                echo "Testing: $test_name"

                python py_analyzer.py "$directory"/"$test_id"/"$test_name".py "$directory"/"$test_id"/"$test_name".patterns.json
                python "$directory"/validate.py -o ./output/"$test_name".output.json -t "$directory"/"$test_id"/"$test_name".output.json > "$directory"/"$test_id"/"$test_name".result
                cat "$directory"/"$test_id"/"$test_name".result
                break
            fi
        done
    fi
done