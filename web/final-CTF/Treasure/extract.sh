#!/bin/bash

# Path to the CSV file
file_path="keyz.csv"

# Extract the second column (Age) from the CSV file
second_columns=$(tail -n +2 "$file_path" | cut -d',' -f2)

# Loop through the extracted values and use them as separate inputs
while IFS= read -r key; do
    echo "$key" >> key.pem
    # Your further processing or operations with each input goes here
    # For example, you can call a function or perform specific tasks with each age value
done <<< "$second_columns"
