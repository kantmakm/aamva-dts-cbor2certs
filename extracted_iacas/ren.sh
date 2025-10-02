#! /bin/bash

for file in [0-9]_*.pem; do
  # Extract the number and the name
  prefix=${file%%_*}
  suffix=${file#*_}
  
  # CORRECTED: Added $(...) to execute the awk command
  new_prefix=$(awk -v p="$prefix" 'BEGIN { printf "%c", 96+p }')
  
  # Rename the file, showing the change
  mv -v "$file" "${new_prefix}_${suffix}"
done;

for file in *-*.pem; do
  mv -v "$file" "${file//-/_}"
done;

