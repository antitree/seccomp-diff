input_file = "default.byte"
output_file = "default.py"

# Read and update lines
with open(input_file, "r") as infile:
    lines = infile.readlines()

updated_lines = [line.rstrip("\n") + ",\n" for line in lines]

# Write the updated lines back to a new file
with open(output_file, "w") as outfile:
    outfile.writelines(updated_lines)