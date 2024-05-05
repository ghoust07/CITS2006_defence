import csv

def create_yara_rule(csv_filepath, output_filepath, rule_name, author):
    try:
        with open(csv_filepath, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            strings_section = []
            meta_section = f'\tdescription = "Rule to detect malware based on specific strings"\n\tauthor = "{author}"\n'

            for i, row in enumerate(reader):
                if row:
                    # Safely format each string to avoid code injection
                    safe_string = csv_escape(row[0])
                    strings_section.append(f'\t$string{i} = "{safe_string}" nocase')

            # Construct the Yara rule with meta, strings, and condition sections
            yara_rule = f"rule {rule_name}\n{{\nmeta:\n{meta_section}strings:\n" + "\n".join(strings_section) + "\n\ncondition:\n\tany of them\n\n\t//TODO: detect common malware tricks (masking extension), detect well-known malware? Cross-reference with database?\n}}\n"
            
            # Write the Yara rule to a file
            with open(output_filepath, 'w', encoding='utf-8') as f:
                f.write(yara_rule)
            
            print(f"Yara rule written to {output_filepath}")

    except FileNotFoundError:
        print(f"Error: The file {csv_filepath} does not exist.")
    except PermissionError:
        print(f"Error: Permission denied while accessing {csv_filepath}.")
    except Exception as e:
        print(f"An error occurred: {e}")

def csv_escape(s):
    """Escape potentially malicious sequences in strings."""
    return s.replace('"', '""').replace('\n', ' ').replace('\r', ' ')

# Usage example
create_yara_rule('mal_string.csv', 'generated_rule.yar', 'malware', 'Your Name')
