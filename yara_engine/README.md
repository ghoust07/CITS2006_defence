Yara engine

requirements:

- Detect malware in the filesystem.
- Detect hidden files containing sensitive information (i.e., files were not encrypted but hidden by user(s) by mistake).
- Detect scripts.
- Detect executables accessing network resources.
- Detect malicious URLs an executable file is trying to access.
- Detect custom signatures (e.g., a specific string or pattern) you might find in the filesystem.

source: https://uwacyber.gitbook.io/cits2006/cits2006-assessments/project


todo:
- Find a list of attack vectors to care about
- Implement Yara rule matching logic
- Create a Yara rule database
- Implement a function to call csv
- Integrate Yara engine with your application
- Test and debug the Yara engine functionality
- Write documentation for the Yara engine

Comments:


The scripts yar file pings off to many things, producing lots of false positives need a better condition case 