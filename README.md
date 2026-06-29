```md
# READ ME! (please)

Face the Facts is a script that identifies package vulnerabilities within a given Python project.

---

## Resources Consulted

- [Using Python requests package](https://pypi.org/project/requests/)
- [Using NIST Vulnerability API](https://nvd.nist.gov/developers/vulnerabilities)
- [Sample NIST API Endpoint](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=pip%20python)
- [Looping through Python Dictionaries](https://www.w3schools.com/python/python_dictionaries_loop.asp)
- [Creating anchor tag elements](https://www.w3schools.com/tags/tag_a.asp)
- [Appending to Python list](https://www.w3schools.com/python/ref_list_append.asp)
- [Importing JSON package](https://www.w3schools.com/python/python_json.asp)
- [Listing files in a directory](https://www.geeksforgeeks.org/python/python-list-files-in-a-directory/)
- [Pop from Python list](https://www.w3schools.com/python/ref_list_pop.asp)
- [Merge Python Lists](https://www.geeksforgeeks.org/python/python-ways-to-concatenate-two-lists/)
- [Python Matches](https://www.w3schools.com/python/python_match.asp)
- [Upgrading Pip](https://stackoverflow.com/questions/15221473/how-do-i-update-upgrade-pip-itself-from-inside-my-virtual-environment)
- [Regex Match Python](https://www.geeksforgeeks.org/python/re-match-in-python/)
- [Reading File in Python](https://www.w3schools.com/python/python_file_open.asp)
- [Python Regex Special Characters](https://www.w3schools.com/python/python_regex.asp)
- [Using Text Wrap](https://stackoverflow.com/questions/68094079/wrap-text-in-txt-file-with-python3)
- [More on Using Text Wrap](https://www.w3schools.com/python/ref_module_textwrap.asp)
- [Linking Stylesheets](https://www.w3schools.com/css/css_howto.asp)
- [Adding Initial HTML Components](https://www.w3schools.com/tags/tag_doctype.asp)

---

## Problem Definition

### What specific problem are you addressing?
This project identifies vulnerabilities statically, without running the code. This avoids unnecessary exposure to vulnerabilities.

### Why is the problem important?
Manually identifying all vulnerabilities in a codebase is time-consuming. This makes developers less likely to take the time to find those vulnerabilities.

### What existing tools or approaches exist?
There are several existing tools including:
- pip-audit
- Trivy
- OSV Scanner

### What gap does your tool fill?
In addition to being open-source and free, my tool provides the context of the import's usage. Ideally, this allows the analyst to more quickly determine and remember whether that vulnerability may apply to the project.

---

## System Design

### High-level architecture
This project runs in a single Python script.

### Technology choices and justification
Python is a widely used programming language, so this allows the program to be easily run, understood, and adapted.

---

## Evaluation

### How did you test the tool?
Gemini created a small Python project. I added additional imports. I commented out one import and added an `import ______ as _____` statement to see if the script is effective in these cases.

### Results
The script successfully identifies many CVEs relevant to the import. However, some imports have simple names that could be confused with non-Python vulnerabilities (for example, the `requests` package).

If the package name resembles a dictionary word (where `colorama` would be a non-example), additional keywords should be added to the search.

---

## Known Issues

- The current code scans all files (not just Python files), so there could be false positives from import-like lines.
- There is a large possibility for redundant API calls from files that import the same packages.

---

## How to Run this Project

### Setup

- Download VSCode
- Install Python if needed

### Create and activate virtual environment

\`\`\`bash
python -m venv venv
source venv/bin/activate
\`\`\`

### Install dependencies

\`\`\`bash
pip install -r requirements.txt
\`\`\`

### Run the project

- Select the latest version of Python (`venv`) as your interpreter

\`\`\`bash
python3 face_the_facts.py
\`\`\`

---

## AI Disclosure

AI (Gemini) was used to conduct an initial search of tools that perform similar tasks.

### For Identifying Similar Apps

Prompt:

\`\`\`
Are there any apps that statically scan a python project for imports and tell the user what known vulnerabilities exist in the imported packages?
\`\`\`

Follow-up prompts focused on verifying that these tools compare against a CVE database and determining whether they cost money.

---

### For Debugging

#### Prompt #1

\`\`\`
python venv keeps using anaconda 3.9 python instead of 3.14
\`\`\`

#### Prompt #2
I supplied my error message to get debugging guidance.

Ultimately, I needed to find the file path of the Python 3.14 installation and supply that path when creating my virtual environment.

#### Prompt #3

\`\`\`
newline character causing error python file writing
\`\`\`

I did not end up using ChatGPT's advice, but instead avoided using the character that was causing the issue.

---

### For Generating Sample Python Projects for Testing

Gemini gave me the `simple_calculator` project after this prompt:

\`\`\`
sample python project with imports
\`\`\`

---

## Prompts for Revisions

- Give me a basic CSS file for a report with headers, paragraphs, ul, li. It should look professional.
- Give me a basic CSS file that covers all of the major HTML elements. This is for a report. The goal is to make the page readable, simple, but aesthetic. One thing: make the page margin 20% on both sides.
- Give me a Python project that uses lots of imports (this is for testing purposes). Use different styles of import statements.
- I asked Gemini to show me how to supply an API key to an NVD GET request.
- Give me a Python function that takes in a package name and returns the author and the latest version number of the package. If neither is found or there is an error, return `None` in the tuple output.
- Clean up this README.md file to use unordered lists where there is just a series of bullets. If any other formatting is messed up or has syntax errors, please fix.

---

## Other Tips

A NIST API key can be requested here:  
https://nvd.nist.gov/developers/request-an-api-key
```
