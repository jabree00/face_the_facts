<h1>READ ME! (please)</h1>
<p>Face The Facts is a script that identifies package vulnerabilites within a given project.</p>

<h2>Resources Consulted</h2>
<ul>
    <li><a href="https://pypi.org/project/requests/">Using Python requests package</a></li>
    <li><a href="https://nvd.nist.gov/developers/vulnerabilities">Using NIST Vulnerability API</a></li>
    <li><a href="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=pip%20python">Sample NIST API Endpoint</a></li>
    <li><a href="https://www.w3schools.com/python/python_dictionaries_loop.asp">Looping through Python Dictionaries</a></li>
    <li><a href="https://www.w3schools.com/tags/tag_a.asp">Creating a tag elements</a></li>
    <li><a href="https://www.w3schools.com/python/ref_list_append.asp">Appending to Python list</a></li>
    <li><a href="https://www.w3schools.com/python/python_json.asp">Importing JSON package</a></li>
    <li><a href="https://www.geeksforgeeks.org/python/python-list-files-in-a-directory/">Listing files in a directory</a></li>
    <li><a href="https://www.w3schools.com/python/ref_list_pop.asp">Pop from list python</a></li>
    <li><a href="https://www.geeksforgeeks.org/python/python-ways-to-concatenate-two-lists/">Merge Python Lists</a></li>
    <li><a href="https://www.w3schools.com/python/python_match.asp">Python Matches</a></li>
    <li><a href="https://stackoverflow.com/questions/15221473/how-do-i-update-upgrade-pip-itself-from-inside-my-virtual-environment">Upgrading Pip</a></li>

</ul>

<h2>AI Disclosure</h2>
AI (Gemini) was used to conduct an initial search of tools that perform similar tasks. 

<h3>For identifying similar apps</h3>
Are there any apps that statically scan a python project for imports and tell the user what known vulnerabilities exist in the imported packages?

My follow-up prompts focused on verifying that these tools compare against a CVE database and determining whether these tools cost money. 

<h3>For debugging...</h3>

Prompt #1 (Described my installation error)
python venv keeps using anaconda 3.9 python instead of 3.14

Prompt #2 (Supplied my error message to get debugging guidance):
ERROR: Ignored the following yanked versions: 2.32.0, 2.32.1
ERROR: Ignored the following versions that require a different python version: 2.33.0 Requires-Python >=3.10; 2.33.1 Requires-Python >=3.10; 2.34.0 Requires-Python >=3.10; 2.34.0.dev1 Requires-Python >=3.10; 2.34.1 Requires-Python >=3.10; 2.34.2 Requires-Python >=3.10
ERROR: Could not find a version that satisfies the requirement requests===2.34.0 (from versions: 0.2.0, 0.2.1, 0.2.2, 0.2.3, 0.2.4, 0.3.0, 0.3.1, 0.3.2, 0.3.3, 0.3.4, 0.4.0, 0.4.1, 0.5.0, 0.5.1, 0.6.0, 0.6.1, 0.6.2, 0.6.3, 0.6.4, 0.6.5, 0.6.6, 0.7.0, 0.7.1, 0.7.2, 0.7.3, 0.7.4, 0.7.5, 0.7.6, 0.8.0, 0.8.1, 0.8.2, 0.8.3, 0.8.4, 0.8.5, 0.8.6, 0.8.7, 0.8.8, 0.8.9, 0.9.0, 0.9.1, 0.9.2, 0.9.3, 0.10.0, 0.10.1, 0.10.2, 0.10.3, 0.10.4, 0.10.6, 0.10.7, 0.10.8, 0.11.1, 0.11.2, 0.12.0, 0.12.1, 0.13.0, 0.13.1, 0.13.2, 0.13.3, 0.13.4, 0.13.5, 0.13.6, 0.13.7, 0.13.8, 0.13.9, 0.14.0, 0.14.1, 0.14.2, 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.1.0, 1.2.0, 1.2.1, 1.2.2, 1.2.3, 2.0.0, 2.0.1, 2.1.0, 2.2.0, 2.2.1, 2.3.0, 2.4.0, 2.4.1, 2.4.2, 2.4.3, 2.5.0, 2.5.1, 2.5.2, 2.5.3, 2.6.0, 2.6.1, 2.6.2, 2.7.0, 2.8.0, 2.8.1, 2.9.0, 2.9.1, 2.9.2, 2.10.0, 2.11.0, 2.11.1, 2.12.0, 2.12.1, 2.12.2, 2.12.3, 2.12.4, 2.12.5, 2.13.0, 2.14.0, 2.14.1, 2.14.2, 2.15.1, 2.16.0, 2.16.1, 2.16.2, 2.16.3, 2.16.4, 2.16.5, 2.17.0, 2.17.1, 2.17.2, 2.17.3, 2.18.0, 2.18.1, 2.18.2, 2.18.3, 2.18.4, 2.19.0, 2.19.1, 2.20.0, 2.20.1, 2.21.0, 2.22.0, 2.23.0, 2.24.0, 2.25.0, 2.25.1, 2.26.0, 2.27.0, 2.27.1, 2.28.0, 2.28.1, 2.28.2, 2.29.0, 2.30.0, 2.31.0, 2.32.2, 2.32.3, 2.32.4, 2.32.5)
ERROR: No matching distribution found for requests===2.34.0

Ultimately, I needed to find the file path of the Python 3.14 installation and supply that file path when creating my virtual environment. 
