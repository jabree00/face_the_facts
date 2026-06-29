import requests
import os 
import re
import sys
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

REPORT_FILENAME = "results.html"
API_KEY = os.getenv("API_KEY")

'''
Given a directory, find CVES of all identified files
'''
def find_paths(dir):
    dir_listing = os.listdir(dir)
    paths = []
    
    for current in dir_listing:
        path = dir + "/" + current
        if os.path.isfile(path) and Path(path).suffix == ".py" :
            paths.append(path)

        elif(os.path.isdir(path)):
            paths += find_paths(path)

    return paths

'''
Given a file, find all of the unique imports in the project
'''
def find_imports(paths):
    imports_dict = {} 

    for path in paths:
        with open(path,"r") as f:
            for line in f: 
                rename_import_regex = r"\Aimport\s\w+\sas\s\w+"
                match = re.match(rename_import_regex, line)
                if (match):
                    found = match.group()
                    import_name = found.split()[1]
                    nickname = found.split()[3]
                    if import_name not in imports_dict:
                       imports_dict[import_name] = [nickname]
                    else:
                        imports_dict[import_name].append(nickname)

                submodule_rename_import = r"\Afrom\s\w+\simport\s\w+\sas\s\w+"
                match = re.match(submodule_rename_import, line)
                if (match):
                    found = match.group()
                    import_name = found.split()[1]
                    nickname = found.split()[5]
                    if import_name not in imports_dict:
                       imports_dict[import_name] = [nickname]
                    else:
                        imports_dict[import_name].append(nickname)

                #Find basic imports as well
                simple_import_regex = r"\Aimport\s\w+"
                match = re.match(simple_import_regex, line)
                if (match):
                    found = match.group()
                    import_name = found.split()[1]
                    if import_name not in imports_dict:
                        imports_dict[import_name] = []
        
    return imports_dict

def setup_report():
    try:
        writable = open(REPORT_FILENAME,"w")
        writable.write(f'<!DOCTYPE html>\n')
        writable.write(f'<html>\n')
        writable.write(f'<head>\n')
        writable.write(f'<title>Face the Facts: Report</title>\n')
        writable.write(f'<link rel="stylesheet" href="style.css">\n')
        writable.write(f'</head>\n')
        writable.write(f'<body>\n')
        writable.close()

    except Exception as e:
        print("File could not be written to.")


def finalize_report():
    writable = open(REPORT_FILENAME,"a")
    writable.write("</body>\n")
    writable.write("</html>\n")
    writable.close()

'''
Given a file, find all of the imports and related CVES
'''
def update_report(import_name, nicknames, context, cves):
    try: 
        writable = open(REPORT_FILENAME,"a")
        writable.write(f'<h2>Import Name: {import_name}</h2>\n')
        if not nicknames == []:
            writable.write(f'<p>References to this import are renamed as {nicknames} in the files.</p>\n')
        writable.write(f"<p>There are {len(context)} references to this import in the project.</p>\n")
        writable.write(f"<p>There are {len(cves)} relevant cves associated with this import in the project.</p>\n")
        writable.write(f"<h3>Contextual Usage:</h3>\n") 
        writable.write(f"<ol>\n")
        for line in context:
            writable.write(f"<li>{line}</li>\n")
        writable.write(f"</ol>\n")
        writable.write(f"<h3>Vulnerabilities:</h3>\n")
        writable.write(f"<ol>\n")
        for cve in cves:
            writable.write(f"<li>{cve}</li>\n")
        writable.write(f"</ol>\n")
        writable.close()

    except:
        print("Error updating results")

'''
Given an import, provide the context of the import 
'''
def get_context(paths, searchables):
    context = []
    lineNumber = 1
    for path in paths: 
        filename = Path(path).name
        with open(path,"r") as f:
            for line in f: 
                for s in searchables:
                    search = re.search(s + "\\.",line)
                    if(search):
                        context.append(f"{filename}, Line {lineNumber}: {line}")
                lineNumber += 1
    return context     

'''
Give an package name conduct a search
'''
def query_nist_database(import_name):
    version_info = get_version_info(import_name)
    vendor_name = get_vendor_name(import_name)
    if (version_info != None) and (vendor_name != None):
        BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        QUERY_PARAMETER = f"cpeName=cpe:2.3:a:{vendor_name}:{import_name}:{version_info}:*:*:*:*:python:*:*"

    # Use keyword search as a fallback alternative
    else:
        print(f"Import {import_name}: No NVD vendor found. Using keyword not cpe search.")
        BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        QUERY_PARAMETER = "keywordSearch=" + import_name + " python package"

    QUERY_PARAMETER = QUERY_PARAMETER.replace(" ","%20")
    # Add the Authorization header
    headers = {
        'Accept': 'application/json',
        'apikey': f'{API_KEY}'
    }

    FULL_URL = BASE_URL + "?" + QUERY_PARAMETER
    response = requests.get(FULL_URL,headers=headers)

    if (response.status_code == 200):
        response = response.json()
        cve_data = extract_cves(response)
        return cve_data
    return []

'''
Helper function for query_nist_database
'''
def extract_cves(json_data):
    cve_data = []
    relevant_json = json_data.get("vulnerabilities")
    for current in relevant_json:
        cve = current.get("cve")
        cve_id = cve.get("id")
        cve_description = cve.get("descriptions")[0]
        cve_dict = {
            "id": cve_id, 
            "description": cve_description
        }
        cve_data.append(cve_dict)
    return cve_data

'''
AI-generated helper function
'''
def get_vendor_name(package_name: str) -> str | None:
    """
    Queries the NVD CPE API to resolve and return the official 
    assigned vendor name for a given package name. Returns None if not found.
    """
    # The official NVD API endpoint for CPE lookup
    url = "https://nist.gov"
    
    # Query parameters using keywordSearch to target the package name
    params = {
        "keywordSearch": package_name,
        "resultsPerPage": 1  # We only need the first valid record to extract the vendor
    }
    
    try:
        # Timeout prevents your script from hanging indefinitely if NVD is slow
        response = requests.get(url, params=params, timeout=10)
        
        # Guard clause for HTTP errors (e.g., rate-limiting 403/429)
        if response.status_code != 200:
            return None
            
        data = response.json()
        products = data.get("products", [])
        
        # If no products match the keyword, return None
        if not products:
            return None
            
        # Extract the full CPE string from the first matching product item
        cpe_string = products[0]["cpe"]["cpeName"]
        
        # Example string format: "cpe:2.3:a:numfocus:pandas:2.2.1:*:*:*:*:*:*:*"
        cpe_parts = cpe_string.split(":")
        
        # Ensure the string is long enough to safely extract index 3 (the vendor)
        if len(cpe_parts) > 3:
            return cpe_parts[3]
            
        return None

    except (requests.RequestException, KeyError, IndexError):
        # Gracefully handle network timeouts, drops, or unexpected API payload changes
        return None


'''
AI-generated helper function
'''
def get_version_info(package_name):
    """
    Fetch latest version from PyPI.

    Args:
        package_name (str): Name of the package.

    Returns:
        latest_version or None if error or if not found.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"

    try:
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return None

        data = response.json()
        info = data.get("info", {})
        version = info.get("version") or None
        return version
    
    except Exception:
        return None

def main(): 
    
    intro = '''FACE THE FACTS...
    Your project probably has vulnerabilities.
    This tool can help by comparing imports in your project 
    against vulnerabilities in the NIST database. 
    This tools assumes that you are using the lastest version of a given import.
    '''
    print(intro)
    print("*" * 50)

    project_dir = input("\nType your project path: ") 
    print("*" * 50)
    if(project_dir == ''):
        print(f"Testing with default sample: ./sample_projects/")
        print("Please wait. This may take a while...")
        project_dir = "./sample_projects/"
    else:
        print(f"You typed: {project_dir}")


    paths = find_paths(project_dir)
    paths.append("./face_the_facts.py")
    import_names = find_imports(paths)
    print("Found these imports: " + str(import_names.keys()))
    setup_report()
    for i in import_names.keys():
        print(f"Investigating module {i}.")
        import_renames = [i] + import_names[i]
        context = get_context(paths, import_renames)
        if (i in sys.builtin_module_names) or (i in sys.stdlib_module_names):
            print(f"Skipping CVES for built-in module {i}.")
            cves = query_nist_database(i)
        else:
            cves = []
        update_report(i, import_names[i], context, cves)

    finalize_report()
    

main()


