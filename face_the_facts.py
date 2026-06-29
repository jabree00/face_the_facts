import requests
import os 
import re
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
            writable.write(f'<p>References to this import as renames as {nicknames} in the files.</p>\n')
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
                    search = re.search(s + "\.",line)
                    if(search):
                        context.append(f"{filename}, Line {lineNumber}: {line}")
                lineNumber += 1
    return context     

'''
Give an package name conduct a search
'''
def query_nist_database(import_name):
    package_info = get_package_info(import_name)
    if package_info[0] != None and package_info[1] != None:
        BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        QUERY_PARAMETER = f"cpeName=cpe:2.3:a:{package_info[0]}:{import_name}:{package_info[1]}:*:*:*:*:python:*:*"

    # Use keyword search as a fallback alternative
    else:
        BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        QUERY_PARAMETER = "keywordSearch=" + import_name + " " + "python"

    QUERY_PARAMETER = QUERY_PARAMETER.replace(" ","%20")
    # Add the Authorization header
    headers = {
        'Accept': 'application/json',
        'apikey': f'{API_KEY}'
    }

    FULL_URL = BASE_URL + "?" + QUERY_PARAMETER
    response = requests.get(FULL_URL,headers=headers).json()
    cve_data = extract_cves(response)
    return cve_data 

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
def get_package_info(package_name):
    """
    Fetch package author and latest version from PyPI.

    Args:
        package_name (str): Name of the package.

    Returns:
        tuple: (author, latest_version)
               Returns (None, None) on error or if not found.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"

    try:
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return (None, None)

        data = response.json()
        info = data.get("info", {})

        author = info.get("author") or None
        version = info.get("version") or None

        if author is None and version is None:
            return (None, None)

        return (author, version)

    except Exception:
        return (None, None)

def main(): 
    
    intro = '''FACE THE FACTS...
    Your project probably has vulnerabilities.
    This tool can help by comparing imports in your project 
    against vulnerabilities in the NIST database. 
    '''
    print(intro)
    print("*" * 50)

    project_dir = input("\nType your project path: ") 
    print("*" * 50)
    if(project_dir == ''):
        print(f"Testing with default sample: ./sample_projects/simple_calculator")
        print("Please wait. This may take a while...")
        project_dir = "./sample_projects/"
    else:
        print(f"You typed: {project_dir}")


    paths = find_paths(project_dir)
    paths.append("./face_the_facts.py")
    import_names = find_imports(paths)
    print(import_names)
    setup_report()

    for i in import_names.keys():
        import_renames = [i] + import_names[i]
        context = get_context(paths, import_renames)
        cves = query_nist_database(i)
        update_report(i, import_names[i], context, cves)

    finalize_report()
    

main()


