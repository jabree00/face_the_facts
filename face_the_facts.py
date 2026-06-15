import requests
import os 
import re
import textwrap

'''
Given a directory, find CVES of all identified files
'''
def recursively_scan_project(dir):
    dir_listing = os.listdir(dir)
    for current in dir_listing:
        path = dir + "/" + current
        #handle files 
        if(os.path.isfile(path)):
            write_aggregated_data(path,"results.txt")
        
        #handle directories 
        elif(os.path.isdir(path)):
            recursively_scan_project(path)

'''
Given a file, find all of the imports and related CVES
'''
def write_aggregated_data(file_path, write_file_path):

    try: 
        wrapper = textwrap.TextWrapper(width = 50)
        writable = open(write_file_path,"w")
        writable.write(f'''FILE FOUND: {file_path}\n\n''')
        
        imports = find_imports(file_path)
        writable.write('''These imports were found: ''')
        writable.write(f"{imports}")
        
        for imp in imports:
            cves = query_nist_database(imp)
            writable.write(f"\n\nA total of {len(cves)} cves for the {imp} import.\n\n")
            writable.write(wrapper.fill(f"Contextual Usage: {get_context(file_path,imp)}"))
            writable.write(f"\n\n")
            writable.write(f"Vulnerabilities:\n")
            for cve in cves:
                writable.write(wrapper.fill(f"{cve}\n"))
        writable.write(f"\n\n\n")
        writable.close()

    except:
        print("Error updating results")

'''
Given an import, provide the context of the import 
'''
def get_context(file, imp):
    context = []
    lineNumber = 1
    with open(file,"r") as f:
        for line in f: 
            search = re.search(imp,line)
            if(search):
                context.append(f"Line {lineNumber}: {line}")
            lineNumber += 1
    return context     


'''
Given a file, find all of the imports 
'''
def find_imports(file):
    imports = []
    with open(file,"r") as f:
        for line in f: 
            regex = r"\Aimport [a-zA-Z]{3,20}"
            match = re.match(regex, line)
            if (match):
                found = match.group()
                parsed = found.split()[1]
                imports.append(parsed)
    return imports

'''
Give an package name conduct a search
'''
def query_nist_database(imported_package):
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    QUERY_PARAMETER = "keywordSearch=" + imported_package + " " + "python"
    QUERY_PARAMETER = QUERY_PARAMETER.replace(" ","%20")
    FULL_URL = BASE_URL + "?" + QUERY_PARAMETER
    response = requests.get(FULL_URL).json()
    cve_data = extract_cves(response)
    return cve_data

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



def main(): 
    
    intro = '''FACE THE FACTS...
    Your project probably has vulnerabilities.
    This tool can help by comparing imports in your project 
    against vulnerabilities in the NIST database. 
    '''
    print(intro)
    print("*" * 50)

    project_dir = input("\nType your filepath: ") 
    print("*" * 50)
    if(project_dir == ''):
        print(f"Testing with default sample: ./sample_projects/simple_calculator")
        print("Please wait. This may take a while...")
        project_dir = "./sample_projects/simple_calculator"
    else:
        print(f"You typed: {project_dir}")

    recursively_scan_project(project_dir)
    print("Job done! Check results.txt file for findings.\n\n")


main()


