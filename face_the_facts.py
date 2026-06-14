import requests
import json
import os 

'''
Given a directory, find CVES of all identified files
'''
def recursively_scan_project(dir):
    imports_listing = []
    dir_listing = os.listdir(dir)

    index = len(dir_listing) - 1
    while (dir_listing != []):
        #handle files 
        if(os.path.isfile(dir_listing)):
            imports_listing + scan_file(dir_listing)
        
        #handle directories 
        elif(os.path.isdir(dir_listing)):
            imports_listing + recursively_scan_project(dir_listing)

        dir_listing.pop(index)
        index = index - 1

    return imports_listing 

'''
Given a file, find CVES of all identified imports 
'''
def scan_file(file):
    f = open(file,"r")
    file_contents = f.read(); 
    regex = r""
    matches_list = file_contents.match(regex)
    return matches_list

'''
Give an package name conduct a search
'''
def query_nist_database(imported_package):
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    QUERY_PARAMETER = "keywordSearch=" + imported_package + " " + "python"
    QUERY_PARAMETER = QUERY_PARAMETER.replace(" ","%20")
    FULL_URL = BASE_URL + "?" + QUERY_PARAMETER
    response = requests.get(FULL_URL).json
    cve_data = extract_cves(response)
    return cve_data

def extract_cves(json_data):
    cve_data = []
    relevant_json = json_data.get("vulnerabilities")
    for current in relevant_json:
        cve = current.get("cve")
        cve_id = cve.get("id")
        cve_description = cve.get("description")
        cve_dict = {
            "id": cve_id, 
            "description": cve_description
        }
        cve_data.append(cve_dict)
    return cve_data

def main(): 
    intro = '''FACE THE FACTS...
    Your project probably has vulnerabilities.
    This tool can help by comparing imports in your project against the
    NIST database. 
    '''
    print(intro)

    all_imports = recursively_scan_project()
    for imp in all_imports:
        query_nist_database(imp)


