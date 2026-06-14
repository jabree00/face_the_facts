def recursively_scan_project(project):
    pass 

def scan_file(file):
    f = open(file,"r")
    file_contents = f.read(); 
    regex = r""
    matches_list = file_contents.match(regex)
    for match in matches_list:
        grab_cves(match)


def grab_cves():
    pass


def main(): 
    intro = '''FACE THE FACTS...
    Your project has vulnerabilities. 
    '''
    print(intro)
    recursively_scan_rpject

