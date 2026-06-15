# 1. Standard Library Import (Built into Python)
#import colorama
import datetime
import requests
import numpy 
import pandas as p

# 2. Local Module Imports (Custom project files)
# Import a specific function using the 'from' syntax
from operations.math_functions import add_numbers
# Import the module name directly to use dot notation
from operations import math_functions

# 3. Third-Party Import (Requires installation via pip)
try:
    import requests
except ImportError:
    requests = None


def main():
    print(f"--- Execution Time: {datetime.datetime.now()} ---")
    
    # Using the directly imported function
    sum_result = add_numbers(12.5, 7.5)
    print(f"Addition Result (from direct import): {sum_result}")
    
    # Using the module dot-notation import
    area_result = math_functions.get_circle_area(5)
    print(f"Circle Area (from module path): {area_result:.2f}")
    
    # Demonstrating the status of third-party package imports
    print("\n--- Third Party Package Check ---")
    if requests:
        print("Status: 'requests' package is installed and working!")
    else:
        print("Status: 'requests' package is missing. (Run: pip install requests)")

if __name__ == "__main__":
    main()
