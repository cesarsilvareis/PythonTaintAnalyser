import argparse
import ast
import astexport.export as astexport
import json

from pattern import Pattern
from multilabel import MultiLabelling
from policy import Policy
from report import Vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Tool for analyzing program slices')
    parser.add_argument('program_file', type=str, help='Name of the Python file containing the program slice to analyze')
    parser.add_argument('vulnerability_patterns_file', type=str, help='Name of the JSON file containing the list of vulnerability patterns to consider')
    
    args = parser.parse_args()
    
    print(f"Program file: {args.program_file}")
    print(f"Vulnerability patterns file: {args.vulnerability_patterns_file}")
    
    with open(args.program_file, 'r') as f:
        program = f.read()
    tree = ast.parse(program)
    ast_json = astexport.export_dict(tree)
    
    with open(args.vulnerability_patterns_file, 'r') as f:
        patterns = json.load(f)
    
    # Code should go here :D
    # Não tive mais tempo, tive que sair lol :(
    

    
    print(program)
    print("----------------------------------------")
    print(ast_json)
    print("----------------------------------------")
    print(patterns)
        
if __name__ == '__main__':
    main()