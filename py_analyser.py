#!/usr/bin/python3
import os, sys
import argparse
import ast
import astexport.export as astexport
import json

from tool_resources import *


def check_file(filename: str):
    if not os.path.isfile(filename):
        print(f"[ERROR] Program file '{filename}' couldn't be open as it doesn't exist :(", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Tool for analyzing program slices')
    parser.add_argument('program_file', type=str, help='Name of the Python file containing the program slice to analyze')
    parser.add_argument('vulnerability_patterns_file', type=str, help='Name of the JSON file containing the list of vulnerability patterns to consider')
    
    args = parser.parse_args()
    
    print(f"Program file: {args.program_file}")
    print(f"Vulnerability patterns file: {args.vulnerability_patterns_file}")
    
    check_file(args.program_file)
    check_file(args.vulnerability_patterns_file)

    with open(args.program_file, 'r') as f:
        program = f.read()
    tree = ast.parse(program)
    ast_json = astexport.export_dict(tree)
    
    with open(args.vulnerability_patterns_file, 'r') as f:
        patterns_raw = json.load(f)
        patterns = list(map(lambda raw:
            Pattern(
                vul_name=raw["vulnerability"],
                sources=raw["sources"],
                sanitizers=raw["sanitizers"],
                sinks=raw["sinks"]
        ), patterns_raw))
    
    # Innovative XPTO Chat (v.0.01) -------------
    # Code should go here :D
    # Não tive mais tempo, tive que sair lol :(
    # Na boa!
    # >
    
    print(f"[PROGRAM]\n{program}")
    print("----------------------------------------")
    print(f"[PROGRAM_AST]\n{ast_json}")
    print("----------------------------------------")
    print(f"[PATTERNS_RAW]\n{patterns_raw}")
    print("----------------------------------------")
    print(f"[PATTERNS]\n{patterns}")
    print("----------------------------------------")



if __name__ == '__main__':
    main()
