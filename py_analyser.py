#!/usr/bin/python3
import os, sys
import argparse
import ast
import astexport.export as astexport
import json

from tool_resources import *

expressions = ["Constant", "Name", "BinOp", "UnaryOp", "BoolOp", "Call", "Expr"]
statements = ["Module", "Assign", "If", "While"]
ast_info_list_global = []
WHILE_MAX_LOOPS = 3
CURRENT_LOOP = 0



def check_file(filename: str):
    if not os.path.isfile(filename):
        print(f"[ERROR] Program file '{filename}' couldn't be open as it doesn't exist :(", file=sys.stderr)
        sys.exit(1)

def traverse_expression(node, policy, multilabelling, vulnerabilities) -> MultiLabel:   # TODO: policy, vulnerabilities
    
    if node is None: return None
    ast_type = node.get('ast_type')
    
    if ast_type not in expressions: return None

    resulted_multilabel = MultiLabel()
    node_info = lambda: print(f"lineno: {node.get('lineno')} | multilabel: {resulted_multilabel} | type: {ast_type}")

    match ast_type:
        case "Constant":
            node_info()
            print("Constant value:", node.get('value'))
            return resulted_multilabel
        case "Name":
            resulted_multilabel = multilabelling.get_multilabel_for_var(node.get('value'))
            node_info()
            print("Name ID:", node.get('id'))
            return resulted_multilabel
        case "BinOp" | "UnaryOp" | "BoolOp":
            mlb1 = traverse_expression(node.get('left'), policy, multilabelling, vulnerabilities)
            mlb2 = traverse_expression(node.get('right'), policy, multilabelling, vulnerabilities)
            if not (mlb1 and mlb2):
                return None

            resulted_multilabel = mlb1.combine(mlb2)
            node_info()
            return resulted_multilabel
        case "Call":     
            call_name = node.get('func').get('id')
                
            for n in node.get('args'):
                mlb = traverse_expression(n, policy, multilabelling, vulnerabilities)
                if not mlb:
                    return None

                resulted_multilabel.combine()

            node_info()
            print("call_name:", call_name)
            return resulted_multilabel
        case "Expr":
            resulted_multilabel = traverse_expression(node.get('value'), policy, multilabelling, vulnerabilities)
            node_info()
            return resulted_multilabel
    
    return None

def traverse_statement(node, policy, multilabelling, vulnerabilities) -> MultiLabelling:
    if node is None: return None
    ast_type = node.get('ast_type')
    
    # if ast_type in expressions:
    #     ml = traverse_expression(node, policy, multilabelling, vulnerabilities) # return Multilabel
    #     return MultiLabelling()
    
    resulted_multilabelling = MultiLabelling()
    node_info = lambda: print(f"lineno: {node.get('lineno')} | multilabel: {resulted_multilabelling} | type: {ast_type}")
    node_info()
    match ast_type:
        # Missing Attribute match
        case "Module":
            #for info in ast_info_list:
            #    info.append(node_info)
                
            #traverse_ast_trace(node.get('test'), ast_info_list)
            for n in node.get('body'):
                #traverse_ast_trace(n, ast_info_list)
                multilabelling = traverse_statement(n, policy, multilabelling, vulnerabilities)
                resulted_multilabelling.combine(multilabelling)
            return resulted_multilabelling
        
        case "Assign":
            # for info in ast_info_list:
            #     info.append(node_info)
            #traverse_ast_trace(, ast_info_list)
            assert len(node.get('targets')) == 1
            for targ in node.get('targets'):
                variable = targ.get("id")
                resulted_multilabelling.add_variable(targ.get("id"))
                left_multilabel = traverse_expression(targ, policy, multilabelling, vulnerabilities)
                resulted_multilabelling.update_multilabel_for_var(variable, left_multilabel) # this combines multilabels too
                                
            right_multilabel = traverse_expression(node.get('value'), policy, multilabelling, vulnerabilities)
            
            return resulted_multilabelling
        
        case "If":
            #print(node_info)
            #print(len(ast_info_list))
            #for info in ast_info_list:
            #    info.append(node_info)
                
            # current_ast_info_list = []
            # for info in ast_info_list:
            #     current_ast_info_list.append(info)
                
            # print(len(current_ast_info_list))
            
            # temporary = []
            # for n in node.get('body'):
            #     #create a sublist with a copy of all the elements in the list
            #     new_info_list = []
            #     for info in current_ast_info_list:
            #         new_info_list.append(info.copy())
            #     temporary.append(new_info_list)
                    
            #     traverse_ast_trace(n, new_info_list)
            # if node.get('orelse') is not None:
            #     for n in node.get('orelse'):
            #         traverse_ast_trace(n, ast_info_list)
            
            # for l in temporary:
            #     for info in l:
            #         ast_info_list.append(info)
            pass
                    
        case "While":
            # global CURRENT_LOOP
                        
            # new_info_list = []
            # for info in ast_info_list:
            #     new_info_list.append(info.copy())
        
                
            # if CURRENT_LOOP < WHILE_MAX_LOOPS:
            #     print(node_info)
            #     for info in ast_info_list:
            #         info.append(node_info)
                    
            #     CURRENT_LOOP += 1
            #     #traverse_ast_trace(node.get('test'), ast_info_list)
            #     for n in node.get('body'):
            #         traverse_ast_trace(n, ast_info_list)
                    
            #     traverse_ast_trace(node, ast_info_list)
            
            #     ast_info_list.append(new_info_list)
            #     CURRENT_LOOP = 0
            pass
    
    return None

def traverse_ast_trace(node, ast_info_list, patterns):
    if node is None: return []
    ast_type = node.get('ast_type')
    node_info = f"lineno: {node.get('lineno')} | {ast_type}"
    
    policy = Policy(patterns)
    multilabelling = MultiLabelling()
    
    vulnerabilities = Vulnerabilities(policy)
    

    multilabelling = traverse_statement(node, policy, multilabelling, vulnerabilities)
    
    print(multilabelling)
    

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
        
    program = """
b = c()
"""

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
        # TODO: parse 'implicit' element
    
    # Innovative XPTO Chat (v.0.01) -------------
    # Code should go here :D
    # Não tive mais tempo, tive que sair lol :(
    # Na boa!
    # >
    
    print(f"[PROGRAM]\n{program}")
    print("----------------------------------------")
    print(f"[PROGRAM_AST]\n{json.dumps(ast_json, indent=4)}")
    print("----------------------------------------")
    print(f"[PATTERNS_RAW]\n{patterns_raw}")
    print("----------------------------------------")
    print(f"[PATTERNS]\n{patterns}")
    print("----------------------------------------")
    
    
    ast_info = []
    ast_info_list_global.append(ast_info)
    

    traverse_ast_trace(ast_json, ast_info_list_global, patterns)

    #for entry in ast_info_list_global:
        #print("PATH...")
        #print(entry)

    #print("Number of different paths:", len(ast_info_list_global))
    



if __name__ == '__main__':
    main()
