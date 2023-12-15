#!/usr/bin/python3

import ast
import json
import astexport.export as astexport
import sys
from tool_resources import *
import argparse
import os

expressions = ["Constant", "Name", "BinOp", "UnaryOp", "BoolOp", "Call", "Expr"]
statements = ["Module", "Assign", "If", "While"]


def check_file(filename: str):
    if not os.path.isfile(filename):
        print(f"[ERROR] Program file '{filename}' couldn't be open as it doesn't exist :(", file=sys.stderr)
        sys.exit(1)

def formatTrace(trace):
    traceStr = ""
    for node in trace:
        traceStr += f"{str(node)} -> "
    if traceStr != "": return traceStr[:-4]
    return traceStr

def traverse_ast_expr(node, policy, multilabelling, vulnerabilities):
    # Expressions are assigned the least upper bound to the variables that are read
    # In this case the least upper bound of the multilabels that compose the resulting expression multilabel
    
    if node is None: return MultiLabel(policy.get_patterns())
    
    ast_type = node.get('ast_type')
    print("Parsing: ",ast_type)
    match ast_type:
        case "Constant":
            # ast_type: Constant
            # value: value_of_constant
            return MultiLabel(policy.get_patterns())
        case "Name":
            # ast_type: Name
            # id: variable_name
            multiLabel = MultiLabel(policy.get_patterns())
            try:
                multiLabel = multilabelling.get_multilabel(node.get('id'))
            except:
                # ! UNITIALIZED VARIABLES ARE VULNERABLE ENTRY POINTS (SOURCES TO EVERY PATTERN) !
                for pattern_name in multiLabel.get_mapping(): 
                    multiLabel.add_source(pattern_name, (node.get('id'), node.get('lineno')))
            return multiLabel
        case "BinOp" | "BoolOp":
            # ast_type: BinOp | BoolOp
            # left: node (expression)
            # op: (ast_type: operator)
            # right: node (expression)
            return traverse_ast_expr(node.get('left'), policy, multilabelling, vulnerabilities).\
                combine(traverse_ast_expr(node.get('right')), policy, multilabelling, vulnerabilities)
        case "UnaryOp":
            # ast_type: UnaryOp
            # op: (ast_type: operator)
            # operand: node (expression)
            return traverse_ast_expr(node.get('operand'), policy, multilabelling, vulnerabilities)
        case "Compare":
            # ast_type: Compare
            # left: node (expression)
            # ops: (ast_type: operator[])
            # comparators: node[]
            multiLabel = traverse_ast_expr(node.get('left'))
            for comparator in node.get('comparators'):
                multiLabel = multiLabel.combine(traverse_ast_expr(comparator), policy, multilabelling, vulnerabilities)
            return multiLabel
        case "Call":
            # ast_type: Call
            # func: node (name)
            # args: node[] (expression)
            # keywords: ?
            function_name = node.get('func').get('id')

            multiLabel = MultiLabel(policy.get_patterns())

            for arg in node.get('args'):
                # Get the multilabel of each argument fed to the function and check if there are illegal flows
                argMultiLabel = traverse_ast_expr(arg, policy, multilabelling, vulnerabilities)
                vulnerabilities.record_ilflows((function_name, node.get('lineno')), policy.filter_ilflows(function_name, argMultiLabel))
                print(argMultiLabel)
                print(multiLabel)
                #multiLabel = multiLabel.combine(argMultiLabel)
            
            func = (function_name, node.get('lineno'))
            for pattern in policy.get_patterns_with_source(func):
                multiLabel.add_source(pattern.get_name(), func)
            for pattern in policy.get_patterns_with_sanitizer(func):
                multiLabel.add_sanitizer(pattern.get_name(), func)
                #clean sources? TODO Se passou num sanitizer ent as sources antes ja n importam e podemso limpar para n detetar como vulnerabilidade (visto que nao guardamos timestamps ou ordem)
                    
            return multiLabel            
        case "Expr":
            # ast_type: Expr
            # value: node (expression)
            return traverse_ast_expr(node.get('value'), policy, multilabelling, vulnerabilities)


def traverse_ast_stmt(node, policy, multilabelling, vulnerabilities):
    
    if node is None: return multilabelling
    
    ast_type = node.get('ast_type')
    print("Parsing: ",ast_type)
    match ast_type:
        case "Module":
            for stmt in node.get('body'):
                multilabelling = traverse_ast_stmt(stmt, policy, multilabelling, vulnerabilities)
        case "Assign":
            assert len(node.get('targets')) == 1 # No multiple assignments in our WHILE language
            target_var = node.get('targets')[0]
            if target_var.get('ast_type') == "Name":
                variable_name = target_var.get('id')
                multilabelling.set_multilabel(variable_name, traverse_ast_expr(node.get('value'), policy, multilabelling, vulnerabilities))
            else:
                raise ValueError(f"Unsupported left type: {target_var.get('ast_type')}") # TODO: Maybe we need to add support for tuples latter
        
        case "If":
            teste = node.get('test') # TODO: Implicit vulnerabilities
            
            body = node.get('body')
            
            for stmt in body:
                multilabelling = multilabelling.combine(traverse_ast_stmt(stmt, policy, multilabelling, vulnerabilities))
            
            orelse = node.get('orelse')
            
            if orelse is not None:
                for stmt in orelse:
                    multilabelling = multilabelling.combine(traverse_ast_stmt(stmt, policy, multilabelling, vulnerabilities))            
        case "While":
            body = node.get('body')
            test = node.get('test')
            
            #option 1: enter body
            
            while_assigns = len(body)
            
            while while_assigns > 0:
                for stmt in body:
                    multilabelling = multilabelling.combine(traverse_ast_stmt(stmt, policy, multilabelling, vulnerabilities))
                while_assigns -= 1
            
            #print(json.dumps(node, indent=4))

            
        case default:
            print(ast_type)
    
    return multilabelling

def traverse_ast_trace(node, patterns):
    if node is None: return []
    ast_type = node.get('ast_type')
    node_info = f"lineno: {node.get('lineno')} | {ast_type}"
    
    policy = Policy(patterns)
    multilabelling = MultiLabelling()
    
    pattern_names = [pattern.get_name() for pattern in patterns]
    vulnerabilities = Vulnerabilities(pattern_names)
    
    multilabelling = traverse_ast_stmt(node, policy, multilabelling, vulnerabilities)    
    
    print(multilabelling)
        
    return multilabelling
        
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
a = c()
z = c()
f = 0
b = 0
y = 0
while a == 1:
    f = b
    b = a
    while a == 1:
       w = y
       y = f

"""

    tree = ast.parse(program)
    ast_json = astexport.export_dict(tree)


    
    with open(args.vulnerability_patterns_file, 'r') as f:
        patterns_raw = json.load(f)
        patterns = list(map(lambda raw:
            Pattern(
                name=raw["vulnerability"],
                sources=raw["sources"],
                sanitizers=raw["sanitizers"],
                sinks=raw["sinks"]
        ), patterns_raw))
        # TODO: parse 'implicit'element
    
    # Innovative XPTO Chat (v.0.01) -------------
    # Code should go here :D
    # Não tive mais tempo, tive que sair lol :(
    # Na boa! 
    # >
    

    print(f"[PROGRAM_AST]\n{json.dumps(ast_json, indent=4)}")
    print("----------------------------------------")
    print(f"[PROGRAM]\n{program}")
    print("----------------------------------------")
    print(f"[PATTERNS_RAW]\n{patterns_raw}")
    print("----------------------------------------")
    print(f"[PATTERNS]\n{patterns}")
    print("----------------------------------------")
    
    
    ast_info = []
    #ast_info_list_global.append(ast_info)
    

    traverse_ast_trace(ast_json, patterns)

    #for entry in ast_info_list_global:
        #print("PATH...")
        #print(entry)

    #print("Number of different paths:", len(ast_info_list_global))
    



if __name__ == "__main__":
    main()