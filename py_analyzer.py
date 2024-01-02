#!/usr/bin/python3

import ast
import json
import astexport.export as astexport
import sys
from tool_resources import *
import argparse
import os

debug = False

def debug_print(msg, **format_args):
    global debug
    if debug:
        print(f"{msg}", **format_args, file=sys.stderr)

def check_file(filename: str):
    if not os.path.isfile(filename):
        print(f"[ERROR] Program file '{filename}' couldn't be open as it doesn't exist :(", file=sys.stderr)
        sys.exit(1)

# def formatTrace(trace):
#     traceStr = ""
#     for node in trace:
#         traceStr += f"{str(node)} -> "
#     if traceStr != "": return traceStr[:-4]
#     return traceStr

def traverse_ast_expr(node, policy: Policy, multilabelling: MultiLabelling, 
                      vulnerabilities: Vulnerabilities) -> MultiLabel:
    # Expressions are assigned the least upper bound to the variables that are read
    # In this case the least upper bound of the multilabels that compose the resulting expression multilabel
    
    if node is None: return MultiLabel(policy.get_patterns())
    
    ast_type = node.get('ast_type')
    debug_print(f"Expr parsing: {ast_type}")
    match ast_type:
        case "Constant":
            # ast_type: Constant
            # value: value_of_constant
            return MultiLabel(policy.get_patterns())
        case "Name":
            # ast_type: Name
            # id: variable_name
            multilabel = MultiLabel(policy.get_patterns())
            try:
                multilabel = multilabelling.get_multilabel(node.get('id'))
                # This keeps source sequence when assigning left source: s1 = s2; sink = s1 --> s1 & s2
                var = (node.get("id"), node.get("lineno"))
                for pattern in policy.get_patterns_with_source(var):
                    multilabel.add_source(pattern.get_name(), var)

            except:
                # ! UNITIALIZED VARIABLES ARE VULNERABLE ENTRY POINTS (SOURCES TO EVERY PATTERN) !
                for pattern_name in multilabel.get_mapping(): 
                    multilabel.add_source(pattern_name, (node.get('id'), node.get('lineno')))
            return multilabel
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
            multilabel = traverse_ast_expr(node.get('left'), policy, multilabelling, vulnerabilities)
            for comparator in node.get('comparators'):
                multilabel = multilabel.combine(traverse_ast_expr(comparator, policy, multilabelling, vulnerabilities))
            return multilabel
        case "Call":
            # ast_type: Call
            # func: node (name)
            # args: node[] (expression)
            # keywords: ?
            function_name = node.get('func').get('id')

            multilabel = MultiLabel(policy.get_patterns())

            for arg in node.get('args'):
                # Get the multilabel of each argument fed to the function and check if there are illegal flows
                arg_multilabel = traverse_ast_expr(arg, policy, multilabelling, vulnerabilities)
                # Report illegal flows for patterns of which the function is sink
                illegal_flows = policy.filter_ilflows(function_name, arg_multilabel)
                vulnerabilities.record_ilflows((function_name, node.get('lineno')), illegal_flows)
                multilabel = multilabel.combine(arg_multilabel)
            
            func = (function_name, node.get('lineno'))
            for pattern in policy.get_patterns_with_source(func):
                multilabel.add_source(pattern.get_name(), func)
            for pattern in policy.get_patterns_with_sanitizer(func):
                multilabel.add_sanitizer(pattern.get_name(), func)
            return multilabel            
        case "Expr":
            # ast_type: Expr
            # value: node (expression)
            return traverse_ast_expr(node.get('value'), policy, multilabelling, vulnerabilities)



def count_assigns(body_nodes) -> int:
    if len(body_nodes) == 0: return 0
    node = body_nodes[0] # Head of list -> Statement / Expression
    if node.get('ast_type') == "Assign":
        return 1 + count_assigns(body_nodes[1:])
    elif node.get('ast_type') == "While":
        return count_assigns(node.get('body'))
    elif node.get('ast_type') == "If":
        return count_assigns(node.get('body')) + (0 if node.get('orelse') is None else count_assigns(node.get('orelse')))
    return count_assigns(body_nodes[1:])


def traverse_ast_stmt(node, policy: Policy, multilabelling: MultiLabelling, 
                      vulnerabilities: Vulnerabilities, pc: MultiLabel) -> MultiLabelling:
    
    if node is None: return multilabelling
    
    ast_type = node.get('ast_type')
    debug_print(f"Stmt parsing: {ast_type}")
    match ast_type:
        case "Module":
            for stmt in node.get('body'):
                multilabelling = traverse_ast_stmt(stmt, policy, multilabelling, vulnerabilities, pc)

        case "Assign":
            assert len(node.get('targets')) == 1 # No multiple assignments in our WHILE language
            target_var = node.get('targets')[0]
            if target_var.get('ast_type') == "Name":
                var_name = target_var.get('id')
                left_multilabel = traverse_ast_expr(node.get('value'), policy, multilabelling, vulnerabilities).combine(pc)

                # Report illegal flows for patterns of which the left side is sink
                illegal_flows = policy.filter_ilflows(var_name, left_multilabel)
                vulnerabilities.record_ilflows((var_name, node.get('lineno')), illegal_flows)

                multilabelling.set_multilabel(var_name, left_multilabel)

            else:
                raise ValueError(f"Unsupported left type: {target_var.get('ast_type')}") # TODO: Maybe we need to add support for tuples latter
            # x, y = blabla<-- bonus
        
        case "If":
            pc = policy.filter_implflows(traverse_ast_expr(node.get('test'), policy, multilabelling, vulnerabilities)).combine(pc)

            ifmultilabelling = multilabelling.deep_copy()
            for stmt in node.get('body'):
                ifmultilabelling = ifmultilabelling.combine(traverse_ast_stmt(stmt, policy, ifmultilabelling, vulnerabilities, pc))

            orelse = node.get('orelse')
            elsemultilabelling = multilabelling.deep_copy()
            if orelse is not None:
                for stmt in orelse:
                    elsemultilabelling = elsemultilabelling.combine(traverse_ast_stmt(stmt, policy, elsemultilabelling, vulnerabilities, pc))

            multilabelling = multilabelling.combine(ifmultilabelling).combine(elsemultilabelling)

        case "While":
            pc = policy.filter_implflows(traverse_ast_expr(node.get('test'), policy, multilabelling, vulnerabilities)).combine(pc)
            while_multilabelling = multilabelling.deep_copy()
            for _ in range(1+count_assigns(node.get('body'))):
                for stmt in node.get('body'):
                    while_multilabelling = while_multilabelling.combine(traverse_ast_stmt(stmt, policy, while_multilabelling, vulnerabilities, pc))

            multilabelling = multilabelling.combine(while_multilabelling)

        case default:
            traverse_ast_expr(node, policy, multilabelling, vulnerabilities)
    
    return multilabelling

def analyse_code(code, patterns: list[Pattern]) -> Vulnerabilities:
    assert(code.get('ast_type') == 'Module')
    
    policy = Policy(patterns)
    vulnerabilities = Vulnerabilities([pattern.get_name() for pattern in patterns])
    pc = MultiLabel(policy.get_implicit_patterns())
    
    multilabelling = MultiLabelling()
    multilabelling = traverse_ast_stmt(code, policy, multilabelling, vulnerabilities, pc)    
    
    debug_print(f"Final multilabelling: {multilabelling}")
        
    return vulnerabilities

        
def main():
    global debug

    parser = argparse.ArgumentParser(description='Tool for analyzing program slices')
    parser.add_argument('program_file', type=str, 
                        help='Name of the Python file containing the program slice to analyze')
    parser.add_argument('vulnerability_patterns_file', type=str, 
                        help='Name of the JSON file containing the list of vulnerability patterns to consider')
    parser.add_argument('--debug', action=argparse.BooleanOptionalAction, default=False)
    
    args = parser.parse_args()
    
    check_file(args.program_file)
    check_file(args.vulnerability_patterns_file)

    debug = args.debug

    with open(args.program_file, 'r') as f:
        program = f.read()
        
#     program = """
# a = c()
# z = c()
# f = 0
# b = 0
# y = 0
# while a == 1:
#     f = b
#     b = a
#     while a == 1:
#         if a == 1:
#             w = y
#             y = f
#     b = 7
# d(b)
# """

    tree = ast.parse(program)
    ast_json = astexport.export_dict(tree)
    
    with open(args.vulnerability_patterns_file, 'r') as f:
        patterns_raw = json.load(f)
        patterns = list(map(lambda raw:
            Pattern(
                name=raw["vulnerability"],
                sources=raw["sources"],
                sanitizers=raw["sanitizers"],
                sinks=raw["sinks"],
                implicit_mode= ( str.lower(raw["implicit"]) == "yes" )
        ), patterns_raw))


    debug_print(f"[PROGRAM_AST]\n{json.dumps(ast_json, indent=4)}\n{70*'-'}")
    debug_print(f"[PROGRAM]\n{program}\n{70*'-'}")
    debug_print(f"[PATTERNS_RAW]\n{patterns_raw}\n{70*'-'}")
    debug_print(f"[PATTERNS]\n{patterns}\n{70*'-'}")

    result = analyse_code(ast_json, patterns)
    print(result, file=sys.stdout)


if __name__ == "__main__":
    main()