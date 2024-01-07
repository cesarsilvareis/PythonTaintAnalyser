#!/usr/bin/python3

import ast
import json
import astexport.export as astexport
import sys
from tool_resources import *
import argparse
import os

debug = False
output_folder = "./output"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

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

unitialized_vars = []


def get_function_name(node):
    if node.get('ast_type') == "Name":
        return node.get('id')
    elif node.get('ast_type') == "Call":
        return node.get('func').get('value')
    elif node.get('ast_type') == "Attribute":
        return node.get('attr') 
    

def update_attributes(node, policy, multilabelling, vulnerabilities, pc, multilabel):
    if node.get('ast_type') == "Name":
        _ = traverse_ast_expr(node.get('value'), policy, multilabelling, vulnerabilities, pc)
    elif node.get('ast_type') == "Attribute":
        multilabelling.set_multilabel(node.get('attr'), multilabel)
        update_attributes(node.get('value'), policy, multilabelling, vulnerabilities, pc, multilabel)


def traverse_ast_expr(node, policy: Policy, multilabelling: MultiLabelling, 
                      vulnerabilities: Vulnerabilities, pc: MultiLabel = None) -> MultiLabel:
    # Expressions are assigned the least upper bound to the variables that are read
    # In this case the least upper bound of the multilabels that compose the resulting expression multilabel
    
    if node is None: return MultiLabel(policy.get_patterns())
    
    global unitialized_vars
    
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
            var = (node.get("id"), node.get("lineno"))
            try:
                multilabel = multilabelling.get_multilabel(node.get('id'))
                # This keeps source sequence when assigning left source: s1 = s2; sink = s1 --> s1 & s2
                for pattern in policy.get_patterns_with_source(var):
                    multilabel.add_source(pattern.get_name(), var)                    
            except:
                # ! UNITIALIZED VARIABLES ARE VULNERABLE ENTRY POINTS (SOURCES TO EVERY PATTERN) !
                multilabel.force_add_source_to_all_patterns(var)
                
            if node.get("id") in unitialized_vars:
                multilabel.force_add_source_to_all_patterns(var)
            
            return multilabel
        
        case "Attribute":
            # ast_type: Attribute
            # value: node (expression) 
            multilabel = MultiLabel(policy.get_patterns())
            var = (node.get("attr"), node.get("lineno"))
            try:
                multilabel = multilabelling.get_multilabel(node.get('attr'))
                # This keeps source sequence when assigning left source: s1 = s2; sink = s1 --> s1 & s2
                for pattern in policy.get_patterns_with_source(var):
                    multilabel.add_source(pattern.get_name(), var)

            except:
                # ! UNITIALIZED VARIABLES ARE VULNERABLE ENTRY POINTS (SOURCES TO EVERY PATTERN) !
                multilabel.force_add_source_to_all_patterns(var)
                 
            if node.get("attr") in unitialized_vars:
                multilabel.force_add_source_to_all_patterns(var)

            return multilabel.combine(traverse_ast_expr(node.get('value'), policy, multilabelling, vulnerabilities))
        
        case "BinOp" | "BoolOp":
            # ast_type: BinOp | BoolOp
            # left: node (expression)
            # op: (ast_type: operator)
            # right: node (expression)
            return traverse_ast_expr(node.get('left'), policy, multilabelling, vulnerabilities).\
                combine(traverse_ast_expr(node.get('right'), policy, multilabelling, vulnerabilities))
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
            if node.get('func').get('ast_type') == "Name":
                function_name = node.get('func').get('id')
                #print(f"\n@ Calling {function_name}")
                multilabel = MultiLabel(policy.get_patterns())

                # Create the multilabel by traversing the expression of each of the fcall arguments and return it
                for arg in node.get('args'):
                    #print(f"@ Function {function_name} arg: {arg.get('id')}")
                    argmultilabel = traverse_ast_expr(arg, policy, multilabelling, vulnerabilities).deep_copy()

                    # Add the outter function as a sanitizer for every pattern of the argmultilabel that has it as a sanitizer
                    for pattern in policy.get_patterns_with_sanitizer((function_name, node.get('lineno'))):
                        argmultilabel.get_label(pattern.get_name()).prepare_sanitized_flow()
                        sanitized_sources = [src[0] for src in argmultilabel.get_label(pattern.get_name()).get_sources()]
                        if len(sanitized_sources) > 0:
                            argmultilabel.add_sanitizer(pattern.get_name(), (function_name, node.get('lineno'), tuple(sanitized_sources)))
                        argmultilabel.get_label(pattern.get_name()).trim_empty_sanitized_flow()
                    # Build the result multilabel of calling the function by combining the arguments
                    multilabel = multilabel.combine(argmultilabel)
                
                # print(f"\n# before - function: {(function_name, node.get('lineno'))} multilabel result\n: {multilabel.get_label('B')}")
                multilabel = multilabel.combine(pc)
                # print(f"\n# itermediate - function: {(function_name, node.get('lineno'))} multilabel result\n: {multilabel.get_label('B')}")
                for pattern in policy.get_patterns_with_sanitizer((function_name, node.get('lineno'))):
                    multilabel.get_label(pattern.get_name()).prepare_sanitized_flow()
                    sanitized_sources = [src[0] for src in multilabel.get_label(pattern.get_name()).get_sources()]
                    if len(sanitized_sources) > 0:
                        multilabel.add_sanitizer(pattern.get_name(), (function_name, node.get('lineno'), tuple(sanitized_sources)))
                    multilabel.get_label(pattern.get_name()).trim_empty_sanitized_flow()
                        
                # Record the possible illegal flows for calling the function with this argument (argmultilabel)
                vulnerabilities.record_ilflows((function_name, node.get('lineno')), policy.filter_ilflows(function_name, multilabel))

                # Add this function as a source for each pattern of the resulting multilabel that has it as source
                for pattern in policy.get_patterns_with_source((function_name, node.get('lineno'))):
                    multilabel.add_source(pattern.get_name(), (function_name, node.get('lineno')))
                return multilabel
                
            elif node.get('func').get('ast_type') == "Attribute":
                multilabel = MultiLabel(policy.get_patterns())
                for arg in node.get('args'):
                    multilabel = multilabel.combine(traverse_ast_expr(arg, policy, multilabelling, vulnerabilities))

                node_test = node.get('func')
                taintedSource = None
                while True:
                    if node_test.get('ast_type') == "Name":
                        function_name = node_test.get('id')
                    if node_test.get('ast_type') == "Attribute":
                        function_name = node_test.get('attr')
                    if node_test.get('ast_type') == "Call":
                        multilabel = multilabel.combine(traverse_ast_expr(node_test.get('func'), policy, multilabelling, vulnerabilities))
                        function_name = get_function_name(node_test.get('func').get('value'))

                    vulnerabilities.record_ilflows((function_name, node.get('lineno')), policy.filter_ilflows(function_name, multilabel))

                    for pattern in policy.get_patterns_with_source((taintedSource if taintedSource is not None else function_name, node.get('lineno'))):
                        multilabel.force_add_source(pattern.get_name(), (function_name, node.get('lineno')))
                        if taintedSource is None: taintedSource = function_name

                    for pattern in policy.get_patterns_with_source((function_name, node.get('lineno'))):
                        multilabel.add_source(pattern.get_name(), (function_name, node.get('lineno')))

                    for pattern in policy.get_patterns_with_sanitizer((function_name, node.get('lineno'))):
                        multilabel.add_sanitizer(pattern.get_name(), (function_name, node.get('lineno'), \
                            tuple([src[0] for src in multilabel.get_label(pattern.get_name()).get_sources()])
                        ))

                    if node_test.get('ast_type') == "Name":
                        break
                    if node_test.get('ast_type') == "Attribute":
                        node_test = node_test.get('value')
                    if node_test.get('ast_type') == "Call":
                        node_test = node_test.get('func').get('value')
                
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
    
    global unitialized_vars
    
    ast_type = node.get('ast_type')
    debug_print(f"Stmt parsing: {ast_type}")
    match ast_type:
        case "Module":
            for stmt in node.get('body'):
                multilabelling = traverse_ast_stmt(stmt, policy, multilabelling, vulnerabilities, pc)

        case "Assign":
            for target_var in node.get('targets'):
                if target_var.get('ast_type') == "Name":
                    var_name = target_var.get('id')
                    
                    if var_name in unitialized_vars:
                        unitialized_vars.remove(var_name)
                    
                    var_name = target_var.get('id')
                    right_multilabel = traverse_ast_expr(node.get('value'), policy, multilabelling, vulnerabilities, pc).combine(pc)

                    # Report illegal flows for patterns of which the left side is sink
                    illegal_flows = policy.filter_ilflows(var_name, right_multilabel)
                    vulnerabilities.record_ilflows((var_name, node.get('lineno')), illegal_flows)

                    multilabelling.set_multilabel(var_name, right_multilabel)
                    
                elif target_var.get('ast_type') == "Attribute":
                    var_name = target_var.get('value').get('id')
                    attribute = target_var.get('attr')

                    if attribute in unitialized_vars:
                        unitialized_vars.remove(attribute)
                    
                    right_multilabel = traverse_ast_expr(node.get('value'), policy, multilabelling, vulnerabilities).combine(pc)
                    update_attributes(target_var.get('value'), policy, multilabelling, vulnerabilities, pc, right_multilabel)

                    # Report illegal flows for patterns of which the left side is sink
                    illegal_flows = policy.filter_ilflows(var_name, right_multilabel)
                    vulnerabilities.record_ilflows((var_name, node.get('lineno')), illegal_flows)
                    #multilabelling.set_multilabel(var_name, right_multilabel)

                    illegal_flows = policy.filter_ilflows(attribute, right_multilabel)
                    vulnerabilities.record_ilflows((attribute, node.get('lineno')), illegal_flows)
                    multilabelling.set_multilabel(attribute, right_multilabel)

                else:
                    raise ValueError(f"Unsupported left type: {target_var.get('ast_type')}")
        
        case "If":
            pc = policy.filter_implflows(traverse_ast_expr(node.get('test'), policy, multilabelling, vulnerabilities)).combine(pc)

            ifmultilabelling = multilabelling.deep_copy()
            for stmt in node.get('body'):
                ifmultilabelling = ifmultilabelling.combine(traverse_ast_stmt(stmt, policy, ifmultilabelling, vulnerabilities, pc))
            
            orelse = node.get('orelse')
            elsemultilabelling = multilabelling.deep_copy()
            if orelse is not None and orelse != []:
                for stmt in orelse:
                    elsemultilabelling = elsemultilabelling.combine(traverse_ast_stmt(stmt, policy, elsemultilabelling, vulnerabilities, pc))
    
            for var_name in ifmultilabelling.get_mapping():
                if var_name not in elsemultilabelling.get_mapping() and var_name not in multilabelling.get_mapping():
                    unitialized_vars.append(var_name)
                    
            multilabelling = multilabelling.combine(ifmultilabelling).combine(elsemultilabelling)

        case "While":
            while_multilabelling = multilabelling.deep_copy()
            for i in range(1+count_assigns(node.get('body'))):
                pc = policy.filter_implflows(traverse_ast_expr(node.get('test'), policy, while_multilabelling, vulnerabilities)).combine(pc)
                # print(f"\n\nWhile #################### iteration {i}: pc = {pc}")
                for stmt in node.get('body'):
                    while_multilabelling = while_multilabelling.combine(traverse_ast_stmt(stmt, policy, while_multilabelling, vulnerabilities, pc))

            for var_name in while_multilabelling.get_mapping():
                if var_name not in multilabelling.get_mapping():
                    unitialized_vars.append(var_name)

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

    output_filename = f"{output_folder}/{args.program_file.split('/')[-1].split('.')[0]}.output.json"
    with open(output_filename, "w") as fp:
        fp.write(f"{result}")


if __name__ == "__main__":
    main()