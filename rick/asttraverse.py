import ast
import json
import astexport.export
import sys
from multilabel import MultiLabel

progfile = sys.argv[1]
traces = [[]]

def formatTrace(trace):
    traceStr = ""
    for node in trace:
        traceStr += f"{str(node)} -> "
    if traceStr != "": return traceStr[:-4]
    return traceStr

def traverse_ast_expr(node, policy, multilabelling, vulnerabilities):
    # Expressions are assigned the least upper bound to the variables that are read
    # In this case the least upper bound of the multilabels that compose the resulting expression multilabel
    ast_type = node.get('ast_type')
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
                    multiLabel.add_source(pattern_name, node.get('id'))
            return multiLabel
        case "BinOp" | "BoolOp":
            # ast_type: BinOp
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
            for arg in node.get('args'):
                # Get the multilabel of each argument fed to the function and check if there are illegal flows
                argMultiLabel = traverse_ast_expr(arg, policy, multilabelling, vulnerabilities)
                vulnerabilities.record_ilflows(function_name, policy.filter_ilflows(function_name, argMultiLabel))
            multiLabel = MultiLabel(policy.get_patterns())
            for pattern in policy.get_patterns_with_source(function_name):
                multiLabel.add_source(pattern.get_name(), function_name)    
            return multiLabel            
        case "Expr":
            # ast_type: Expr
            # value: node (expression)
            return traverse_ast_expr(node.get('value'), policy, multilabelling, vulnerabilities)

def traverse_ast_stmt(node, policy, label, multilabel):
    pass

def traverse_ast(node, current_trace):
    if node is None: return
    ast_type = node.get('ast_type')
    node_info = f"lineno: {node.get('lineno')} | {ast_type}"
    match ast_type:
        # Missing Attribute match
        case "Constant" | "Name": # Leaf
            print(node_info)
            current_trace.append(node_info)
        case "BinOp" | "UnaryOp" | "BoolOp":
            node_info = node_info.split("|")[0] + f"| {node.get('op').get('ast_type')}"
            print(node_info)
            current_trace.append(node_info)
            traverse_ast(node.get('left'), current_trace)
            traverse_ast(node.get('right'), current_trace)
        case "Call":
            print(node_info)
            current_trace.append(node_info)
            for n in node.get('args'):
                traverse_ast(n, current_trace)
        case "Expr" | "Assign":
            print(node_info)
            current_trace.append(node_info)
            traverse_ast(node.get('value'), current_trace)
        case "If":
            print(node_info)
            current_trace.append(node_info)
            traceidx = len(traces)
            traces.append(current_trace)
            for n in node.get('body'):
                traverse_ast(n, traces[traceidx-1])
            if node.get('orelse') is not None:
                for n in node.get('orelse'):
                    traverse_ast(n, traces[traceidx])
        case "While":
            print(node_info)
            current_trace.append(node_info)
            traverse_ast(node.get('test'), current_trace)
            for n in node.get('body'):
                traverse_ast(n, current_trace)

with open(progfile, 'r') as f:
    prog_ast = ast.parse(f.read())
    ast_dict = astexport.export.export_dict(prog_ast)
    ast_json = json.dumps(ast_dict)
    for node in ast_dict.get('body'):
        traverse_ast(node, traces[0])
    print("Showing ast in json format:")
    print(ast_json)
    print("\nShowing all traces:")
    for trace in traces:
        print(formatTrace(trace))
        print('\n')