

Testing: 1a-basic-flow

********************************************************************************
[92m[+] All outputs of file common-tests/T00-01/1a-basic-flow.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-01/1a-basic-flow.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['c', 2], 'sink': ['e', 4], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 1b-basic-flow

********************************************************************************
[92m[+] All outputs of file common-tests/T00-02/1b-basic-flow.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-02/1b-basic-flow.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['b', 2], 'sink': ['d', 4], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_2', 'source': ['c', 4], 'sink': ['d', 4], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_3', 'source': ['b', 2], 'sink': ['e', 5], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_4', 'source': ['c', 4], 'sink': ['e', 5], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 2-expr-binary-ops

********************************************************************************
[92m[+] All outputs of file common-tests/T00-03/2-expr-binary-ops.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-03/2-expr-binary-ops.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['a', 3], 'sink': ['e', 3], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_2', 'source': ['d', 3], 'sink': ['e', 3], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_3', 'source': ['a', 2], 'sink': ['e', 3], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_1', 'source': ['b', 1], 'sink': ['a', 1], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_2', 'source': ['b', 1], 'sink': ['e', 3], 'unsanitized_flows': 'yes', 'sanitized_flows': [[['s', 2]]]}, {'vulnerability': 'B_3', 'source': ['d', 3], 'sink': ['e', 3], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 3a-expr-func-calls

********************************************************************************
[92m[+] All outputs of file common-tests/T00-04/3a-expr-func-calls.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-04/3a-expr-func-calls.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['b', 1], 'sink': ['e', 2], 'unsanitized_flows': 'no', 'sanitized_flows': [[['f', 2]]]}, {'vulnerability': 'A_2', 'source': ['b', 1], 'sink': ['c', 2], 'unsanitized_flows': 'yes', 'sanitized_flows': [[['f', 2]]]}, {'vulnerability': 'A_3', 'source': ['b', 1], 'sink': ['e', 3], 'unsanitized_flows': 'yes', 'sanitized_flows': [[['f', 2]]]}, {'vulnerability': 'B_1', 'source': ['b', 1], 'sink': ['c', 2], 'unsanitized_flows': 'no', 'sanitized_flows': [[['d', 2]], [['e', 2], ['d', 2]]]}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 3b-expr-func-calls

********************************************************************************
[92m[+] All outputs of file common-tests/T00-05/3b-expr-func-calls.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-05/3b-expr-func-calls.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['a', 1], 'sink': ['z', 1], 'unsanitized_flows': 'no', 'sanitized_flows': [[['t', 1]]]}, {'vulnerability': 'B_1', 'source': ['a', 1], 'sink': ['t', 1], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 3c-expr-attributes

********************************************************************************
[92m[+] All outputs of file common-tests/T00-06/3c-expr-attributes.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-06/3c-expr-attributes.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['b', 2], 'sink': ['a', 2], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_2', 'source': ['c', 2], 'sink': ['a', 2], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_3', 'source': ['m', 2], 'sink': ['a', 2], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_1', 'source': ['b', 2], 'sink': ['f', 2], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_2', 'source': ['c', 2], 'sink': ['f', 2], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 4a-conds-branching

********************************************************************************
[92m[+] All outputs of file common-tests/T00-07/4a-conds-branching.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-07/4a-conds-branching.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['f', 4], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_2', 'source': ['c', 7], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_3', 'source': ['a', 7], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_1', 'source': ['d', 6], 'sink': ['c', 6], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_2', 'source': ['a', 7], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_3', 'source': ['c', 7], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_4', 'source': ['d', 6], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 4b-conds-branching

********************************************************************************
[92m[+] All outputs of file common-tests/T00-08/4b-conds-branching.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-08/4b-conds-branching.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['d', 6], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_2', 'source': ['d', 7], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_3', 'source': ['b', 1], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_1', 'source': ['d', 6], 'sink': ['a', 6], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'C_1', 'source': ['d', 6], 'sink': ['e', 7], 'unsanitized_flows': 'no', 'sanitized_flows': [[['c', 6]]]}, {'vulnerability': 'C_2', 'source': ['d', 7], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'C_3', 'source': ['a', 7], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'C_4', 'source': ['a', 6], 'sink': ['e', 7], 'unsanitized_flows': 'no', 'sanitized_flows': [[['c', 6]]]}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 5a-loops-unfolding

********************************************************************************
[92m[+] All outputs of file common-tests/T00-09/5a-loops-unfolding.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-09/5a-loops-unfolding.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['b', 1], 'sink': ['h', 6], 'unsanitized_flows': 'yes', 'sanitized_flows': [[['d', 3]]]}, {'vulnerability': 'B_1', 'source': ['f', 4], 'sink': ['c', 3], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 5b-loops-unfolding

********************************************************************************
[92m[+] All outputs of file common-tests/T00-10/5b-loops-unfolding.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-10/5b-loops-unfolding.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['b', 1], 'sink': ['q', 9], 'unsanitized_flows': 'yes', 'sanitized_flows': [[['s', 8]]]}, {'vulnerability': 'B_1', 'source': ['b', 1], 'sink': ['c', 5], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 5c-loops-unfolding

********************************************************************************
[92m[+] All outputs of file common-tests/T00-11/5c-loops-unfolding.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-11/5c-loops-unfolding.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['c', 7], 'sink': ['z', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_2', 'source': ['b', 1], 'sink': ['z', 7], 'unsanitized_flows': 'no', 'sanitized_flows': [[['s', 4]]]}, {'vulnerability': 'B_1', 'source': ['s', 4], 'sink': ['q', 7], 'unsanitized_flows': 'no', 'sanitized_flows': [[['z', 7]]]}, {'vulnerability': 'B_2', 'source': ['c', 7], 'sink': ['q', 7], 'unsanitized_flows': 'no', 'sanitized_flows': [[['z', 7]]]}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 6a-sanitization

********************************************************************************
[92m[+] All outputs of file common-tests/T00-12/6a-sanitization.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-12/6a-sanitization.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['f', 4], 'sink': ['z', 4], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_2', 'source': ['b', 1], 'sink': ['z', 4], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_1', 'source': ['b', 1], 'sink': ['d', 3], 'unsanitized_flows': 'yes', 'sanitized_flows': [[['e', 3]]]}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 6b-sanitization

********************************************************************************
[92m[+] All outputs of file common-tests/T00-13/6b-sanitization.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-13/6b-sanitization.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['b', 1], 'sink': ['e', 3], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_1', 'source': ['e', 2], 'sink': ['c', 2], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_2', 'source': ['b', 1], 'sink': ['c', 2], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 7-conds-implicit

********************************************************************************
[92m[+] All outputs of file common-tests/T00-14/7-conds-implicit.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-14/7-conds-implicit.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['c', 3], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_2', 'source': ['b', 1], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_3', 'source': ['boo', 1], 'sink': ['e', 7], 'unsanitized_flows': 'yes', 'sanitized_flows': []}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 8-loops-implicit

********************************************************************************
[92m[+] All outputs of file common-tests/T00-15/8-loops-implicit.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-15/8-loops-implicit.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['b', 1], 'sink': ['t', 5], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_2', 'source': ['i', 3], 'sink': ['t', 5], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'A_3', 'source': ['b', 1], 'sink': ['w', 6], 'unsanitized_flows': 'no', 'sanitized_flows': [[['s', 6]]]}, {'vulnerability': 'A_4', 'source': ['i', 3], 'sink': ['w', 6], 'unsanitized_flows': 'no', 'sanitized_flows': [[['s', 6]]]}]

[91m
WRONG FLOWS
[][0m

[93m
MISSING FLOWS
[][0m


Testing: 9-regions-guards

********************************************************************************
[92m[+] All outputs of file common-tests/T00-16/9-regions-guards.myoutput.json are well defined[0m
[92m[+] All outputs of file common-tests/T00-16/9-regions-guards.output.json are well defined[0m

GOOD FLOWS
[{'vulnerability': 'A_1', 'source': ['d', 2], 'sink': ['z', 12], 'unsanitized_flows': 'no', 'sanitized_flows': [[['s', 5]]]}, {'vulnerability': 'B_1', 'source': ['b', 1], 'sink': ['a', 1], 'unsanitized_flows': 'yes', 'sanitized_flows': []}, {'vulnerability': 'B_2', 'source': ['b', 1], 'sink': ['a', 11], 'unsanitized_flows': 'yes', 'sanitized_flows': [[['s', 11]]]}]

[91m
WRONG FLOWS
[{'vulnerability': 'B_3', 'source': ['b', 1], 'sink': ['z', 12], 'unsanitized_flows': 'yes', 'sanitized_flows': [[['s', 5]]]}][0m

[93m
MISSING FLOWS
[{'vulnerability': 'B_3', 'source': ['b', 1], 'sink': ['z', 12], 'unsanitized_flows': 'yes', 'sanitized_flows': [[['s', 11], ['s', 5]], [['s', 11]]]}][0m
