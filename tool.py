#!/usr/bin/python3
from pattern import Pattern
from multilabel import MultiLabelling
from policy import Policy
from report import Vulnerabilities

if __name__ == "__main__":
    variables = ["x", "y", "z", "w"]
    p1 = Pattern(
        vul_name="v1", 
        sources=["x", "y"], 
        sanitizers=["f", "g"],
        sinks=["open"]
    )
    p2 = Pattern(
        vul_name="v2", 
        sources=["z", "w", "n"], 
        sanitizers="f",
    )
    
    multilabelling = MultiLabelling(variables)
    ml1 = multilabelling.get_multilabel_for_var("y"); ml1.add_pattern(p1)    # variable y
    ml2 = multilabelling.get_multilabel_for_var("z"); ml2.add_pattern(p2)    # variable z
    ml3 = multilabelling.get_multilabel_for_var("x"); ml3.add_pattern(p1)    # variable x

    print("M1 - patterns", ml1.get_patterns())
    print("M2 - patterns", ml2.get_patterns())

    ml1.capture_source(p1, "y")
    ml1.capture_source(p1, "x")
    print("M1 - label", ml1.get_label_for_pattern(p1))
    ml2.capture_source(p2, "w")
    print("M2 - label", ml2.get_label_for_pattern(p2))

    ml1.capture_sanitizer(p1, "g", "y")
    print("M1 - label", ml1.get_label_for_pattern(p1))

    ml2.capture_sanitizer(p1, "g", "w")
    print("M2 - label", ml2.get_label_for_pattern(p2))

    print("COMB", ml1.combine(ml2))

    ml3.capture_source(p1, "y")
    ml3.capture_sanitizer(p1, "f")
    print("M3 - label", ml3.get_label_for_pattern(p1))

    print("M1", ml1)
    print("M3", ml3)
    print("COMB", ml3.combine(ml1))

    policy = Policy([p1, p2])
    vulnerabilities = Vulnerabilities(policy)

    vulnerabilities.report_for_name(ml1, "open")
    # vulnerabilities.report_for_name(ml3, "open")
    vulnerabilities.save()

    print(f"\nMLbling ORIGINAL: {multilabelling}")

    multilabellingCOPY = multilabelling.copy()
    print(f"\nMLbling COPY: {multilabellingCOPY}")

    multilabellingCOPY.get_multilabel_for_var("z").capture_sanitizer(p2, "f", "n")
    multilabellingCOPY.get_multilabel_for_var("z").capture_source(p2, "w")
    multilabellingCOPY.get_multilabel_for_var("w").add_pattern(p1)
    print(f"\nMLbling COPYv2: {multilabellingCOPY}")

    multilabellingCOMB = multilabelling.combine(multilabellingCOPY)
    print(f"\nMLbling COMB: {multilabellingCOMB}")




    