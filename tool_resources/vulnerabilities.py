import json
from tool_resources import MultiLabel

class Vulnerability:
    def __init__(self, name, sink, source, sanitized_flows, unsanitized_flows):
        self.name = name
        self.source = source
        self.sink = sink
        self.sanitized_flows = sanitized_flows
        self.unsanitized_flows = unsanitized_flows

    def hasUnsanitizedFlows(self):
        return "yes" if len(self.unsanitized_flows) > 0 else "no"

    def formatVulnerability(self) -> str:
        return json.dumps({
                "vulnerability": self.name,
                "source": self.source,
                "sink": self.sink,
                "unsanitized_flows": self.hasUnsanitizedFlows(),
                "sanitized_flows": [list(self.sanitized_flows)] if len(self.sanitized_flows) > 0 else []
            }
        )
        
    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return self.formatVulnerability()

class Vulnerabilities:
    def __init__(self, vulnerabilities: list[str]):
        self.mapping = { vulnerability_name: [] for vulnerability_name in vulnerabilities }
    
    
    def filter_sflows(self, source, label):
        sflows = []
        for sflow in label.get_sanitized_flows():
            sanitizers = list(filter(lambda san: san[0] == sflow[0], label.get_sanitizers()))[0]
            if source[0] in sanitizers[2]: sflows.append(sflow)
        return sflows
    
    def record_ilflows(self, sink: str, illegal_flows: MultiLabel):
        for pattern_name in illegal_flows.get_mapping():
            #print(f"---->>>> {illegal_flows.get_label(pattern_name)}")
            for source in illegal_flows.get_label(pattern_name).get_sources():
                label = illegal_flows.get_label(pattern_name)
                self.mapping[pattern_name].append(Vulnerability(
                    f"{pattern_name}_{len(self.mapping[pattern_name])+1}",
                    sink, source, self.filter_sflows(source, label), label.get_unsanitized_flows()
                ))

    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str(sum(self.mapping.values(), []))