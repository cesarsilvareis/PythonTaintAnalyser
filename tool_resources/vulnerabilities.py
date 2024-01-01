import json

from tool_resources import MultiLabel

class Vulnerability:
    def __init__(self, name, source, sink, sanitizers):
        self.name = name
        self.source = source
        self.sink = sink
        self.sanitizers = sanitizers

    def hasUnsanitizedFlows(self) -> str:
        return "YES" if len(self.sanitizers) == 0 else "NO"

    def formatVulnerability(self) -> str:
        return str({
                "vulnerability": self.name,
                "source": self.source,
                "sink": self.sink,
                "unsanitized_flows": self.hasUnsanitizedFlows(),
                "sanitized_flows": list(self.sanitizers)
            }
        )
        # Add lineno to sink and source : (instruction, lineno) ???
        
    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return self.formatVulnerability()

class Vulnerabilities:
    def __init__(self, vulnerabilities: list[str]):
        self.mapping = { vulnerability_name: [] for vulnerability_name in vulnerabilities }
    
    def record_ilflows(self, sink: str, illegal_flows: MultiLabel):
        for pattern_name in illegal_flows.get_mapping():
            for source in illegal_flows.get_label(pattern_name).get_sources():
                self.mapping[pattern_name].append(Vulnerability(
                    f"{pattern_name}_{len(self.mapping[pattern_name])+1}", source, sink, 
                    illegal_flows.get_label(pattern_name).get_sanitizers()
                ))       

    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str(self.mapping)