import json
from tool_resources import MultiLabel

class Vulnerability:
    def __init__(self, name, sink, source, sanitized_flows, has_unsanitized_flows):
        self.name = name
        self.source = source
        self.sink = sink
        self.sanitized_flows = sanitized_flows
        self.unsanitized_flows = has_unsanitized_flows

    def formatVulnerability(self) -> str:
        return json.dumps({
                "vulnerability": self.name,
                "source": self.source,
                "sink": self.sink,
                "unsanitized_flows": self.unsanitized_flows,
                "sanitized_flows": [self.sanitized_flows] if self.sanitized_flows != [] else self.sanitized_flows
            }
        )
        
    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return self.formatVulnerability()

class Vulnerabilities:
    def __init__(self, vulnerabilities: list[str]):
        self.mapping = { vulnerability_name: [] for vulnerability_name in vulnerabilities }
    
    def classify_iflows(self, source, sanitizers):
        sanitized = False
        sanitized_flows = []
        for sanitizer in sanitizers:
            if source in [sanitized_source for sanitized_source in sanitizer[2]]:
                sanitized_flows.append((sanitizer[0], sanitizer[1]))
                sanitized = True
        return sanitized_flows, "yes" if not sanitized else "no"

    def record_ilflows(self, sink: str, illegal_flows: MultiLabel):
        for pattern_name in illegal_flows.get_mapping():
            for source in illegal_flows.get_label(pattern_name).get_sources():
                sflows, unsflows = self.classify_iflows(source, illegal_flows.get_label(pattern_name).get_sanitizers())
                self.mapping[pattern_name].append(Vulnerability(
                    f"{pattern_name}_{len(self.mapping[pattern_name])+1}",
                    sink, source, sflows, unsflows,
                ))

    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str(sum(self.mapping.values(), []))