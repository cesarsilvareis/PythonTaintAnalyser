class Vulnerability:
    def __init__(self, name, source, sink, sanitizers):
        self.name = name
        self.source = source
        self.sink = sink
        self.sanitizers = sanitizers

    def hasUnsanitizedFlows(self):
        return "YES" if len(self.sanitizers) == 0 else "NO"

    def formatVulnerability(self):
        return f'''
                "vulnerability": {self.name},
                "source": {self.source},
                "sink": {self.sink},
                "unsanitized_flows": {self.hasUnsanitizedFlows()},
                "sanitized_flows": {self.sanitizers}
                '''
        # Add lineno to sink and source : (instruction, lineno)
        
    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return self.formatVulnerability()

class Vulnerabilities:
    def __init__(self, vulnerabilities):
        self.mapping = {vulnerability_name: [] for vulnerability_name in vulnerabilities}
    
    def record_ilflows(self, sink, multiLabel):
        for pattern_name in multiLabel.get_mapping():
            for source in multiLabel.get_label(pattern_name).get_sources():
                self.mapping[pattern_name].append(Vulnerability(
                    f"{pattern_name}_{len(self.mapping[pattern_name])+1}", source, sink, 
                    multiLabel.get_label(pattern_name).get_sanitizers()
                ))       
                
    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str(self.mapping)