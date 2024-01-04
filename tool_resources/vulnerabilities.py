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
        #print(f"---->>>> pattern_name: {self.name.split('_')[0]} | source: {self.source} | sink: {self.sink} | unsanitized_flows: {self.unsanitized_flows}\n")
        return "yes" if len(self.unsanitized_flows) > 0 else "no"

    def formatVulnerability(self) -> str:
        return json.dumps({
                "vulnerability": self.name,
                "source": self.source,
                "sink": self.sink,
                "unsanitized_flows": self.hasUnsanitizedFlows(),
                "sanitized_flows": self.sanitized_flows
            }
        )

    def get_source(self):
        return self.source
    def get_sink(self):
        return self.sink

    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return self.formatVulnerability()

class Vulnerabilities:
    def __init__(self, vulnerabilities: list[str]):
        self.mapping = { vulnerability_name: [] for vulnerability_name in vulnerabilities }
    
    def filter_sflows(self, source, sanitizers, flows):
        if type(flows) is tuple:
            _sans = [san[2] for san in sanitizers if flows[0] == san[0] and san[1] >= source[1]]
            return flows if len(_sans) > 0 and source[0] in _sans[0] else []
        elif type(flows) is list:
            if len(flows) == 0: return []
        head_res = self.filter_sflows(source, sanitizers, flows[0])
        return ([head_res] if head_res != [] else []) + self.filter_sflows(source, sanitizers, flows[1:])

    def filter_unsflows(self, source, flows):
        return set(list(filter(lambda flow: source[1] >= flow[1], flows)))

    def record_ilflows(self, sink: str, illegal_flows: MultiLabel):
        for pattern_name in illegal_flows.get_mapping():
            for source in illegal_flows.get_label(pattern_name).get_sources():
                label = illegal_flows.get_label(pattern_name)
                # print(f"---->>>> pattern_name: {pattern_name} | source: {source} | sink: {sink} | ilflow_label: {label}")
                vuln = self.vulnerabilityExists(pattern_name, sink, source, label)
                if vuln is not None: self.mapping[pattern_name].append(vuln)
                #print(vuln)
                #print('\n')

    def vulnerabilityExists(self, pattern_name, sink, source, label):
        for vulnerability in self.mapping[pattern_name]:
            if vulnerability.get_source() == source and vulnerability.get_sink() == sink:
                return None
        return Vulnerability(
            f"{pattern_name}_{len(self.mapping[pattern_name])+1}",
            sink, source, 
            self.filter_sflows(source, label.get_sanitizers(), label.get_sanitized_flows()),
            self.filter_unsflows(source, label.get_unsanitized_flows())
        )

    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str(sum(self.mapping.values(), []))