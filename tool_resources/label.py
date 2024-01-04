import copy

# Represents the integrity of information carried by a resource
# Captures the sources that might have influenced a certain piece of information
# and the sanitizers that might have intercepted this information since its flow from each source
class Label:
    def __init__(self):
        self.sources = set()
        self.sanitizers = set()
        self.sanitized_flows = []
        self.unsanitized_flows = set()
    
    def get_sources(self) -> set[tuple[str, int]]:
        # Sources are tuples (source_name, lineno)
        return self.sources
    def get_sanitizers(self) -> set[tuple[str, int]]:
        # Sanitizers are tuples (sanitizer_name, lineno)
        return self.sanitizers
    def get_sanitized_flows(self):
        return self.sanitized_flows
    def get_unsanitized_flows(self):
        return self.unsanitized_flows
    
    def prepare_sanitized_flow(self):
        self.sanitized_flows.append([])
    def trim_empty_sanitized_flow(self):
        if (self.sanitized_flows[-1] == []):
            self.sanitized_flows = self.sanitized_flows[:-1]

    def noFlowHasSanitizer(self, sanitizer, flows):
        if type(flows) is tuple:
            return not (sanitizer[0] == flows[0] and sanitizer[1] == flows[1])
        elif type(flows) is list:
            if len(flows) == 0: return True
            return self.noFlowHasSanitizer(sanitizer, flows[0]) and self.noFlowHasSanitizer(sanitizer, flows[1:])

    def updateFlows(self, sanitizer):
        unsanitized_flows = copy.deepcopy(self.unsanitized_flows)
        for unsflow in unsanitized_flows:
            if unsflow[0] in sanitizer[2] and unsflow[1] <= sanitizer[1]:
                self.unsanitized_flows.remove(unsflow)
        if self.noFlowHasSanitizer(sanitizer, self.sanitized_flows):
            for flow in self.sanitized_flows:
                flow.append((sanitizer[0], sanitizer[1]))

        #print(f"Adding sanitized flow: {(sanitizer[0], sanitizer[1])} to label: {self}; current sanitized flows: {self.sanitized_flows}")
    
    def add_source(self, source):
        self.sources.add(source)
        self.unsanitized_flows.add(source)

    def add_sanitizer(self, sanitizer):
        #(sanitizer, lineno, (source_sanitized, ))
        added = False
        for san in self.sanitizers:
            if san[0] == sanitizer[0]:
                if sanitizer[2][0] not in san[2]:
                    self.sanitizers.remove(san)
                    self.sanitizers.add((san[0], san[1], tuple([sanitizer[2][0]] + [src for src in san[2]])))
                    added = True
                    break
        if not added: self.sanitizers.add(sanitizer)
        self.updateFlows(sanitizer)

    def add_sanitized_flow(self, flow):
        self.sanitized_flows.append(flow)

    def add_unsanitized_flow(self, flow):
        self.unsanitized_flows.add(flow)

    def deep_copy(self):
        label = Label()
        for source in self.sources:
            label.add_source(source)
        for sanitizer in self.sanitizers:
            label.add_sanitizer(sanitizer)
        for flow in self.sanitized_flows:
            label.add_sanitized_flow(flow)
        for flow in self.unsanitized_flows:
            label.add_unsanitized_flow(flow)
        return label

    def combine(self, label: 'Label'):
        #print("\n@")
        combinedLabel = Label()
        if label is None: return self.deep_copy()

        for source in label.get_sources().union(self.get_sources()): 
            combinedLabel.add_source(source)

        for sanitizer in label.get_sanitizers().union(self.get_sanitizers()):
            combinedLabel.add_sanitizer(sanitizer)

        for flow in copy.deepcopy(label.get_sanitized_flows()):
            combinedLabel.add_sanitized_flow(flow)
        for flow in copy.deepcopy(self.get_sanitized_flows()):
            if flow not in combinedLabel.get_sanitized_flows():
                combinedLabel.add_sanitized_flow(flow)

        for flow in label.get_unsanitized_flows().union(self.get_unsanitized_flows()):
            combinedLabel.add_unsanitized_flow(flow)

        #print(f"Combining Labels self: {self} with label: {label} results in combinedLabel: {combinedLabel}\n")
        return combinedLabel

    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str({"sources": self.sources, "sanitizers": self.sanitizers, "sanitized_flows": self.sanitized_flows, "unsanitized_flows": self.unsanitized_flows})