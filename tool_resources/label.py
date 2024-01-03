import copy

# Represents the integrity of information carried by a resource
# Captures the sources that might have influenced a certain piece of information
# and the sanitizers that might have intercepted this information since its flow from each source
class Label:
    def __init__(self):
        self.sources = set()
        self.sanitizers = set()
        self.sanitized_flows = set()
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
    
    def updateFlows(self, sanitizer):
        unsanitized_flows = copy.deepcopy(self.unsanitized_flows)
        for unsflow in unsanitized_flows:
            if unsflow[0] in sanitizer[2]:
                self.unsanitized_flows.remove(unsflow)
        self.add_sanitized_flow((sanitizer[0], sanitizer[1]))
    
    def add_source(self, source):
        self.sources.add(source)
        self.unsanitized_flows.add(source)

    def add_sanitizer(self, sanitizer):
        self.sanitizers.add(sanitizer)
        self.updateFlows(sanitizer)

    def add_sanitized_flow(self, flow):
        self.sanitized_flows.add(flow)
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
        for flow in label.get_sanitized_flows().union(self.get_sanitized_flows()):
            combinedLabel.add_sanitized_flow(flow)
        for flow in label.get_unsanitized_flows().union(self.get_unsanitized_flows()):
            combinedLabel.add_unsanitized_flow(flow)

        # Find the common sources to both labels
        #common_sources = set([src[0] for src in label.get_sources()]).intersection(set([src[0] for src in self.get_sources()]))

        # Add every sanitizer that does not sanitize a common source to the combinedLabel, example below:
        # z1 = src1(l)
        # z2 = src2(l)
        # a = san1(z1)
        # b = san2(z2)
        # x = f(a, b) -> {a: {sources: src1, san: (san1, lineno, (src1,)); b: {sources: src2, san: (san2, lineno, (src2),); }}
        #             -> x: {sources: src1, src2; san: (san1, lineno, (src1,)), (san2, lineno, (src2,))}
        #sanitizers = copy.deepcopy(label.get_sanitizers().union(self.get_sanitizers()))
        #for sanitizer in label.get_sanitizers().union(self.get_sanitizers()):
        #    if len(list(filter(lambda src: src in common_sources, sanitizer[2]))) == 0:
        #        combinedLabel.add_sanitizer(sanitizer)
        #        sanitizers.remove(sanitizer)
        
        # Remaining sanitizers sanitize some common source -> Potential for unsanitized flows: in case only one of the label sanitizes the common source
        #for sanitizer in sanitizers:
            
        #print(f"Combining Labels self: {self} with label: {label} results in combinedLabel: {combinedLabel}\n")
        return combinedLabel

    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str({"sources": self.sources, "sanitizers": self.sanitizers, "sanitized_flows": self.sanitized_flows, "unsanitized_flows": self.unsanitized_flows})