from tool_resources import Pattern, Label
import copy

class MultiLabel:
    def __init__(self, patterns: list[Pattern]):
        self.mapping = {pattern.get_name(): {'label': Label(), 'pattern': pattern} for pattern in patterns}
    
    def get_entry(self, pattern_name):
        val = self.mapping.get(pattern_name)
        if val is None:
            raise ValueError(f"There is no label matching the pattern with name: {pattern_name}")
        return val
    def get_label(self, pattern_name) -> Label:
        if pattern_name not in self.mapping:
            return None
        return self.mapping.get(pattern_name).get('label')
    def get_pattern(self, pattern_name) -> Pattern:
        if pattern_name not in self.mapping:
            return None
        return self.mapping.get(pattern_name).get('pattern')
    def get_mapping(self):
        return self.mapping
    
    def deep_copy(self):
        patterns = [self.mapping[pattern].get('pattern') for pattern in self.mapping]
        multiLabel = MultiLabel(patterns)
        for pattern_name in multiLabel.get_mapping():
            multiLabel.add_label(pattern_name, self.get_label(pattern_name).deep_copy())
        return multiLabel

    def add_label(self, pattern_name, label):
        if self.mapping.get(pattern_name) is None: return
        self.get_entry(pattern_name)['label'] = label
    
    def add_source(self, pattern_name, source):
        if self.mapping.get(pattern_name) is None: return
        if self.get_pattern(pattern_name).has_source(source):
            self.get_label(pattern_name).add_source(source)
            
    def force_add_source_to_all_patterns(self, source):
        for pattern_name in self.mapping:
            self.get_label(pattern_name).add_source(source)
    def force_add_source(self, pattern_name, source):
        self.get_label(pattern_name).add_source(source)

    def add_sanitizer(self, pattern_name, sanitizer):
        if self.mapping.get(pattern_name) is None: return
        if self.get_pattern(pattern_name).has_sanitizer(sanitizer):
            self.get_label(pattern_name).add_sanitizer(sanitizer)
    
    def combine(self, multiLabel: 'MultiLabel'):
        if multiLabel is None: return self.deep_copy()
        l1_patterns = set([val.get('pattern') for val in self.mapping.values()]) # Get the patterns of this MultiLabel
        l2_patterns = set([val.get('pattern') for val in multiLabel.get_mapping().values()]) # Get the patterns of the received multiLabel
        combined_patterns = list(l1_patterns.union(l2_patterns)) # Combine both patterns
        newMultiLabel = MultiLabel(combined_patterns) # Create a new MultiLabel with patterns of both MultiLabels

        for pattern_name in newMultiLabel.get_mapping():    
            # For each pattern combine the label of this MultiLabel with the label of the received multiLabel into a combinedLabel
            combinedLabel = newMultiLabel.get_label(pattern_name).combine(self.get_label(pattern_name)).combine(multiLabel.get_label(pattern_name))
            for source in combinedLabel.get_sources():
                newMultiLabel.get_label(pattern_name).add_source(source)
            for sanitizer in combinedLabel.get_sanitizers():
                newMultiLabel.get_label(pattern_name).add_sanitizer(sanitizer)
            for flow in combinedLabel.get_sanitized_flows():
                newMultiLabel.get_label(pattern_name).add_sanitized_flow(flow)
            for flow in combinedLabel.get_unsanitized_flows():
                newMultiLabel.get_label(pattern_name).add_unsanitized_flow(flow)
        
        #print(f"Combining MultiLabels self: {self} with label: {multiLabel} results in newMultiLabel: {newMultiLabel}\n")
        return newMultiLabel
    
    
    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str(self.mapping)