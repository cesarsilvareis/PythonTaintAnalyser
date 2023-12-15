from tool_resources import Label

class MultiLabel:
    def __init__(self, patterns):
        self.mapping = {pattern.get_name(): {'label': Label(), 'pattern': pattern} for pattern in patterns}
    
    def get_entry(self, pattern_name):
        val = self.mapping.get(pattern_name)
        if val is None:
            raise ValueError(f"There is no label matching the pattern with name: {pattern_name}")
        return val
    def get_label(self, pattern_name):
        return self.mapping.get(pattern_name).get('label')
    def get_pattern(self, pattern_name):   
        return self.mapping.get(pattern_name).get('pattern')
    def get_mapping(self):
        return self.mapping
    
    def add_label(self, pattern_name, label):
        if self.mapping.get(pattern_name) is None: return
        self.get_entry(pattern_name)['label'] = label
    
    def add_source(self, pattern_name, source):
        if self.mapping.get(pattern_name) is None: return
        if self.get_pattern(pattern_name).has_source(source):
            self.get_label(pattern_name).add_source(source)
            
    def add_sanitizer(self, pattern_name, sanitizer):
        if self.mapping.get(pattern_name) is None: return
        if self.get_pattern(pattern_name).has_sanitizer(sanitizer):
            self.get_label(pattern_name).add_sanitizer(sanitizer)
    
    def combine(self, multiLabel):
        l1_patterns = set([val.get('pattern') for val in self.mapping.values()]) # Get the patterns of this MultiLabel
        l2_patterns = set([val.get('pattern') for val in multiLabel.get_mapping().values()]) # Get the patterns of the received multiLabel
        combined_patterns = list(l1_patterns.union(l2_patterns)) # Combine both patterns
        newMultiLabel = MultiLabel(combined_patterns) # Create a new MultiLabel with patterns of both MultiLabels

        for pattern_name in newMultiLabel.get_mapping():    
            # For each pattern combine the label of this MultiLabel with the label of the received multiLabel into a combinedLabel
            combinedLabel = newMultiLabel.get_label(pattern_name).combine(self.get_label(pattern_name)).combine(multiLabel.get_label(pattern_name))
            # Add the combinedLabel sources to the new MultiLabel label for this pattern (ensure the add_source conditions)
            for source in combinedLabel.get_sources():
                newMultiLabel.get_label(pattern_name).add_source(source)
            # Add the combinedLabel sanitizers to the new MultiLabel label for this pattern (ensure the add_sanitizer conditions)
            for sanitizer in combinedLabel.get_sanitizers():
                newMultiLabel.get_label(pattern_name).add_sanitizer(sanitizer)
                
        return newMultiLabel
    
    
    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str(self.mapping)