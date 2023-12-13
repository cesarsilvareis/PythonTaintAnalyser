from multilabel import MultiLabel

class Policy:
    def __init__(self, patterns):
        self.patterns = patterns
    
    def get_patterns(self):
        return self.patterns
    
    def get_pattern_names(self):
        return [pattern.get_name() for pattern in self.patterns]
    
    def get_patterns_with_source(self, source):
        return [pattern for pattern in self.patterns if pattern.has_source(source)]
    
    def get_patterns_with_sanitizer(self, sanitizer):
        return [pattern for pattern in self.patterns if pattern.has_sanitizer(sanitizer)]
        
    def get_patterns_with_sink(self, sink):
        return [pattern for pattern in self.patterns if pattern.has_sink(sink)]
    
    def filter_ilflows(self, function_name, multiLabel):
        # Given a name of a function and a multiLabel (fed to the function)
        # Returns a multilabel representing the illegal flows:
        # -> Has a pattern for which the function_name is a sink
        # -> Has atleast one source on the label corresponding to that pattern
        multiLabel = MultiLabel(self.patterns)
        for pattern in self.get_patterns_with_sink(function_name):
            if len(multiLabel.get_label(pattern.get_name()).get_sources()) > 0:
                multiLabel = multiLabel.combine(MultiLabel(pattern))
        return multiLabel