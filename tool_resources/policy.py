from tool_resources import Pattern, MultiLabel

class Policy:
    def __init__(self, patterns: list[Pattern]):
        self.patterns = patterns
    
    def get_patterns(self):
        return self.patterns
    
    def get_pattern_names(self):
        return [pattern.get_name() for pattern in self.patterns]
    
    def get_patterns_with_source(self, source: tuple[str, int]):
        return [pattern for pattern in self.patterns if pattern.has_source(source)]
    
    def get_patterns_with_sanitizer(self, sanitizer: tuple[str, int]):
        return [pattern for pattern in self.patterns if pattern.has_sanitizer(sanitizer)]
        
    def get_patterns_with_sink(self, sink: str):
        return [pattern for pattern in self.patterns if pattern.has_sink(sink)]
    
    def get_patterns_with_unknown_var(self, var: tuple[str, int]):
        return [pattern for pattern in self.patterns if not (pattern.has_sanitizer(var) or pattern.has_sink(var[0]))]

    def get_implicit_patterns(self):
        return [pattern for pattern in self.patterns if pattern.get_implicit_mode()]
    
    def filter_ilflows(self, function_name: str, multiLabel: MultiLabel):
        # multiLabel corresponds to an argument -> Has its sources and sanitizers, together with its flows
        new_multilabel = MultiLabel(self.patterns)
        # For each pattern of the multiLabel
        for pattern in self.get_patterns_with_sink(function_name):
            # If there are sources for that pattern
            if len(multiLabel.get_label(pattern.get_name()).get_sources()) > 0:
                # Save the label for that pattern to a new multilabel
                new_multilabel.add_label(pattern.get_name(), multiLabel.get_label(pattern.get_name()).deep_copy())
        return new_multilabel
    
    def filter_implflows(self, multilabel: MultiLabel):
        implicit_patterns = self.get_implicit_patterns()
        pc = MultiLabel(implicit_patterns)
        for pattern in implicit_patterns:
            pc.add_label(pattern.get_name(), multilabel.get_label(pattern.get_name()).deep_copy())
        return pc
