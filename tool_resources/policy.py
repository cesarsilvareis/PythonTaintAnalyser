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
        # Given a name of a function and a multiLabel (fed to the function)
        # Returns a multilabel representing the illegal flows:
        # -> Has a pattern for which the function_name is a sink
        # -> Has atleast one source on the label corresponding to that pattern

        new_multilabel = MultiLabel(self.patterns)
        for pattern in self.get_patterns_with_sink(function_name):
            if len(multiLabel.get_label(pattern.get_name()).get_sources()) > 0:
                new_multilabel.add_label(pattern.get_name(), multiLabel.get_label(pattern.get_name()))
        return new_multilabel
    
    def filter_implflows(self, multilabel: MultiLabel):
        implicit_patterns = self.get_implicit_patterns()
        pc = MultiLabel(implicit_patterns)
        for pattern in implicit_patterns:
            pc.add_label(pattern.get_name(), multilabel.get_label(pattern.get_name()))
        return pc
