from tool_resources import Pattern, MultiLabel, Label

class Policy:
    def __init__(self, patterns: list[Pattern]|Pattern):
        if isinstance(patterns, Pattern):
            patterns = [patterns]

        self.patterns = patterns


    def get_patterns(self) -> Pattern:
        return self.patterns
    
    def get_patterns_with_source(self, source: str) -> list[Pattern]:
        return list(filter(lambda p: p.is_source(source), self.patterns))

    def get_patterns_with_sanitizer(self, sanitizer: str) -> list[Pattern]:
        return list(filter(lambda p: p.is_sanitizer(sanitizer), self.patterns))
    
    def get_patterns_with_sink(self, sink: str) -> list[Pattern]:
        return list(filter(lambda p: p.is_sink(sink), self.patterns))


    def get_vul_names(self) -> list[str]:
        return list(map(lambda p: p.get_vul_name(), self.patterns))
    
    def get_vul_name_for_source(self, source: str)-> list[str]:
        return list(map(lambda p: p.get_vul_name(), self.get_patterns_with_source(source)))

    def get_vul_name_for_sanitizer(self, sanitizer: str)-> list[str]:
        return list(map(lambda p: p.get_vul_name(), self.get_patterns_with_sanitizer(sanitizer)))
    
    def get_vul_name_for_sink(self, sink: str)-> list[str]:
        return list(map(lambda p: p.get_vul_name(), self.get_patterns_with_sink(sink)))
    

    def get_illegal_flows(self, name: str, multilabel: MultiLabel) -> MultiLabel:
        considered_patterns = self.get_patterns_with_sink(name)
        illegal_multilabel = MultiLabel()
        
        for pattern in considered_patterns:
            label = multilabel.get_label_for_pattern(pattern)
            if not self.is_illegal_label(label): continue

            illegal_multilabel.add_pattern(pattern)
            # keep label as the illegal label
            illegal_multilabel.set_label_for_pattern(pattern, label)
        
        return illegal_multilabel
    
    @staticmethod
    def is_illegal_label(label: Label) -> bool:
        for source in label.get_captured_sources():
            if not label.is_sanitized_source(source):
                return True
        
        return False
