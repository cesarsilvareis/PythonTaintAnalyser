from pattern import Pattern
from label import Label

# Maps (vulnerability) Patterns to Labels (unique for variable)
class MultiLabel:
    def __init__(self):
        self.pattern_labels = {}

    def get_patterns(self) -> list[Pattern]:
        return list(self.pattern_labels.keys())
    
    def get_label_for_pattern(self, pattern: Pattern) -> Label:
        if not self.is_recognized_pattern(pattern): return None

        return self.pattern_labels[pattern]

    def get_labels(self) -> list[Label]:
        return list(self.pattern_labels.values())

    def get_captured_sources(self, pattern: Pattern) -> list[str]:
        label = self.get_label_for_pattern(pattern)
        if not label: return None

        return label.get_captured_sources()
    
    def get_captured_sanitizers(self, pattern: Pattern) -> list[str]:
        label = self.get_label_for_pattern(pattern)
        if not label: return None

        return label.get_captured_sanitizers()
    
    def is_recognized_pattern(self, pattern: Pattern):
        return pattern in self.get_patterns()
    
    def add_pattern(self, pattern: Pattern):
        if self.is_recognized_pattern(pattern): return

        self.pattern_labels[pattern] = Label()

    def set_label_for_pattern(self, pattern: Pattern, new_label: Label):
        label = self.get_label_for_pattern(pattern)
        if not label: return

        label.copy_from(new_label)
    
    def capture_source(self, pattern: Pattern, source: str):
        if not pattern.is_source(source): return

        label = self.get_label_for_pattern(pattern)
        if not label: return

        label.capture_source(source)

    def capture_sanitizer(self, pattern: Pattern, sanitizer: str, arg_source: list[str]=[]):
        if not pattern.is_sanitizer(sanitizer): return
        
        label = self.get_label_for_pattern(pattern)
        if not label: return

        if not arg_source:
            label.capture_sanitizer(sanitizer)
            return
        
        filtered_sources = list(filter(pattern.is_source, arg_source))
        label.capture_sanitizer(sanitizer, filtered_sources)

    def combine(self, other: 'MultiLabel') -> 'MultiLabel':
        recognized_patterns = list(set(self.get_patterns() + other.get_patterns()))
        comb = MultiLabel()

        for pattern in recognized_patterns:
            my_label = self.get_label_for_pattern(pattern)
            other_label = other.get_label_for_pattern(pattern)

            resulted_label = None
            if my_label and other_label:
                resulted_label = my_label.combine(other_label)
            elif my_label:
                resulted_label = my_label
            else:
                assert other_label
                resulted_label = other_label

            comb.add_pattern(pattern)
            comb.set_label_for_pattern(pattern, resulted_label) # update the label of this pattern

        return comb
    
    def __str__(self) -> str:
        return f"mlbl:{self.pattern_labels}"

    def __repr__(self) -> str:
        return str(self)

# Maps variable names to MultiLabels
class MultiLabelling:
    def __init__(self, variables: list[str]| str):
        if isinstance(variables, str):
            variables = [variables]

        self.var_labels = {
            var: MultiLabel() for var in variables
        }

    def get_variables(self) -> list[str]:
        return list(self.var_labels.keys())

    def get_multilabel_for_var(self, variable: str) -> MultiLabel:
        if not self.is_recognized_variable(variable): return None

        return self.var_labels[variable]
    
    def set_multilabel_for_var(self, variable: str, new_multilabel: MultiLabel):
        if not self.is_recognized_variable(variable): return

        self.var_labels[variable] = new_multilabel

    def is_recognized_variable(self, variable: str) -> bool:
        return variable in self.var_labels
    
    def copy(self) -> 'MultiLabelling':
        from copy import deepcopy
        return deepcopy(self)
    
    def combine(self, other: 'MultiLabelling') -> 'MultiLabelling':
        variables = list(set(self.get_variables() + other.get_variables()))
        comb = MultiLabelling(variables)

        for var in variables:
            my_multilabel = self.get_multilabel_for_var(var)
            other_multilabel = other.get_multilabel_for_var(var)
            
            resulted_multilabel = None
            if my_multilabel and other_multilabel:
                resulted_multilabel = my_multilabel.combine(other_multilabel)
            elif my_multilabel:
                resulted_multilabel = my_multilabel
            else:
                assert other_multilabel # just to be sure
                resulted_multilabel = other_multilabel

            comb.set_multilabel_for_var(var, resulted_multilabel)

        return comb
    
    def __str__(self) -> str:
        return f"lbling{self.var_labels}"

    def __repr__(self) -> str:
        return str(self)
            
