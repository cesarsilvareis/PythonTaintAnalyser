# Represents the integrity of information carried by a resource
# Captures the sources that might have influenced a certain piece of information
# and the sanitizers that might have intercepted this information since its flow from each source
class Label:
    def __init__(self):
        self.sources = set()
        self.sanitizers = set()
    
    def get_sources(self):
        # Sources are tuples (source_name, lineno)
        return self.sources
    def get_sanitizers(self):
        # Sanitizers are tuples (sanitizer_name, lineno)
        return self.sanitizers
    
    def add_source(self, source):
        self.sources.add(source)
    def add_sanitizer(self, sanitizer):
        self.sanitizers.add(sanitizer)

    def deep_copy(self):
        label = Label()
        for source in self.sources:
            label.add_source(source)
        for sanitizer in self.sanitizers:
            label.add_sanitizer(sanitizer)
        return label

    def combine(self, label):
        newLabel = self.deep_copy()
        if label is None: return newLabel
        for source in label.get_sources(): 
            newLabel.add_source(source)
        for sanitizer in label.get_sanitizers():
            newLabel.add_sanitizer(sanitizer)
        return newLabel

    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return f"{{sources: {self.sources}; sanitizers: {self.sanitizers}}}"