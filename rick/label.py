# Represents the integrity of information carried by a resource
# Captures the sources that might have influenced a certain piece of information
# and the sanitizers that might have intercepted this information since its flow from each source
class Label:
    def __init__(self, sources=set(), sanitizers=set()):
        self.sources = sources
        self.sanitizers = sanitizers
    
    def get_sources(self):
        return self.sources
    def get_sanitizers(self):
        return self.sanitizers
    
    def add_source(self, source):
        self.sources.add(source)
    def add_sanitizer(self, sanitizer):
        self.sanitizers.add(sanitizer)
    
    def combine(self, label):
        return Label(\
            sources = self.sources.union(label.get_sources()), \
            sanitizers = self.sanitizers.union(label.get_sanitizers()) \
        ) if label is not None \
        else Label(sources = self.sources.copy(), sanitizers=self.sanitizers.copy())

