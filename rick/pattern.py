# Represents a Vulnerability with a given name
# Has a list of sources, sanitizers and sinks
class Pattern:
    def __init__(self, name, sources, sanitizers, sinks):
        self.name = name
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
    
    def get_name(self):
        return self.name
    def get_sources(self):
        return self.sources
    def get_sanitizers(self):
        return self.sanitizers
    def get_sinks(self):
        return self.sinks

    def has_source(self, source):
        # Source is a tuple (source_name, lineno)
        return source[0] in self.sources
    def has_sanitizer(self, sanitizer):
        # Sanitizer is a tuple (sanitizer_name, lineno)
        return sanitizer[0] in self.sanitizers
    def has_sink(self, sink):
        return sink in self.sinks
    
    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return f"{{pattern_name: {self.name};" +\
               f"sources: {self.sources};" +\
               f"sanitizers: {self.sanitizers};" +\
               f"sinks: {self.sinks}}}"