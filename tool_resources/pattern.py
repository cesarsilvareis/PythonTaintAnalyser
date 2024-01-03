import json
# Represents a Vulnerability with a given name
# Has a list of sources, sanitizers and sinks
class Pattern:
    def __init__(self, name: str, sources: list[str], 
                 sanitizers: list[str], sinks: list[str], implicit_mode: bool):
        self.name = name
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
        self.implicit_mode = implicit_mode
    
    def get_name(self):
        return self.name
    def get_sources(self):
        return self.sources
    def get_sanitizers(self):
        return self.sanitizers
    def get_sinks(self):
        return self.sinks
    def get_implicit_mode(self):
        return self.implicit_mode

    def has_source(self, source: tuple[str, int]) -> bool:
        # Source is a tuple (source_name, lineno)
        #print(f"Checking if pattern: {self.name} has source[0]: {source[0]} in self.sources: {self.sources}")
        return source[0] in self.sources
    def has_sanitizer(self, sanitizer: tuple[str, int]) -> bool:
        # Sanitizer is a tuple (sanitizer_name, lineno)
        #print(f"Checking if pattern: {self.name} has sanitizer[0]: {sanitizer[0]} in self.sanitizers: {self.sanitizers}")
        return sanitizer[0] in self.sanitizers
    def has_sink(self, sink: str) -> bool:
        return sink in self.sinks

    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str(
            {
                "pattern_name": self.name,
                "sources": self.sources,
                "sanitizers": self.sanitizers,
                "sinks": self.sinks
            }
        )