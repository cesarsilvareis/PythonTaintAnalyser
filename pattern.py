# Represents a vulnerability pattern of a program
class Pattern():
    
    def __init__(
            self, 
            vul_name: str,
            sources: list[str] = [],
            sanitizers: list[str] = [],
            sinks: list[str] = []
        ):

        self.vul_name = vul_name
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks

    def get_vul_name(self):
        return self.vul_name

    def get_sources(self):
        return self.sources
    
    def get_sanitizers(self):
        return self.sanitizers
    
    def get_sinks(self):
        return self.sinks

    def is_source(self, component_name: str) -> bool:
        return component_name in self.sources

    def is_sanitizer(self, component_name: str) -> bool:
        return component_name in self.sanitizers
    
    def is_sink(self, component_name: str) -> bool:
        return component_name in self.sinks
    
    def __str__(self) -> str:
        return f"pat:({self.vul_name})-{{ " +\
               f"src:{len(self.sources)};" +\
               f"san:{len(self.sanitizers)};" +\
               f"sin:{len(self.sinks)} }}"

    def __repr__(self) -> str:
        return str(self)
    
    def __hash__(self) -> int:
        return hash((self.vul_name, tuple(self.sources), 
                     tuple(self.sanitizers), tuple(self.sinks)))

    def __eq__(self, other: object) -> bool:
        return other and isinstance(other, Pattern) and \
            self.vul_name == other.vul_name and \
            self.sources == other.sources and \
            self.sanitizers == other.sanitizers and \
            self.sinks == other.sinks