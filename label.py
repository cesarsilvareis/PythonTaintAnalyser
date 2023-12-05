class Label():
    def __init__(self):        
        # self.captured_sources: list[str] = []
        self.captured_sanitizers: list[str] = [] # Maybe not needed
        self.captured_source_sanitizers: dict[str, list[str]] = {}

    def get_captured_sources(self) -> list[str]:
        return list(self.captured_source_sanitizers.keys())
    
    def get_captured_sanitizers(self) -> list[str]:
        return self.captured_sanitizers
    
    def get_captured_sanitizers_for_source(self, source: str) -> list[str]:
        if not self.is_recognized_source(source): return None
        
        return self.captured_source_sanitizers[source]
    
    def get_captured_sources_for_sanitizer(self, sanitizer: str) -> list[str]:
        if not self.is_recognized_sanitizer(sanitizer): return None

        sanitizer_sources = []
        for source in self.captured_source_sanitizers:
            source_sanitizers = self.get_captured_sanitizers_for_source(source)
            if sanitizer in source_sanitizers:
                sanitizer_sources.append(source)

        return sanitizer_sources


    def is_recognized_source(self, source: str) -> bool:
        return source in self.get_captured_sources()
    
    def is_recognized_sanitizer(self, sanitizer: str) -> bool:
        return sanitizer in self.get_captured_sanitizers()
    
    def is_recognized_sanitizer_for_source(self, sanitizer: str, source: str) -> bool:
        return sanitizer in self.get_captured_sanitizers_for_source(source)
    
    def is_sanitized_source(self, source) -> bool:
        if not self.is_recognized_source(source): return False

        sanitizers = self.get_captured_sanitizers_for_source(source)
        return len(sanitizers) > 0 

    def is_illegal(self) -> bool:
        for source in self.get_captured_sources():
            if not self.is_sanitized_source(source):
                return True
        
        return False
            

    def capture_source(self, source: str): 
        # if self.is_recognized_source(source): return # TODO check this

        self.captured_source_sanitizers[source] = [] # without sanitizer

    def capture_sanitizer(self, sanitizer: str, arg_sources: list[str]=[]):
        if not self.is_recognized_sanitizer(sanitizer):
            self.captured_sanitizers.append(sanitizer)

        for source in arg_sources:
            if not self.is_recognized_source(source):
                self.capture_source(source)
            
            if self.is_recognized_sanitizer_for_source(sanitizer, source):
                continue

            self.captured_source_sanitizers[source].append(sanitizer)
    
    def combine(self, other: 'Label') -> 'Label':
        comb = Label()

        recognized_sources = list(set(self.get_captured_sources() + 
                           other.get_captured_sources()))
        
        # Union with predominance of Ls (keeping Hs - the sanitized sources)
        for source in recognized_sources:
            my_sanitizers = self.get_captured_sanitizers_for_source(source)
            other_sanitizers = other.get_captured_sanitizers_for_source(source)

            resulted_sanitizers = []
            if my_sanitizers and other_sanitizers:
                resulted_sanitizers = list(set(my_sanitizers + other_sanitizers))
            elif my_sanitizers:
                resulted_sanitizers = my_sanitizers
            elif other_sanitizers:
                resulted_sanitizers = other_sanitizers

            if not resulted_sanitizers:
                comb.capture_source(source)
                continue

            for san in resulted_sanitizers:
                comb.capture_sanitizer(san, source)

        return comb

    def copy_from(self, other: 'Label'):
        self.captured_sanitizers = other.captured_sanitizers.copy()
        self.captured_source_sanitizers = other.captured_source_sanitizers.copy()

    def __str__(self) -> str:
        return f"lbl:{self.captured_source_sanitizers}"
    def __repr__(self) -> str:
        return str(self)

