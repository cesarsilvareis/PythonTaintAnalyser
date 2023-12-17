import copy

class MultiLabelling:
    def __init__(self):
        self.mapping = {}
    
    def get_mapping(self):
        return self.mapping
    def deep_copy(self):
        return copy.deepcopy(self)
    def get_multilabel(self, variable_name):
        multilabel = self.mapping.get(variable_name)
        if multilabel is None:
            raise ValueError(f"There is no mapping for variable with name: {variable_name}")
        return multilabel
    
    def set_multilabel(self, variable_name, newMultilabel):
        self.mapping[variable_name] = newMultilabel
        
    def combine(self, multilabelling):
        new_multilabelling = MultiLabelling()
        ml1_variables = set(self.mapping.keys())
        ml2_variables = set(multilabelling.get_mapping().keys())
        combined_variables = list(ml1_variables.union(ml2_variables))
        
        for variable_name in combined_variables:
            if variable_name in self.mapping and variable_name in multilabelling.get_mapping():
                new_multilabelling.set_multilabel(variable_name, self.get_multilabel(variable_name).combine(multilabelling.get_multilabel(variable_name)))
            elif variable_name in self.mapping:
                new_multilabelling.set_multilabel(variable_name, self.get_multilabel(variable_name))
            else:
                new_multilabelling.set_multilabel(variable_name, multilabelling.get_multilabel(variable_name))
        
        return new_multilabelling
    
    def __repr__(self) -> str:
        return str(self)
    
    def __str__(self) -> str:
        return str(self.mapping)
