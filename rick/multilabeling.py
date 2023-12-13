import copy

class MultiLabeling:
    def __init__(self):
        self.mapping = {}
    
    def get_mapping(self):
        return self.mapping
    def deep_copy(self):
        return copy.deepcopy(self.mapping)
    def get_multilabel(self, variable_name):
        multilabel = self.mapping.get(variable_name)
        if multilabel is None:
            raise ValueError(f"There is no mapping for variable with name: {variable_name}")
        return multilabel
    
    def set_multilabel(self, variable_name, newMultilabel):
        self.mapping[variable_name] = newMultilabel
