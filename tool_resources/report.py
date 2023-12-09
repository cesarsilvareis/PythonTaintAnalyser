from tool_resources import Policy, MultiLabel

class Vulnerabilities:
    def __init__(self, policy: Policy):
        self.policy = policy
        # ...
        self.report = {}

    def update_report(self, 
                      vul_name: str, 
                      sink: str, 
                      detected_sources: str, 
                      detected_sanitizers: dict[str, list[str]]):
        
        if vul_name not in self.report:
            self.report[vul_name] = {
                "warning_sinks": {
                    sink: {
                        "detected_sources": detected_sources,
                        "detected_sanitizers": detected_sanitizers
                    }
                }
            }
            return
        
        self.report[vul_name]["watning_sinks"][sink] = {
            "detected_sources": detected_sources,
            "detected_sanitizers": detected_sanitizers 
        }
        
        

    def report_for_name(self, multilabel: MultiLabel, name: str):
        illegal_multilabel = self.policy.get_illegal_flows(name, multilabel)

        for pattern in illegal_multilabel.get_patterns():
            label = illegal_multilabel.get_label_for_pattern(pattern)
            assert label and self.policy.is_illegal_label(label)

            vul_name = pattern.vul_name
            detected_sources = list(filter(
                lambda s: not label.is_sanitized_source(s), label.get_captured_sources()))
            detected_sanitizers = {
                sanitizer: label.get_captured_sources_for_sanitizer(sanitizer)
                    for sanitizer in label.get_captured_sanitizers()
            }

            self.update_report(vul_name, name, detected_sources, detected_sanitizers)


    def save(self, file_name: str = "results.json"):
        import json
        with open(file_name, "w") as f:
            json_data = json.dumps(self.report, indent=2)
            f.write(json_data)