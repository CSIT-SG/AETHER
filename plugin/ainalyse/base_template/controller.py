

class TemplateController :
    def __init__(self, param1 = 0, param2 = 0) :
        self.param1 = param1
        self.param2 = param2
        self.param3 = 0

    def all_params(self) :
        return self.param1 + self.param2 + self.param3