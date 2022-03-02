class Api:
    function_name: str
    return_info: str
    arguments_info: str

    def __init__(self, function_name, return_info, arguments_info):
        self.function_name = function_name
        self.return_info = return_info
        self.arguments_info = arguments_info

    def __str__(self):
        return f"Api(function_name={self.function_name})"

    def __repr__(self):
        return str(self)

class Arg:
    name: str
    flag: str
    size: int
    type: str

    def __init__(self, name, flag, size, type):
        self.name = name
        self.flag = flag
        self.size = size
        self.type = type

    def __str__(self):
        return f"Arg(name={self.name})"

    def __repr__(self):
        return str(self)