class Api:
    function_name: str
    is_vararg: bool
    return_info: str
    arguments_info: str

    def __init__(self, function_name, is_vararg, return_info, arguments_info):
        self.function_name = function_name
        self.is_vararg = is_vararg
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
    is_type_incomplete: bool

    def __init__(self, name, flag, size, type, is_type_incomplete):
        self.name = name
        self.flag = flag
        self.size = size
        self.type = type
        self.is_type_incomplete = is_type_incomplete

    def __str__(self):
        return f"Arg(name={self.name})"

    def __repr__(self):
        return str(self)