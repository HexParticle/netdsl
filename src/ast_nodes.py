# An endpoint is something that can receive data such as an Ethernet port.
class Endpoint():
    def __init__(self, ip: str, mac: str, port: int = None):
        self.ip = ip
        self.port = port
        self.mac = mac    


class Condition:
    def __init__(self, field: str, operator: str, value: str):
        self.field = field
        self.operator = operator
        self.value = value


class FilterStatement:
    def __init__(self, source: Endpoint, destination: Endpoint, condition: Condition = None):
        self.source = source
        self.destination = destination
        self.condition = condition