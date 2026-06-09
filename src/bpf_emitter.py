from .ast_nodes import FilterStatement

import enum

class EndpointType(enum.Enum):
    SOURCE = enum.auto()
    DESTINATION = enum.auto()


def emit_bpf_endpoint(ast: FilterStatement, et: EndpointType):
    fragments = []

    if et == EndpointType.SOURCE:
        if ast.source.ip:
            fragments.append(f'src host {ast.source.ip}')
    
        if ast.source.port:
            if ast.source.ip is None:
                raise ValueError("source port without an IP is not supported.")

            fragments.append(f'src port {ast.source.port}')

        if ast.source.mac:
            fragments.append(f'ether src {ast.source.mac}')
    else:
        if ast.destination.ip:
            fragments.append(f'dst host {ast.destination.ip}')
    
        if ast.destination.port:
            if ast.destination.ip is None:
                raise ValueError("destination port without an IP is not supported.")

            fragments.append(f'dst port {ast.destination.port}')

        if ast.destination.mac:
            fragments.append(f'ether dst {ast.destination.mac}')

    if len(fragments) == 0: return None

    return " and ".join(fragments)


def emit_bpf_endpoints(ast: FilterStatement):
    endpoint_str = emit_bpf_endpoint(ast, EndpointType.SOURCE)
    endpoint_str = f'{endpoint_str} and {emit_bpf_endpoint(ast, EndpointType.DESTINATION)}'
    return endpoint_str


def emit_bpf_condition(ast: FilterStatement):
    if ast.condition:
        field = ast.condition.field.upper()
        op = ast.condition.operator
        val = ast.condition.value

        if field == "TCP.WINDOW_SIZE":
            return f"tcp[14:2] {op} {val}"
            
        elif field == "IP.TTL":
            return f"ip[8] {op} {val}"

    return ''


def emit_bpf(ast: FilterStatement):
    fragments = filter(lambda x: x is not '', [emit_bpf_endpoints(ast), emit_bpf_condition(ast)])
    return " and ".join(fragments)