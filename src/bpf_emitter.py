from ast_nodes import FilterStatement

def emit_bpf(ast: FilterStatement):
    fragments = []

    src_str = f'src host {ast.source.ip}'
    if ast.source.port:
        src_str = f'{src_str} and src port {ast.source.port}'

    fragments.append(src_str)

    dst_str = f'dst host {ast.destination.ip}'
    if ast.destination.port:
        dst_str = f'{dst_str} and dst port {ast.destination.port}'	

    fragments.append(dst_str)

    if ast.condition:
        field = ast.condition.field.upper()
        op = ast.condition.operator
        val = ast.condition.value

        if field == "TCP.WINDOW_SIZE":
            fragments.append(f"tcp[14:2] {op} {val}")
            
        elif field == "IP.TTL":
            fragments.append(f"ip[8] {op} {val}")

    return " and ".join(fragments)