from . import parser
from . import bpf_emitter

if __name__ == "__main__":
    dsl_input = "FROM 192.168.1.1:3000 TO 192.168.1.2 WHERE TCP.WINDOW_SIZE > 1024"
    
    ast_root = parser.parse(dsl_input)

    if ast_root:
        bpf_output = bpf_emitter.emit_bpf(ast_root)
        print(f"NetDSL Input:  {dsl_input}")
        print(f"BPF Literal:   \"{bpf_output}\"")