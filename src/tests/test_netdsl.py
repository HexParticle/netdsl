import unittest
from .. import parser
from .. import bpf_emitter

class TestNetDSLCompiler(unittest.TestCase):
    def test_valid_transpilations(self):
        test_cases = [
            {
                "name": "Simple IP to IP",
                "input": "FROM 10.0.0.1 TO 10.0.0.2",
                "expected": "(src host 10.0.0.1) and (dst host 10.0.0.2)"
            },
            {
                "name": "Endpoints with Ports",
                "input": "FROM 192.168.1.1:80 TO 172.16.0.5:443",
                "expected": "(src host 192.168.1.1 and src port 80) and (dst host 172.16.0.5 and dst port 443)"
            },
            {
                "name": "Where clause with numeric value",
                "input": "FROM 10.0.0.1 TO 10.0.0.2 WHERE TCP.WINDOW_SIZE > 1024",
                "expected": "(src host 10.0.0.1) and (dst host 10.0.0.2) and (tcp[14:2] > 1024)"
            },
            {
                "name": "Where clause with string flag literal",
                "input": "FROM 10.0.0.1 TO 10.0.0.2 WHERE IP.TTL = 10",
                "expected": "(src host 10.0.0.1) and (dst host 10.0.0.2) and (ip[8] = 10)"
            }
        ]

        for case in test_cases:
            with self.subTest(case=case["name"]):
                ast = parser.parse(case["input"])
                self.assertIsNotNone(ast, f"Failed to parse valid input in: {case['name']}")
                
                bpf_output = bpf_emitter.emit_bpf(ast)
                self.assertEqual(bpf_output, case["expected"])

    
    def test_tex_syntax_errors(self):
        invalid_inputs = [
            "FROM 10.0.0.1",
            "FROM 10.0.0.1 TO",
            "FROM 10.0.0.1 TO 10.0.0.2 WHERE",
            "FROM 10.0.0.1 TO 10.0.0.2 WHERE TCP.FLAGS =",
            "FROM 999.999.999.999 TO 10.0.0.1"
        ]

        for bad_input in invalid_inputs:
            with self.subTest(input=bad_input):
                ast = parser.parse(bad_input)
                self.assertIsNone(ast, f"Parser incorrectly accepted wrong syntax: {bad_input}")

    
    def test_src_and_dest_both_mac_addresses(self):
        test_cases = [
            {
                'name': 'Test Mac to Mac is Okay',
                'input': 'from aa:bb:cc:dd:ee:ff to ff:ee:dd:cc:bb:aa',
                'expected': '(src)'
            }
        ]


if __name__ == "__main__":
    unittest.main()