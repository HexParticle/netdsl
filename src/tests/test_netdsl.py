import unittest
from .. import parser
from .. import bpf_emitter

class TestNetDSLCompiler(unittest.TestCase):
    def run_emitted_bpf_should_be_valid_test_cases(self, test_cases):
        for case in test_cases:
            with self.subTest(case=case["name"]):
                ast = parser.parse(case["input"])
                self.assertIsNotNone(ast, f"Failed to parse valid input in: {case['name']}")
                
                bpf_output = bpf_emitter.emit_bpf(ast)
                self.assertEqual(bpf_output, case["expected"])


    def test_valid_transpilations(self):
        test_cases = [
            {
                "name": "Simple IP to IP",
                "input": "FROM 10.0.0.1 TO 10.0.0.2",
                "expected": "src host 10.0.0.1 and dst host 10.0.0.2"
            },
            {
                "name": "Endpoints with Ports",
                "input": "FROM 192.168.1.1:80 TO 172.16.0.5:443",
                "expected": "src host 192.168.1.1 and src port 80 and dst host 172.16.0.5 and dst port 443"
            },
            {
                "name": "Where clause with numeric value",
                "input": "FROM 10.0.0.1 TO 10.0.0.2 WHERE TCP.WIN_SIZE > 1024",
                "expected": "src host 10.0.0.1 and dst host 10.0.0.2 and tcp[14:2] > 1024"
            },
            {
                "name": "Where clause with string flag literal",
                "input": "FROM 10.0.0.1 TO 10.0.0.2",
                "expected": "src host 10.0.0.1 and dst host 10.0.0.2"
            }
        ]

        self.run_emitted_bpf_should_be_valid_test_cases(test_cases)

    
    def test_tex_syntax_errors(self):
        invalid_inputs = [
            "FROM 10.0.0.1",
            "FROM 10.0.0.1 TO",
            "FROM 10.0.0.1 TO 10.0.0.2 WHERE",
            "FROM 10.0.0.1 TO 10.0.0.2 WHERE TCP.FLAGS =",
            "FROM 999.999.999.999 TO 10.0.0.1",
            "FROM 1234.1.1.1 TO 10.0.0.1",
            "FROM @aa:bb:cc:dd:ee:ff TO 12345",
            "FROM TO",
            "FROM 1.1.1.1@a-a-a-a-a-a TO"
        ]

        for bad_input in invalid_inputs:
            with self.subTest(input=bad_input):
                ast = parser.parse(bad_input)
                self.assertIsNone(ast, f"Parser incorrectly accepted wrong syntax: {bad_input}")

    
    def test_src_and_dest_both_containing_mac_addresses(self):
        test_cases = [
            {
                'name': 'Test From Mac to Mac is Okay',
                'input': 'FROM @aa:bb:cc:dd:ee:ff TO @ff:ee:dd:cc:bb:aa',
                'expected': 'ether src aa:bb:cc:dd:ee:ff and ether dst ff:ee:dd:cc:bb:aa'
            },
            {
                'name': 'Test From IP@Mac to IP:port@Mac is Okay',
                'input': 'FROM 1.1.1.1@aa:bb:cc:dd:ee:ff TO 2.2.2.2:2222@ff:ee:dd:cc:bb:aa',
                'expected': 'src host 1.1.1.1 and ether src aa:bb:cc:dd:ee:ff and dst host 2.2.2.2 and dst port 2222 and ether dst ff:ee:dd:cc:bb:aa'
            },
            {
                'name': 'Test From Mac to IP:port@Mac is Okay',
                'input': 'FROM @aa:bb:cc:dd:ee:ff TO 2.2.2.2:2222@ff:ee:dd:cc:bb:aa',
                'expected': 'ether src aa:bb:cc:dd:ee:ff and dst host 2.2.2.2 and dst port 2222 and ether dst ff:ee:dd:cc:bb:aa'
            },
            {
                'name': 'Test From Mac to IP:port is Okay',
                'input': 'FROM @aa:bb:cc:dd:ee:ff TO 2.2.2.2:2222',
                'expected': 'ether src aa:bb:cc:dd:ee:ff and dst host 2.2.2.2 and dst port 2222'
            }
        ]

        self.run_emitted_bpf_should_be_valid_test_cases(test_cases)


    def test_where_clause_multiple_supported_tcp_fields(self):
        test_cases = [
            {
                "name": "Multiple TCP ports with AND",
                "input": "FROM 10.0.0.1 TO 10.0.0.2 WHERE TCP.SRC_PORT = 80, TCP.DST_PORT = 443",
                "expected": "src host 10.0.0.1 and dst host 10.0.0.2 and tcp[0:2] = 80 and tcp[2:2] = 443"
            },
            {
                "name": "TCP sequence and acknowledgment numbers with OR",
                "input": "FROM 10.0.0.1 TO 10.0.0.2 WHERE TCP.SEQ_NUM = 1000, TCP.ACK_NUM = 2000",
                "expected": "src host 10.0.0.1 and dst host 10.0.0.2 and tcp[4:4] = 1000 and tcp[8:4] = 2000"
            },
            {
                "name": "TCP window size and urgent pointer conditions",
                "input": "FROM 10.0.0.1 TO 10.0.0.2 WHERE TCP.WIN_SIZE > 2048, TCP.URG_PTR = 0",
                "expected": "src host 10.0.0.1 and dst host 10.0.0.2 and tcp[14:2] > 2048 and tcp[18:2] = 0"
            },
            {
                "name": "Complex chaining of multiple TCP offsets",
                "input": "FROM 10.0.0.1 TO 10.0.0.2 WHERE TCP.SRC_PORT = 80, TCP.SEQ_NUM > 0, TCP.CKSUM = 5000",
                "expected": "src host 10.0.0.1 and dst host 10.0.0.2 and tcp[0:2] = 80 and tcp[4:4] > 0 and tcp[16:2] = 5000"
            }
        ]
        self.run_emitted_bpf_should_be_valid_test_cases(test_cases)


    def test_any_endpoints(self):
        test_cases = [
            {
                "name": "Any IP",
                "input": "FROM ANY TO ANY",
                "expected": ""
            },
            {
                "name": "Any IP and Any Port to some other IP",
                "input": "FROM ANY TO 192.168.1.1",
                "expected": "dst host 192.168.1.1"
            },
            {
                "name": "Any IP, a specific Port and Any MAC to some other IP",
                "input": "FROM ANY:12345 TO 192.168.1.1",
                "expected": "src port 12345 and dst host 192.168.1.1"
            },
        ]
        self.run_emitted_bpf_should_be_valid_test_cases(test_cases)


if __name__ == "__main__":
    unittest.main()