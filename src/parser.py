import ply.yacc as yacc
from .lexer import tokens
from . import ast_nodes as ast


def p_statement_root(p: yacc.YaccProduction):
    '''statement : FROM endpoint TO endpoint
                 | FROM endpoint TO endpoint where_clause'''
    if len(p) == 6:
        p[0] = ast.FilterStatement(source=p[2], destination=p[4], where_clause=p[5])
    else:
        p[0] = ast.FilterStatement(source=p[2], destination=p[4])


def p_ip_address(p: yacc.YaccProduction):
    '''
    ip_address : IP_ADDRESS 
                | ANY
    '''
    p[0] = p[1]


def p_port_num(p: yacc.YaccProduction):
    '''
    port_num : NUMBER 
    '''
    p[0] = p[1]


def p_endpoint_ip_and_port(p: yacc.YaccProduction):
    '''
    endpoint : ip_address COLON port_num
    '''
    p[0] = ast.Endpoint(ip=p[1], mac=None, port=p[3])
    

def p_endpoint_ip_and_mac(p: yacc.YaccProduction):
    '''
    endpoint : ip_address AT MAC_ADDRESS
    '''
    p[0] = ast.Endpoint(ip=p[1], mac=p[3], port=None)


def p_endpoint_ip_port_and_mac(p: yacc.YaccProduction):
    '''
    endpoint : ip_address COLON port_num AT MAC_ADDRESS
    '''
    p[0] = ast.Endpoint(ip=p[1], port=p[3], mac=p[5])


def p_endpoint_port_only(p: yacc.YaccProduction):
    '''
    endpoint : COLON port_num
    '''
    p[0] = ast.Endpoint(ip=None, port=p[2], mac=None)


def p_endpoint_ip_only(p: yacc.YaccProduction):
    '''
    endpoint : ip_address
    '''
    p[0] = ast.Endpoint(ip=p[1], mac=None, port=None)


def p_endpoint_mac_only(p: yacc.YaccProduction):
    '''
    endpoint : AT MAC_ADDRESS
    '''
    p[0] = ast.Endpoint(mac=p[2], ip=None, port=None)


def p_condition(p: yacc.YaccProduction):
    '''
    condition : FIELD OPERATOR VALUE
                | FIELD OPERATOR NUMBER
    '''
    p[0] = ast.Condition(field=p[1], operator=p[2], value=p[3])


def p_condition_list(p: yacc.YaccProduction):
    '''
    condition_list : condition 
                    | condition_list COMMA condition
    '''
    if len(p) == 4:
        p[0] = ast.ConditionList(conditions=p[1] + [p[3]])
    else:
        p[0] = ast.ConditionList(conditions=[p[1]])


def p_where_clause(p: yacc.YaccProduction):
    '''
    where_clause : WHERE condition_list
    '''
    p[0] = ast.WhereClause(condition_list=p[2])


def p_error(p: yacc.YaccError):
    if p:
        print(f"Syntax error at token {p.type} (Value: {p.value})")
    else:
        print("Syntax error: Unexpected end of input")


_parser = yacc.yacc()

def parse(input: str):
    return _parser.parse(input)