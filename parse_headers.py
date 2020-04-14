from urlparse import urlparse, parse_qs, parse_qsl
from collections import OrderedDict
import xml.etree.ElementTree as ET

import base64
import json

from urlparse import urlparse, parse_qs, parse_qsl
from collections import OrderedDict
import xml.etree.ElementTree as ET

import base64
import json

def parse_method(first_line, parsed_request):
    """ 
    Function for parsing of method, url, httpVersion 
    adding into parsed_request.
    :param first_line: string
    :param parsed_request: dictionary
    """
    parsed_first_line = first_line.split(' ')
    #for elem in parsed_first_line:
    #    print(elem)
    parsed_request["method"] = parsed_first_line[0]
    parsed_request["url"] = parsed_first_line[1]
    #parse_query_string(parsed_request["url"], parsed_request)
    #parsed_request["httpVersion"] = parsed_first_line[2]

def parse_header(line, parsed_request):
    """ 
    Function for parsing of each header and 
    adding into parsed_request['headers']{}.
    :param line: string
    :param parsed_request: dictionary
    """
    header_name = line.split(' ')[0]
    header_value = line.replace(header_name+" ", "")
    header_pair = (header_name, header_value)
    #print(header_dict)
    parsed_request["headers"].append(header_pair)


def find_content_len(parsed_request):
    for header_dict in parsed_request["headers"]:
        #print(header_dict)
        if header_dict[0] == "Content-Length":
            #print("Content-Length found")
            return int(header_dict[1])
    return 0

def parse_body(line, parsed_request):
    """ 
    Function for parsing of body and 
    adding into parsed_request['cookies']{}.
    :param line: string
    :param parsed_request: dictionary
    """
    #print("I am body parser")
    line = line.replace("\r", "")
    if line:
        parsed_request["bodySize"] = find_content_len(parsed_request)
        if "body" not in parsed_request.keys():
            parsed_request["body"] = ""
            parsed_request["body"] = str(line + "\n")
            print(type(parsed_request["body"]))
        else:
            parsed_request["body"] += str(line + "\n")


def parse(request):
    parsed_request = {}
    #print("\nParsing function")
    lines = request.split("\n")
    
    parsed_request["headers"] = []
    parsed_request["queryString"] = []
    parsed_request["bodySize"] = 0
    parsed_request["body"] = ""
    #parsed_request["cookies"] = []
    parse_func = parse_method
    for i,line in enumerate(lines):
        #print(i, line)
        if line == '':
            parse_func = parse_body
            
        if i == 0:
            parse_func(line, parsed_request)
            parse_func = parse_header
        else:
            parse_func(line, parsed_request)
    #print(str(parsed_request))
    
    return parsed_request

