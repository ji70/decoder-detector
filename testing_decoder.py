#! /usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import uuid
import functools
from copy import deepcopy
import sys
import os
import json
import glob
import difflib
import psycopg2
from datetime import datetime

sys.path.append('/waf/')

import common
from data_objects.http import (
    ParsedHttpResponse,
    ParsedHttpRequest,
    RequestAction,
    RequestParseTree
)


from data_objects.parse_decision_tree import ParsingDecisionTree
from common.settings import load_settings_mongo
from common.db.http_transaction import TxManager
from common.db.decision_tree import RequestParsingDecisionTreeManager, ResponseParsingDecisionTreeManager
from data_objects.predicates import CheckPaths
 
from common.db.dumper import ManagerDumper, BatchManagerDumper
from common.settings import config
from mock import patch, MagicMock

from common.db.http_transaction import TxManager

from common.formats.content_type import ContentTypeHeaderParser
from common.formats.cookie_header import CookieHeaderParser
from common.formats.csv_parser import CSVDetectorParser
from common.formats.deflate_parser import DeflateUnpacker
from common.formats.dsv_parser import DSVDetectorParser
from common.formats.form_urlencode import FormUrlencodeParser
from common.formats.graphql_parser import GraphQLDetectorParser
from common.formats.gzip_parser import GzipUnpacker
from common.formats.html_parser import HTMLDetectorParser
from common.formats.json_p_parser import JSONPDetectorParser
from common.formats.json_parser import JSONDetectorParser
from common.formats.json_rpc_parser import JsonRPCDetectorParser
from common.formats.multipart_auto_boundary import AutoBoundaryMultipartParser
from common.formats.multipart_form_data import MultipartFormDataParser
from common.formats.php_serialize_parser import PHPSerializeDetectorParser
from common.formats.regex_group_parser import RegexGroupParser
from common.formats.set_cookie_header import SetCookieHeaderParser
from common.formats.soap_parser import SOAPDetectorParser
from common.formats.static_prefix_parser import StaticPrefixParser
from common.formats.url_parser import UrlParser
from common.formats.xml_parser import XMLDetectorParser
from common.formats.xml_rpc_parser import XMLRPCDetectorParser
from common.formats.yaml_parser import YAMLDetectorParser
from common.encodings.base_encodings import Base64DetectorDecoder, Base32DetectorDecoder,\
    Base16DetectorDecoder

from data_objects.parse_tree_node import ParseTreeNodeTypes, ParseTreeNode


from parse_headers import parse
from decoding import count_decoder, ALL_DECODERS_CLASSES, ALL_DECODERS_CLASSES_NAMES


try:
    ParsedHttpRequest()
    RequestParsingDecisionTreeManager()
except:
    pass

TRAIN = '/train'
TEST = '/test'
PARSED = '/parsed'
webapp_id='56d69c95-2cc0-4da5-92e3-b514f3681932' # current waf webapp_id
MONGO = "mongodb://waf:0d678fdb64062f178033@localhost/waf" # from /etc/default/solidwall-analyzer
ABSPATH = os.path.abspath('.')
FNAME = ABSPATH + '/decoder-detector/new_samples/foodband/train/parsed/100.json'
TREE_FNAME = ABSPATH + '/decoder-detector/labels/foodband.txt'

STATS = {}

def initial_stats():
    for i, name in enumerate(ALL_DECODERS_CLASSES_NAMES):
        STATS[name] = [0, 0, 0, 0] 
        # 0 - string type X, detected X, correct decoded
        # 1 - string type X, detected X, incorrect decoded
        # 2 - string type X, detected Y
        # 3 - string was Y, detected X
    print(len(STATS))


def decision_tree_walk(decision_dict):
    path_decoder_dict = []
    for key in decision_dict.keys():
        if 'children' not in key:
            #print(key, decision_dict[key], type(decision_dict[key]))
            if isinstance(decision_dict[key], dict):
                #print(decision_dict[key]['item_address'], decision_dict[key]['parser_class'])

                path_decoder_dict.append({'item_address': decision_dict[key]['item_address'], 
                                        'parser_class': decision_dict[key]['parser_class']})
                #print(path_decoder_dict)
        else:
            for i, child in enumerate(decision_dict[key]):
                #print(i, child)
                path_decoder_dict += decision_tree_walk(child['subtree'])

    return path_decoder_dict


def new_walk(tree, decision_tree_dict, path=[]):
    # функция для обхода дерева
    # для каждого листа нужно проверить все декодеры
    #decision_tree_walk(decision_tree.dump_to_dict())

    for key, subtree in tree.children:
        if subtree.is_leaf():
            print(path + [key], subtree.value)
            decoder_stats = count_decoder(subtree.value)
            """
            for key in decoder_stats.keys():
                print(key, decoder_stats[key])
                """
        else:
            new_walk(subtree, decision_tree, path + [key])

def check_path(path, decision_tree_dict):
    #print(path)
    check = False
    for pair in decision_tree_dict:
        #print("SAME?", path, pair['item_address'])
        if len(path) == len(pair['item_address']):
            count = len(path)
            for i, part in enumerate(path):
                #print("Current", part, pair['item_address'][i])
                if part in pair['item_address'][i]:
                    count -= 1

            if not count:
                #print(path, pair['item_address'])
                name = pair['parser_class']

                return True, name

    return check, None

def count_walk(tree, decision_tree_dict, path=[]):
    #print(type(decision_tree_dict))
    for key, subtree in tree.children:
        if subtree.is_leaf():
            #print(path + [key], subtree.value)
            decoder_stats = count_decoder(subtree.value)

            # if current path in ParsingDecisionTree, 
            # check stats 
            check, real_decoder = check_path(path + [key], decision_tree_dict)
            # real_decoder - name of decoder from ParsingDecisionTree, type X
            if check: 
                print(path + [key], "exists")

                print("REAL DECODER", real_decoder)
                for k in decoder_stats.keys():
                    # if decoder X was used (X: [1, tree_obj]), count stats
                    if k == real_decoder:
                        if decoder_stats[k][0]:
                            print("correct detected")
                            STATS[k][0] += 1
                        else:
                            STATS[k][2] += 1
                    elif decoder_stats[k][0]:
                        STATS[k][3] += 1
                    print(k, decoder_stats[k])
                
        else:
            count_walk(subtree, decision_tree_dict, path + [key])    


if __name__ == "__main__":
    initial_stats()

    with open(TREE_FNAME) as tree_file:
        tree_string = tree_file.read()
        #print("TREE", tree_string)
        tree_string = tree_string.replace('\'', '"')
        tree_string = tree_string.replace('u"', '"')
        #print(tree_string)
        tree_dict = json.loads(tree_string)
        decision_tree = ParsingDecisionTree.init_from_dict(tree_dict) # открываем реальное дерево

    #decision_tree = ParsingDecisionTree.init_from_dict(json.load(open(TREE_FNAME))) # открываем реальное дерево

    #print("REAL_TREE", decision_tree.dump_to_dict())


    pdtree_manager = RequestParsingDecisionTreeManager()
    default_webapp_dtree = pdtree_manager.get_webapp_tree(None) # открываем исходное дерево, потому что хотим пробовать все декодеры

    #print("DEFAULT_TREE", default_webapp_dtree.dump_to_dict())


    with open(FNAME) as request_file:
        request_string = request_file.read()
        #print("REQUEST", request_string)
        request = eval(request_string) # в виде ParsedHTTPRequest 

    parsed_req = ParsedHttpRequest(
                    webapp_id=request['webapp_id'],
                    time=datetime.now(tz=psycopg2.tz.FixedOffsetTimezone(offset=180, name=None)),
                    uri=request['uri'],
                    src_ip=request['src_ip'],
                    dst_ip=request['dst_ip'], # wafplayground8
                    src_port=request['src_port'],
                    dst_port=request['dst_port'], # waf port
                    obj_id=request['obj_id'],
                    headers=request['headers'],
                    protocol=request['protocol'],
                    method=request['method'],
                    body=request['body'],
                    raw_uri=request['raw_uri'],
                    type="request")

    parse_tree = RequestParseTree.parse_request(parsed_req, default_webapp_dtree)[0]
    real_parse_tree = RequestParseTree.parse_request(parsed_req, decision_tree)[0]

    tree = parse_tree.tree
    real_tree = real_parse_tree.tree
    #print(type(tree))    
    new_walk(tree, decision_tree) 
    #print("REAL WALK")
    #new_walk(real_tree, decision_tree)
    print("PARSING TREE DESCRIPTION")
    decision_tree_dict = decision_tree_walk(decision_tree.dump_to_dict())
    
    print("FROM DICT")
    #print(decision_tree_dict)
    for pair in decision_tree_dict:
        print(pair['item_address'], pair['parser_class'])
    

    print("COUNT WALK")
    count_walk(tree, decision_tree_dict)


    for k in STATS.keys():
        print(k, STATS[k])

