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
 
from common.db.dumper import ManagerDumper, BatchManagerDumper
from common.settings import config
from mock import patch, MagicMock

from common.db.http_transaction import TxManager


from parse_headers import parse


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

tree = parse_tree.tree
print(type(tree))

def new_walk(tree, path=[]):
    # функция для обхода дерева
    # для каждого листа нужно проверить все декодеры
    for key, subtree in tree.children:
        if subtree.is_leaf():
            print(path + [key], subtree.value)
        else:
            new_walk(subtree, path + [key])

new_walk(tree)         