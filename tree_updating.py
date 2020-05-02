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
import pandas as pd
from tqdm import tqdm

sys.path.append('/waf/')
sys.path.append('/home/anna/Documents/Work/solidwall-analyzer/')

import common
from data_objects.http import (
    ParsedHttpResponse,
    ParsedHttpRequest,
    RequestAction,
    RequestParseTree
)


from data_objects.parse_decision_tree import ParsingDecisionTree, ParseStep
from data_objects.predicates import Predicate
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

STATS = []
OVERALL_STATS = {}

PATH_DECODERS = {}

D = {"['body', 'request']": 'JSONDetectorParser', "['body', 'answers']": 'JSONDetectorParser', "['body', 'bgRequest']": 'JSONDetectorParser', "['body', 'deviceinfo']": 'JSONDetectorParser', "['body', 'cookiesDisabled']": 'JSONDetectorParser', "['body', 'f.req']": 'JSONDetectorParser', "['body', 'diagnostics']": 'JSONDetectorParser', "['url', 'query', 'gtm']": 'FormUrlencodeParser'}




def name_decoder(name):
    for i, n in enumerate(ALL_DECODERS_CLASSES_NAMES):
        if n == name:
            return ALL_DECODERS_CLASSES[i]


def walk_append_child(tree, path_decoder_dict):
    for path in path_decoder_dict.keys():
        current_decoder_name = path_decoder_dict[path]
        path = path.replace(' ', '')
        path = path.replace('\'', '')
        print(type(path), path[1:-1].split(','))

        new_tree = ParsingDecisionTree(
            policy=ParsingDecisionTree.ChildSelectionPolicy.EVERY_MATCH,
            action=ParseStep(
                parser_class=name_decoder(current_decoder_name),
                item_address=path[1:-1].split(','),
                parser_settings = {}
            )
        )
        #print(current_dict)
        tree.append_child(
            CheckPaths(path[1:-1].split(',')),
            ParsingDecisionTree(**new_tree.dump_to_dict())
            )
    return tree

def walk_tree(tree):
    # функция для обхода дерева
    # для каждого листа нужно проверить все декодеры

    for pred, subtree in tree.children:
        #print(pred.dump_to_dict(), subtree.dump_to_dict())
        #print()
        walk_tree(subtree)


if __name__ == "__main__":
    pdtree_manager = RequestParsingDecisionTreeManager()
    default_webapp_dtree = pdtree_manager.get_webapp_tree(None) # открываем исходное дерево, потому что хотим пробовать все декодеры

    walk_tree(default_webapp_dtree)

    new_tree = walk_append_child(default_webapp_dtree, D)

    #print("AFTER APPEND")

    walk_tree(new_tree)
    print(new_tree.dump_to_dict())


    with open(ABSPATH+'/decoder-detector/result_labels/teachercenter.txt', 'w') as file:
        file.write(str(new_tree.dump_to_dict()))