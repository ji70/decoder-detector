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
FNAME = ABSPATH + '/decoder-detector/new_samples/graphql_stakeshare/train/parsed/100.json'
FNAME2 = ABSPATH + '/decoder-detector/new_samples/graphql_stakeshare/train/parsed/104.json'
TREE_FNAME = ABSPATH + '/decoder-detector/labels/graphql_stakeshare.txt'

STATS = []
OVERALL_STATS = {}

CORRECT_DECODERS = 0
INCORRECT_DECODERS = 0

def initial_stats():
    current_stats = {}
    for i, name in enumerate(ALL_DECODERS_CLASSES_NAMES):
        current_stats[name] = [0, 0, 0, 0] 
        # 0 - string type X, detected X, correct decoded
        # 1 - string type X, detected X, incorrect decoded
        # 2 - string type X, detected Y
        # 3 - string was Y, detected X
    #print(len(current_stats))
    return current_stats

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

def path_in_stats(path):
    check = False
    for i, pair in enumerate(STATS):
        if len(path) == len(pair[0]):
            count = len(path)
            for j, part in enumerate(path):
                #print("Current", part, pair['item_address'][i])
                if part in pair[0][j]:
                    count -= 1

            if not count:
                return True, i

    return check, len(STATS)

def count_walk(tree, decision_tree_dict, path=[]):
    #print(type(decision_tree_dict))
    for key, subtree in tree.children:
        if subtree.is_leaf():
            #print(path + [key], subtree.value)
            decoder_stats = count_decoder(subtree.value)
            # if path not in STATS, append [path, {}]
            stats_path, path_place = path_in_stats(path + [key])
            #print(path + [key], path_place)
            if not stats_path:
                STATS.append([path+[key], initial_stats(), 1])
                #print(STATS)
            else:
                STATS[path_place][2] += 1

            # if current path in ParsingDecisionTree, 
            # check stats 
            check, real_decoder = check_path(path + [key], decision_tree_dict)
            # real_decoder - name of decoder from ParsingDecisionTree, type X
            if check: 
                #print(path + [key], "exists")

                #print("REAL DECODER", real_decoder)
                for k in decoder_stats.keys():
                    # if decoder X was used (X: [1, tree_obj]), count stats
                    if k == real_decoder:
                        if decoder_stats[k][0]:
                            #print("correct detected")
                            STATS[path_place][1][k][0] += 1
                        else:
                            STATS[path_place][1][k][2] += 1
                    elif decoder_stats[k][0]:
                        STATS[path_place][1][real_decoder][2] += 1
                        STATS[path_place][1][k][3] += 1
                    #print(k, decoder_stats[k])
            else:
                #print(path + [key])
                for k in decoder_stats.keys():
                    if decoder_stats[k][0]:
                        STATS[path_place][1][k][3] += 1

                    #print(k, decoder_stats[k])
                
        else:
            count_walk(subtree, decision_tree_dict, path + [key])    # работает

def predict_decoder(decoder_stats):
    highest_prob = 0
    most_probable_decoder = None
    for key in decoder_stats.keys():
        if decoder_stats[key][0] == 1:
            if PROB_STATS[key][0] > highest_prob:
                highest_prob = PROB_STATS[key][0] 
                most_probable_decoder = key
    return most_probable_decoder

def decode_walk(tree, decision_tree_dict, path=[]):
    correctness = [0, 0]
    for key, subtree in tree.children:
        if subtree.is_leaf():
            #print(path + [key], subtree.value)
            decoder_stats = count_decoder(subtree.value)
            most_probable_decoder = predict_decoder(decoder_stats)


            check, real_decoder = check_path(path + [key], decision_tree_dict)
            
            if most_probable_decoder == real_decoder:
                #CORRECT_DECODERS += 1
                #print(path + [key], most_probable_decoder, real_decoder)
                #print("Correct guess")
                correctness[0] += 1
                
            else:
                #INCORRECT_DECODERS += 1
                print(path + [key], most_probable_decoder, real_decoder)
                print("incorrect guess")
                correctness[1] += 1
                
        else:
            current_correctness = decode_walk(subtree, decision_tree_dict, path + [key])
            correctness[0] += current_correctness[0]
            correctness[1] += current_correctness[1]
    return correctness

def file_processing(file_name, webapp_dtree, decision_tree_dict):
    with open(file_name) as request_file:
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
    #print(decision_tree_walk(webapp_dtree.dump_to_dict()))
    parse_tree = RequestParseTree.parse_request(parsed_req, webapp_dtree)[0]
    real_parse_tree = RequestParseTree.parse_request(parsed_req, decision_tree)[0]

    tree = parse_tree.tree
    real_tree = real_parse_tree.tree

    count_walk(tree, decision_tree_dict)

def file_processing_check(file_name, webapp_dtree, decision_tree_dict):
    with open(file_name) as request_file:
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
    #print(decision_tree_walk(webapp_dtree.dump_to_dict()))
    parse_tree = RequestParseTree.parse_request(parsed_req, webapp_dtree)[0]
    real_parse_tree = RequestParseTree.parse_request(parsed_req, decision_tree)[0]

    tree = parse_tree.tree
    real_tree = real_parse_tree.tree

    correctness = decode_walk(tree, decision_tree_dict)
    return correctness


def application_processing(current_path, default_webapp_dtree, decision_tree_dict):
    correctness = [0, 0]
    for path, folder, files in os.walk(current_path):
        if ('parsed' in path):
            for (i, fname) in tqdm(enumerate(files)):
                #print(path+'/'+fname)
                new_name = path+'/'+fname
                current_correctness = file_processing(new_name, default_webapp_dtree, decision_tree_dict)


    #for k in STATS:
        #print(k)    
def application_processing_check(current_path, default_webapp_dtree, decision_tree_dict):
    correctness = [0, 0]
    for path, folder, files in os.walk(current_path):
        if ('parsed' in path):
            for (i, fname) in tqdm(enumerate(files)):
                #print(path+'/'+fname)
                new_name = path+'/'+fname
                current_correctness = file_processing_check(new_name, default_webapp_dtree, decision_tree_dict)
                correctness[0] += current_correctness[0]
                correctness[1] += current_correctness[1]
    return correctness

LABEL_ABSPATH = ABSPATH + '/decoder-detector/new_labels/'

def all_applictions_processing(default_webapp_dtree, label_path):
    for path, folder, files in os.walk(ABSPATH +'/decoder-detector/new_samples/'):
        if ('parsed' not in path and 'train' not in path and 'test' not in path and 'perekrestok_base64' not in path and 'gwt' not in path):
            print(path)
            if len(path[path.rfind('/'):]) > 1:
                current_tree_path = label_path + path[path.rfind('/')+1:] + '.txt'
                print(current_tree_path)
                with open(current_tree_path) as tree_file:
                    tree_string = tree_file.read()
                    #print("TREE", tree_string)
                    tree_string = tree_string.replace('\'', '"')
                    tree_string = tree_string.replace('u"', '"')
                    #print(tree_string)
                    tree_dict = json.loads(tree_string)
                    decision_tree = ParsingDecisionTree.init_from_dict(tree_dict) # открываем реальное дерево приложения

                decision_tree_dict = decision_tree_walk(decision_tree.dump_to_dict())

                print(decision_tree_dict)

                application_processing(path, default_webapp_dtree, decision_tree_dict)


    #for k in STATS:
        #print(k)

def all_applictions_processing_check(default_webapp_dtree, label_path):
    correctness = [0, 0]
    for path, folder, files in os.walk(ABSPATH +'/decoder-detector/new_samples/graphql_stakeshare'):
        if ('parsed' not in path and 'train' not in path and 'test' not in path and 'perekrestok_base64' not in path and 'gwt' not in path):
            print("CHECK path", path)
            if len(path[path.rfind('/'):]) > 1:
                current_tree_path = label_path + path[path.rfind('/')+1:] + '.txt'
                print(current_tree_path)
                with open(current_tree_path) as tree_file:
                    tree_string = tree_file.read()
                    #print("TREE", tree_string)
                    tree_string = tree_string.replace('\'', '"')
                    tree_string = tree_string.replace('u"', '"')
                    #print(tree_string)
                    tree_dict = json.loads(tree_string)
                    decision_tree = ParsingDecisionTree.init_from_dict(tree_dict) # открываем реальное дерево приложения

                decision_tree_dict = decision_tree_walk(decision_tree.dump_to_dict())

                print(decision_tree_dict)

                current_correctness = application_processing_check(path, default_webapp_dtree, decision_tree_dict)
                correctness[0] += current_correctness[0]
                correctness[1] += current_correctness[1]
    return correctness

def stats_to_csv():
    st_df = pd.DataFrame()
    st_dict = {}
    for k in STATS:
        path = ''
        for i in k[0]:
            path += str(i)+'/' 

        for key in k[1].keys():
            current = ''
            for i in k[1][key]:
                current += str(i)+',' 
            k[1][key] = current
        st_dict[path] = k[1]
    st_df = pd.DataFrame(st_dict)
    st_df.to_csv('stats.csv')

PROB_STATS = {'Base64DetectorDecoder': [0.00014438886249522586, 0, 0, 0.9998556111375048],
 'JsonRPCDetectorParser': [0, 0, 0, 0],
 'CSVDetectorParser': [0, 0, 0, 0.7447404162987978],
 'XMLDetectorParser': [0, 0, 0, 0],
 'JSONPDetectorParser': [0, 0, 0, 1.1882708164252297e-06],
 'Base32DetectorDecoder': [0, 0, 0, 0.18485691436964016],
 'YAMLDetectorParser': [0, 0, 0, 0.7408488293750052],
 'GraphQLDetectorParser': [0.9969571832210389, 0, 0, 0.0030428167789610956],
 'JSONDetectorParser': [0.06675758096383472, 0, 0, 0.9332424190361652],
 'DeflateUnpacker': [0, 0, 0, 0],
 'FormUrlencodeParser': [0.010992371626299726, 0, 0, 0.9890076283737003],
 'GzipUnpacker': [0, 0, 0, 0.009342185158735156],
 'UrlParser': [0, 0, 0, 0.7747953500586412],
 'DSVDetectorParser': [0, 0, 0, 0.765453164899906],
 'Base16DetectorDecoder': [0, 0, 0, 0.03973815264289254]}


if __name__ == "__main__":
    CORRECT_DECODERS = 0
    INCORRECT_DECODERS = 0
    initial_stats()

    with open(TREE_FNAME) as tree_file:
        tree_string = tree_file.read()
        #print("TREE", tree_string)
        tree_string = tree_string.replace('\'', '"')
        tree_string = tree_string.replace('u"', '"')
        #print(tree_string)
        tree_dict = json.loads(tree_string)
        decision_tree = ParsingDecisionTree.init_from_dict(tree_dict) # открываем реальное дерево

    pdtree_manager = RequestParsingDecisionTreeManager()
    default_webapp_dtree = pdtree_manager.get_webapp_tree(None) # открываем исходное дерево, потому что хотим пробовать все декодеры

    #print("DEFAULT_TREE", default_webapp_dtree.dump_to_dict())

    decision_tree_dict = decision_tree_walk(decision_tree.dump_to_dict())

    with open(ABSPATH+'/decoder-detector/less_general_tree.txt') as new_tree_file:
        lg_tree_string = new_tree_file.read()
        print("TREE", lg_tree_string)
        lg_tree_string = lg_tree_string.replace('\'', '"')
        lg_tree_string = lg_tree_string.replace('u"', '"')
        #print(lg_tree_string)
        lg_tree_dict = json.loads(lg_tree_string)
        lg_decision_tree = ParsingDecisionTree.init_from_dict(lg_tree_dict) # открываем реальное дерево

    print("LESS GENERAL TREE")
    decision_tree_walk(lg_decision_tree.dump_to_dict())

    """
    
    file_processing(FNAME, lg_decision_tree, decision_tree_dict)
    for elem in STATS:
        print(elem)
    print("SECOND FILE")
    file_processing(FNAME2, lg_decision_tree, decision_tree_dict)
    for elem in STATS:
       print(elem)
       """
    

    
    #all_applictions_processing(lg_decision_tree, ABSPATH + '/decoder-detector/new_labels/')
    correctness = all_applictions_processing_check(default_webapp_dtree, ABSPATH + '/decoder-detector/labels/')
    CORRECT_DECODERS, INCORRECT_DECODERS = correctness[0], correctness[1]

    #application_processing(ABSPATH + '/decoder-detector/new_samples/graphql_stakeshare/', default_webapp_dtree, decision_tree_dict)
    
    #with open(ABSPATH+'/decoder-detector/stats_full.txt', 'w') as stats_file:
    #    for path in STATS:
    #        stats_file.write(str(path) + '\n')   

    print("Result:")
    print("Correct guesses ", CORRECT_DECODERS)
    print("Incorrect guesses ", INCORRECT_DECODERS)
