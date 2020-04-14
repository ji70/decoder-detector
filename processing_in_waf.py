import unittest
import uuid
import functools
from copy import deepcopy
import sys
sys.path.append('/home/anna/Documents/Work/solidwall-analyzer/')
#exec('/home/anna/Documents/Work/solidwall-analyzer/data_objects/')
#sys.path.append('/waf/')

#import common
from data_objects.http import (
    ParsedHttpResponse,
    ParsedHttpRequest,
    RequestAction,
    RequestParseTree
)

#from common.db.decision_tree import RequestParsingDecisionTreeManager, ResponseParsingDecisionTreeManager
 
#from common.db.dumper import ManagerDumper, BatchManagerDumper
from common.settings import config
#from mock import patch, MagicMock
from common.settings import load_settings_mongo
#from common.db.http_transaction import TxManager

import os
import json
import glob
import difflib
import psycopg2
import shutil
from datetime import datetime

from parse_headers import parse

TRAIN = '/train'
TEST = '/test'
PARSED = '/parsed'
webapp_id='56d69c95-2cc0-4da5-92e3-b514f3681932' # current waf webapp_id
MONGO = "mongodb://waf:0d678fdb64062f178033@localhost/waf" # from /etc/default/solidwall-analyzer


def processing (request):
    parsed = parse(request)
            
    request_id = uuid.uuid4() # random uuid
    #print(parsed)
    the_headers = parsed["headers"]
    parsed_req = ParsedHttpRequest(
        webapp_id=webapp_id,
        time=datetime.now(tz=psycopg2.tz.FixedOffsetTimezone(offset=180, name=None)),
        uri={},
        src_ip="10.0.0.14",
        dst_ip="10.72.55.226", # wafplayground8
        src_port=44332,
        dst_port=80, # waf port
        obj_id=request_id,
        headers=the_headers,
        protocol=1.1,
        method=parsed["method"],
        body=parsed["body"],
        raw_uri=parsed["url"],
        type="request")

    return parsed_req

def train_test_parsed_trees():
    for path, folder, files in os.walk('.'):
        if (('train' in path or 'test' in path) and 'parsed' not in path):
            if os.path.exists(path+PARSED):
                shutil.rmtree(path+PARSED)
            
            if not os.path.exists(path+PARSED):
                os.makedirs(path+PARSED)

            for (i, fname) in enumerate(files):
                print(path+'/'+fname)
                with open(path+'/'+fname) as request_file:
                    request = request_file.read()

                parsed_req = processing(request)
                #print(parsed_req.dump_to_dict())

                with open(path+PARSED+'/'+fname[:-4]+'.json', 'w') as parsed_test_file:
                    parsed_dict = parsed_req.dump_to_dict()
                    del parsed_dict['time']
                    parsed_test_file.write(json.dumps(parsed_dict))





if __name__ == "__main__":
    train_test_parsed_trees()
    

    # As soon as we neet this part for ParsingDecisionTree  check, comment
    """ 
    load_settings_mongo(MONGO, 'settings', 'default-0')
    manager = TxManager() # manager to load transactions


    pdtree_manager = RequestParsingDecisionTreeManager()

    current_webapp_dtree = pdtree_manager.get_webapp_tree(uuid.UUID(webapp_id))
    print("NEW", current_webapp_dtree.dump_to_dict())
    """

    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    tests = sorted([
        {"fname": fname, "num": int(os.path.basename(fname).split('.')[0])}
        for fname in glob.glob("new_samples/aws/train/*.txt")
    ], key=lambda test: test["num"])


    for test in tests:
        #all_ok = True
        test_fname = test["fname"]
        #print ("test", test_fname, "..."),
        
        with open(test_fname) as request_file:
            request = request_file.read()
        
        #with open("new_samples/parsed/%d.json" % test["num"], 'w') as parsed_test_file:
        parsed_req = processing(request)      
            
            #manager.store('ParsedHttpRequest', parsed_req.dump_to_dict())
            #parse_tree = RequestParseTree.parse_request(parsed_req, current_webapp_dtree)[0]
            #manager.store("RequestParseTree", parse_tree.dump_to_dict())
            
            #print(parse_tree.dump_to_dict())
        

        print(parsed_req.dump_to_dict())
            #parsed_test_file.write(json.dumps(parsed))

        
        #print ("END")