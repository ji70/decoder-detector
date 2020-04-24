import unittest
import uuid
import functools
from copy import deepcopy
import sys
#sys.path.append('/home/anna/Documents/Work/solidwall-analyzer/')
#exec('/home/anna/Documents/Work/solidwall-analyzer/data_objects/')
sys.path.append('/waf/')

import common
from data_objects.http import (
    ParsedHttpResponse,
    ParsedHttpRequest,
    RequestAction,
    RequestParseTree
)
from common.db.decision_tree import RequestParsingDecisionTreeManager, ResponseParsingDecisionTreeManager
 
from common.db.dumper import ManagerDumper, BatchManagerDumper
from common.settings import config
from mock import patch, MagicMock
from common.settings import load_settings_mongo
from common.db.http_transaction import TxManager

import os
import json
import glob
import difflib
import psycopg2
from datetime import datetime

from parse_headers import parse


if __name__ == "__main__":
    MONGO = "mongodb://waf:0d678fdb64062f178033@localhost/waf" # from /etc/default/solidwall-analyzer
    webapp_id='56d69c95-2cc0-4da5-92e3-b514f3681932' # current waf webapp_id
    load_settings_mongo(MONGO, 'settings', 'default-0')
    manager = TxManager() # manager to load transactions

    pdtree_manager = RequestParsingDecisionTreeManager()
    #default_webapp_dtree = pdtree_manager.get_webapp_tree(None)
    #print("DEFAULT", default_webapp_dtree.dump_to_dict())

    current_webapp_dtree = pdtree_manager.get_webapp_tree(uuid.UUID(webapp_id))
    print("NEW", current_webapp_dtree.dump_to_dict())


    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    tests = sorted([
        {"fname": fname, "num": int(os.path.basename(fname).split('.')[0])}
        for fname in glob.glob("new_samples/*.txt")
    ], key=lambda test: test["num"])

    for test in tests:
        #all_ok = True
        test_fname = test["fname"]
        #print ("test", test_fname, "..."),
        
        with open(test_fname) as request_file:
            request = request_file.read()
        
        with open("new_samples/parsed/%d.json" % test["num"], 'w') as parsed_test_file:
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
            #print(parsed_req)
            manager.store('ParsedHttpRequest', parsed_req.dump_to_dict())
            parse_tree = RequestParseTree.parse_request(parsed_req, current_webapp_dtree)[0]
            manager.store("RequestParseTree", parse_tree.dump_to_dict())
            #print(parse_tree.dump_to_dict())
            parsed_test_file.write(json.dumps(parsed))

        
        #print ("END")