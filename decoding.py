#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.append('/waf/')
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

ALL_DECODERS_CLASSES = [#AutoBoundaryMultipartParser, # input: node, output: node & 
                        Base64DetectorDecoder,
                        Base32DetectorDecoder,
                        Base16DetectorDecoder,
                        ##CookieHeaderParser, this breaks everything => visiraet error
                        CSVDetectorParser,# TODO: check that it delete digits and get space and create ticket
                        DeflateUnpacker,
                        DSVDetectorParser,
                        FormUrlencodeParser,
                        GraphQLDetectorParser,
                        GzipUnpacker,
                        #HTMLDetectorParser,TODO: See #2074
                        JSONPDetectorParser,
                        JSONDetectorParser,
                        JsonRPCDetectorParser,
                        #####MultipartFormDataParser,#TODO: add this parser
                        #SetCookieHeaderParser,#TODO: check that it delete digits and get space and create ticket
                        #SOAPDetectorParser,
                        #####StaticPrefixParser, doesn't work, don't need it
                        UrlParser,
                        XMLDetectorParser,
                        #XMLRPCDetectorParser,
                        YAMLDetectorParser]

DECODERS_SPEC_SET = set([JSONPDetectorParser, Base64DetectorDecoder])


def check_info():
    for i, name in enumerate(ALL_DECODERS_CLASSES):
        decoder = name()
        print(i+1, type(decoder))
        try:
            print(decoder.info)
        except:
            print("No info in decoder", decoder)


def walk(tree, path=[]):
    for key, subtree in tree.children:
        if subtree.is_leaf():
            print(path + [key], subtree.value)
        else:
            walk(subtree, path + [key])
        

def count_decoder(token):
    """
    Подаем на вход token - string value
    Возвращаем словарь из элементов вида {Класс декодера: [(1/0 (применился декодер или нет)), (дерево, если применился)]}
    """

    decoder_applic = {}
    for i, name in enumerate(ALL_DECODERS_CLASSES):
        decoder_applic[name] = [0, None] # исходно, декдоер не применим, возвращается None
        decoder = name()
        try:
            decoded_node = decoder.decode(token) # если получается расшифровать, то круто
            #print("Decoded with", name, " result:", decoded_node, "prob", decoder.check(token))
            if decoded_node is None:
                decoder_applic[name] = [0, None] # тут срабоатл check_decoder и выдал False
            elif isinstance(decoded_node, ParseTreeNode):
                children = list(decoded_node.children)
                if len(children) != 0:
                    decoder_applic[name] = [1, decoded_node]
                else:
                    decoded_node = decoded_node.strvalue
                    new_tree = ParseTreeNode(ParseTreeNodeTypes.OBJECT, '')
                    new_tree._append_child('decoded', decoded_node)

                    decoder_applic[name] = [1, new_tree]
                    #print("STATISTIC", decoder_applic)
            else: # для encodings, которые выдают ответ в string
                new_tree = ParseTreeNode(ParseTreeNodeTypes.OBJECT, '')
                new_tree._append_child('decoded', decoded_node)

                decoder_applic[name] = [1, new_tree]
        except:
            #print("Non-applicable decoder", name)
            decoder_applic[name] = [0, None]

    return decoder_applic


if __name__ == "__main__":

    print(len(ALL_DECODERS_CLASSES))
    #check_info()
    test = "json=%7B%22dishes%22%3A%5B%7B%22number%22%3A0%2C%22dishId%22%3A336%2C%22dishKindId%22%3A518%2C%22totalDiscountAmount%22%3A0%2C%22qty%22%3A1%2C%22price%22%3A245%2C%22clearAmount%22%3A245%2C%22toppings%22%3A%5B%5D%2C%22forPoints%22%3Afalse%7D%2C%7B%22number%22%3A1%2C%22dishId%22%3A72%2C%22dishKindId%22%3A108%2C%22totalDiscountAmount%22%3A0%2C%22qty%22%3A1%2C%22price%22%3A150%2C%22clearAmount%22%3A150%2C%22toppings%22%3A%5B%5D%2C%22forPoints%22%3Afalse%7D%2C%7B%22number%22%3A2%2C%22dishId%22%3A389%2C%22dishKindId%22%3A596%2C%22totalDiscountAmount%22%3A0%2C%22qty%22%3A1%2C%22price%22%3A85%2C%22clearAmount%22%3A85%2C%22toppings%22%3A%5B%5D%2C%22forPoints%22%3Afalse%7D%5D%2C%22dishSets%22%3A%5B%5D%2C%22prizeId%22%3Anull%2C%22currentPrize%22%3Anull%2C%22promocode%22%3A%22%22%2C%22promocodeId%22%3Anull%2C%22promoactionId%22%3Anull%2C%22promoactionName%22%3Anull%2C%22prizeCount%22%3A1%2C%22customerId%22%3A0%2C%22phone%22%3A%22%22%2C%22customerName%22%3A%22%22%2C%22payMethodId%22%3A1%2C%22personsCount%22%3A0%2C%22postponed%22%3Afalse%2C%22timePlan%22%3Anull%2C%22changeAmount%22%3A2000%2C%22totalClearAmount%22%3A480%2C%22discountPercentOnOrder%22%3A0%2C%22address%22%3A%7B%22id%22%3A0%2C%22cityId%22%3Anull%2C%22addressText%22%3Anull%2C%22longitude%22%3Anull%2C%22latitude%22%3Anull%7D%2C%22remark%22%3A%22%22%2C%22costDelivery%22%3A0%7D\n"

    decoder_dict = count_decoder(test)
    #print(decoder_dict)

    for key in decoder_dict.keys():
        print(key, decoder_dict[key])

