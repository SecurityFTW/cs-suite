#!/usr/bin/env python
import ConfigParser
import argparse
from argparse import Namespace as Namespace
from pprint import pprint

def check_run_time_argument(args):
    list_of = vars(args)
    list_of_run_time_argumnet = []
    list_of_values = []
    for key, value in list_of.items():
       if value != None and value != False:
            list_of_run_time_argumnet.append(key)
            list_of_values.append(value)
    data = dict(zip(list_of_run_time_argumnet, list_of_values))
    return data

def read_config_file(section):
    list_of_keys = []
    list_of_values = []
    config = ConfigParser.ConfigParser()
    config.read('config.ini')
    tmp = config.items(section)
    for i in range(len(tmp)):
        list_of_keys.append(tmp[i][0])
        list_of_values.append(tmp[i][1])
    data = dict(zip(list_of_keys, list_of_values))
    return data

def get_environment():
    config = ConfigParser.ConfigParser()
    config.read('config.ini')
    value = config.get('default','environment')
    if value == 'None':
        value = None
    return value

def correct_false_values(args):
    args = vars(args)
    for key in args:
        if args[key] == 'None':
            args[key] = None
        if args[key] == 'False':
            args[key] = False
        if args[key] == 'True':
            args[key] = True
    args = Namespace(**args)
    return args
    
def property_or_argument_read(args):
    sections = ['default']
    if args.environment != None:
        sections.append(args.environment)
    elif get_environment() != None :
        sections.append(get_environment())
    else:
        print("No environment defined to run audit upon!")
        exit(0)
    data_from_cli = check_run_time_argument(args)
    config_file_data = {}
    for section in sections:
        config_file_data[section] = read_config_file(section)
    args = put_config_file_data(sections,config_file_data,args)
    args = put_runtime_arguments(data_from_cli,args)
    args = correct_false_values(args)
    return args

def put_runtime_arguments(data,args):
    args = vars(args)
    for single_data in data:
        args[single_data] = data[single_data]
    args = Namespace(**args)
    return args

def put_config_file_data(sections,config_file_data,args):
    args = vars(args)
    for section in sections:
        for i in config_file_data[section]:
            args[i] = config_file_data[section][i]
    args = Namespace(**args)
    return args
