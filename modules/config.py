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
    # print(data)
    return data



def getEnvironment():
    config = ConfigParser.ConfigParser()
    config.read('config.ini')
    value = config.get('default','environment')
    if value == 'None':
        value = None
    return value



def onefunc():
    pass



def test(args):
    
    sections = ['default']
    if args.environment != None:
        sections.append(args.environment)
    elif getEnvironment() != None :
        sections.append(getEnvironment())
    else:
        print("No environment defined to run audit upon!")
        exit(0)
    data_from_cli = check_run_time_argument(args)
    config_file_data = {}
    for section in sections:
        config_file_data[section] = read_config_file(section)
    args = putConfigFileData(sections,config_file_data,args,data_from_cli)
    args = putRuntimeArguments(data_from_cli,args)
    return args


def putRuntimeArguments(data,args):
    args = vars(args)
    for single_data in data:
        args[single_data] = data[single_data]
    args = Namespace(**args)
    return args


def putConfigFileData(sections,config_file_data,args,data_from_cli):
    args = vars(args)
    for section in sections:
        for i in config_file_data[section]:
            args[i] = config_file_data[section][i]
    args = Namespace(**args)
    return args
