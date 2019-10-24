#!/usr/bin/env python
import ConfigParser
import argparse
import readconfigfile
from argparse import Namespace as Namespace
import logging
import os

def check_run_time_argument(args_dict):
    list_of_run_time_keys = []
    list_of_run_time_values = []
    for key, value in args_dict.items():
       if value != None and value != False:
            list_of_run_time_keys.append(key)
            list_of_run_time_values.append(value)
    data_dict = dict(zip(list_of_run_time_keys, list_of_run_time_values))
    return data_dict

def get_environment():
    config = ConfigParser.ConfigParser()
    config.read('config.ini')
    env_value_at_config_file = config.get('default','environment')
    if env_value_at_config_file == 'None':
        env_value_at_config_file = None
    return env_value_at_config_file

def put_env_variables(args_dict):
    try:
        print(os.environ['password'])
        list_of_env_variables = ['password','azure_pass']
        for env_variable in list_of_env_variables:
            if os.environ[env_variable] != None and os.environ[env_variable] != 'None' :
                args_dict[env_variable] = os.environ[env_variable]
        return args_dict 
    except Exception as identifier:
        logging.exception(identifier)

def update_args(args_namespace):
    args_dict = vars(args_namespace)
    sections = ['default']
    if args_namespace.environment != None:
        sections.append(args_namespace.environment)
    elif get_environment() != None :
        sections.append(get_environment())
    else:
        print("No environment defined to run audit upon!")
        exit(0)
    data_from_cli = check_run_time_argument(args_dict)
    config_file_data = {}
    for section in sections:
        config_file_data[section] = readconfigfile.get_section_data(section)
    args_dict = put_config_file_data(sections,config_file_data,args_dict)
    args_dict = put_runtime_arguments(data_from_cli,args_dict)
    args_dict = put_env_variables(args_dict)    
    args_namespace = Namespace(**args_dict)
    return args_namespace

def put_runtime_arguments(data,args_dict):
    for single_data in data:
        args_dict[single_data] = data[single_data]
    return args_dict

def put_config_file_data(sections,config_file_data,args_dict):
    for section in sections:
        for i in config_file_data[section]:
            args_dict[i] = config_file_data[section][i]
    return args_dict