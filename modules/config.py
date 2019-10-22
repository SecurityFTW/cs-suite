#!/usr/bin/env python
import ConfigParser
import argparse

def check_run_time_argument(*args):
    list_of = args[0].__dict__
    list_of_run_time_argumnet = []
    for key, value in list_of.items():
       if value != None and value != False:
            list_of_run_time_argumnet.append(key)
    return list_of_run_time_argumnet

def read_config_file(env,file_name):
    config = ConfigParser.ConfigParser()
    config.read('config.ini')
    print(config.get(env,file_name))

def default_config(args): 
    #list_of_run_time = check_run_time_argument(*args)
    if args.environment == None:
        if read_config_file('default','env') == None:
            exit(0)
        if read_config_file('default','env') == 'aws':
            aws_config_file(args)
        if read_config_file('default','env') == 'azure':
            azure_file_config(args)
        if read_config_file('default','env') == 'gcp':
            gcp_config_file(args)

    if args.environment == 'aws':
        aws_config_file(args)
    if args.environment == 'gcp':
        gcp_config_file(args)
    if args.environment == 'azure':
        azure_file_config(args)


def aws_config_file(args):

    print("aws")
def gcp_config_file(args):
    print("gcp")
def azure_file_config(args):
    print("azure")


# def check_condition(args, ):
#         if args.environment == 'aws':
#             aws_config_file(args)
#         if args.environment == 'gcp':
#             gcp_config_file(args)
#         if args.environment == 'azure':
#             azure_file_config(args)
