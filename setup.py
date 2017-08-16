 #! /usr/bin/env python
from __future__ import print_function
import subprocess

def main():
    """ main function """
    try:
        print ("installing requirements for Scout2")
        subprocess.call(['sudo', 'pip', 'install', '-r', './tools/Scout2/requirements.txt'])
        print ("Setting up Scout2")
        subprocess.call(['python', 'setup.py', 'install'], cwd='tools/Scout2')
        print ("Installing other requirements")
        subprocess.call(['sudo', 'pip', 'install', '-r', './scripts/requirements.txt'])
        print ("Setting up aws-security-test")
        subprocess.call(['python', 'setup.py', 'install'], cwd='tools/aws-security-test')
        print ("Installing AWS CLI") # WINDOWS HAS NO SUDO 
        subprocess.call(['sudo', 'pip', 'install', 'awscli', '--ignore-installed', 'six'])
        print ("Please enter your AWS credetionals")
        subprocess.call(['aws', 'configure'])
    except:
        print ("FAILED in one of the steps")

if __name__ == '__main__':
    main()
