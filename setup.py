 #! /usr/bin/env python
from __future__ import print_function
import subprocess

def main():
    """ main function """
    try:
        print ("Installing dependencies...")
        subprocess.call(['sudo', 'pip', 'install', '-r', 'requirements.txt'])
        print ("Installing AWS CLI") # WINDOWS HAS NO SUDO 
        subprocess.call(['sudo', 'pip', 'install', 'awscli', '--ignore-installed', 'six'])
        print ("Please enter your AWS credetionals")
        subprocess.call(['aws', 'configure'])
    except:
        print ("FAILED in one of the steps")

if __name__ == '__main__':
    main()
