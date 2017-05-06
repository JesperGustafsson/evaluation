#!/usr/bin/python
'''
Created on May 3, 2017

@author: jesper
'''


from Parsers.RJParser import *
from Parsers import RJParser as rjParser

if __name__ == '__main__':
    
    moduleName = 'users'
    hostname = "jesper-Aspire-E5-571"
    
    resultPath = "/home/stoff/TrueSec/result/"

    
    
    file = open(resultPath + moduleName + "_info/" + hostname + ".log", "r")
    method_to_call = getattr(RJParser, "read_" + moduleName + "_info")
    dict = method_to_call(file)
    
    print "######################\n######################"
    method_to_call = getattr(RJParser, "evaluate_" + moduleName + "_info")
    returnString = method_to_call(dict)
    
    print returnString
    
    
    pass