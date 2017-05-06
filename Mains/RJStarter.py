'''
Created on May 3, 2017

@author: jesper
'''

import Parsers
from Parsers.RJParser import *
from Parsers import RJParser as rjParser

if __name__ == '__main__':
    
    moduleName = 'users'
    hostname = "jesper-Aspire-E5-571"
    
    resultPath = "/home/jesper/Documents/remote_job_linux_osx-master-d98598cf1ea7ba905e77c62efb3b52a4bcacf366/result/"
    

    
    
    file = open(resultPath + moduleName + "_info/" + hostname + ".log", "r")
    method_to_call = getattr(rjParser, "read_" + moduleName + "_info")
    dict = method_to_call(file)
    
    print "######################\n######################"
    method_to_call = getattr(rjParser, "evaluate_" + moduleName + "_info")
    returnString = method_to_call(dict)
    
    print returnString
    
    
    pass
