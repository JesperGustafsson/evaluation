#!/usr/bin/python
'''
Created on May 3, 2017

@author: jesper
'''


from Parsers.RJParser import *
from Parsers import RJParser as rjParser

if __name__ == '__main__':
    
    finalString = ""
    output = open("Output.txt", "w")
    
    tests = [i[:-1] for i in open("RJTests")]
    print tests
    
    
    for test in tests[:]:
        print test
        
    
        moduleName = test
        hostname = "jesper-Aspire-E5-571"
        
        resultPath = "/home/jesper/Documents/remote_job_linux_osx-master-d98598cf1ea7ba905e77c62efb3b52a4bcacf366/result/"
        
        finalString += "### " + moduleName + " ###\n\n"
        
        file = open(resultPath + moduleName + "_info/" + hostname + ".log", "r")
        method_to_call = getattr(rjParser, "read_" + moduleName + "_info")
        dict = method_to_call(file)
        
        print "######################\n######################"
        method_to_call = getattr(rjParser, "evaluate_" + moduleName + "_info")
        returnString = method_to_call(dict)
        
        finalString += str(returnString)
        
        finalString += "\n##################\n\n\n\n\n"
        
       # output.write(str(returnString) + "\n##################\n\n\n\n\n")
    
    output.write(finalString)
    pass