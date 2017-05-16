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
    
    
    for test in tests[15:16]:
        print test
        
    
        moduleName = test
        hostname = "jesper-Aspire-E5-571"
        
        resultPath = "/home/jesper/result/"
        
        finalString += "### " + moduleName + " ###\n\n"
        
        file = open(resultPath + moduleName + "_info/" + hostname + ".log", "r")

        audit_module = getattr(rjParser, moduleName)
        dict = audit_module.read(file)        
        returnString = audit_module.evaluate(dict)
        
        finalString += str(returnString)        
        finalString += "\n##################\n\n\n\n\n"
        
       # output.write(str(returnString) + "\n##################\n\n\n\n\n")
    
    output.write(finalString)
    
    print "END OF PROGRAM"

    pass