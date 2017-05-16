#!/usr/bin/python
'''
Created on May 3, 2017

@author: jesper
'''

from Parsers.RJParser import *
from Parsers import RJParser as rjParser
from Parsers import LynisParser as lynisParser
from Parsers import UnixParser as unixParser

if __name__ == '__main__':


    finalString = ""
    rjString = ""
    lynisString = ""
    unixString = ""
    output = open("Output.txt", "w")
    
    tests = [i[:-1] for i in open("RJTests")]
    print tests
    
    # RJParser
    for test in tests[:]:
        print test
        
    
        moduleName = test
        hostname = "jesper-Aspire-E5-571"
        
        resultPath = "/home/jesper/result/"
        
        rjString += "### " + moduleName + " ###\n\n"
        
        file = open(resultPath + moduleName + "_info/" + hostname + ".log", "r")

        audit_module = getattr(rjParser, moduleName)
        dict = audit_module.read(file)        
        returnString = audit_module.evaluate(dict)
        
        rjString += str(returnString)        
        rjString += "\n##################\n\n\n\n\n"
        
       # output.write(str(returnString) + "\n##################\n\n\n\n\n")
    
    finalString += "The remote-job has found the following issues:\n\n"
    finalString += rjString + "\n\n##############################\n##############################\n\n"
    

    print "END OF RJParser"
    
    #Lynis
    
    lynis_log = "/home/jesper/lynis/lynis.log"

    file = open(lynis_log, "r")
    
    dict = lynisParser.read(file)
    lynisString = lynisParser.evaluate(dict)

    
    print "END OF LynisParser"
    finalString += lynisString
    finalString += "\n\n##############################\n##############################\n\n"


    unix_log = "/home/jesper/unix/outputdetailed.txt" #outputdetailed/outputstandard
    print "UNIX START"
    file = open(unix_log, "r")
    
    dict = unixParser.read(file)
    unixString = unixParser.evaluate(dict)
    
    
    print "UNIX END"
    finalString += unixString
    
    output.write(finalString)

    pass