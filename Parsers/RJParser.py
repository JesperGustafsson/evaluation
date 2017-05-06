'''
Created on May 3, 2017

@author: jesper
'''

import itertools


def read_cron_at_info(file):
    print("RJParser/read_cron_at_info")
    
    values = dict()
    files = ["null", "/etc/cron.allow", "/etc/at.allow"]
    fileIndex = 0
  
    while True:
        nextLine = file.readline()
        print "[" + nextLine + "]"
        if (nextLine == ""):
            print "first if"
            if (file.read() == ""):
                break
        
        elif "No such file or directory" in nextLine:
            print "if"
            fileIndex = fileIndex + 1
            values[files[fileIndex]] = "No such file or directory"
        
        elif "total" in nextLine:
            print "elif"
            fileIndex = fileIndex + 1
        
        else: 
            print "else"
            innerValues = nextLine.split()
            values[files[fileIndex]+innerValues[8]] = innerValues
            
    return values

def evaluate_cron_at_info(dict):
    print "RJParser/evaluate_cron_at_info"
    returnString = ""
    
    for key, value in dict.items():
        if ("No such file or directory" in value):
            returnString = returnString + "No " + key + " has been set up.\n"
        
        else:
            permissions = value[0].split("")
            if (permissions[8] == "w"):
                returnString = returnString + ("\n Warning! Any user can alter the cron for " + key
                 + "\n It would be a good idea to change permissions so that only the owner and group can write to this file");

    return returnString


def read_crontab_info(file):
    print "RJParser/read_crontab"
    values = dict()
    notSetupString = "No crontab has been set up for the following: \n"
    
    while True: 
        nextLine = file.readline()
        if (nextLine.startswith("#") or nextLine == ""):
            print ("if")
        else:
            notSetupString = notSetupString + (nextLine.split(" ")[3]);
            
        print notSetupString
    pass

def evaluate_crontab_info(dict):
    """Already implemented in the read method"""
    pass

def read_diskvolume_info(file):
    values = dict()
    file.readline() #Skip first line
    
    while True:
        #[Filesystem][Size][Used][Avail][Use%][Mounted on]
        nextLine = file.readline()
        
        if (nextLine == ""): 
            break
        
        innerValues = nextLine.split()
        print innerValues[5]
        values[innerValues[5]] = innerValues

    print "End of read_diskvolume"
    pass

def evaluate_diskvolume_info(dict):
    pass

def read_encrypted_disk_info(file):
    values = dict()

    while True:
        innerValues = dict()
        
        nextLine = file.readline()
        if (nextLine == ""):
            break
        print nextLine
        nLineSplit = nextLine.split()
        print nLineSplit
        
        for i in range(1, len(nLineSplit)):
            print "i: " + str(i)
            print "SPLINTOR: " + nLineSplit[i]
            nLineSSPlit = nLineSplit[i].split("=")
            print "SPLINTORED: " 
            print nLineSSPlit
            innerValues[nLineSSPlit[0]] = nLineSSPlit[1]
            
        values[nLineSplit[0]] = innerValues
    
    return values

def evaluate_encrypted_disk_info(dict):
    returnString = ""
    
    for key in dict:
        print "key: " + key
        for keykey in dict[key]:
            print "keykey: " + keykey
            print "value?: " + dict[key][keykey]
    
    return returnString

def read_environment_info(file):
    values = dict()
    while True:
        nextLine = file.readline()
        if (nextLine == ""):
            break
        
        innerValues = nextLine.split("=")
        if (innerValues[0] == "LS_COLORS"): #Hard to parse and don't think it has anythign to do with security risks
            continue
        
        values[innerValues[0]] = innerValues[1]
        
        
        
        
    return values

def evaluate_environment_info(dict):
    returnString = ""
    
    
    return returnString

def read_firewall_info(file):
    values = dict()
    
    while True:
        nextLine = file.readline()
        if (nextLine == ""): break
        innerValues = nextLine.split()
        print innerValues
        if (innerValues and innerValues[0] == "Chain"):
            chain = innerValues[1]
            policy = innerValues[3].split(")")[0]
            print chain
            print policy
            values[chain] = policy
            
    return values

def evaluate_firewall_info(dict):
    returnString = ""
    
    policy = 000
    print policy
    
    if dict["INPUT"] == "ACCEPT": 
        print "InputAcc" 
        policy = policy + 100
        print policy
        
    if dict["FORWARD"] == "ACCEPT":
        print "ForwardAcc"
        policy = policy + 10
        print policy

        
    if dict["OUTPUT"] == "ACCEPT":
        print "OutputAcc"
        policy = policy + 1
        print policy
        
    print "final policy: " + str(policy)
    
    if (policy >= 100):
        returnString = returnString + ("Warning: There is no firewall set up for incoming traffic.\n");
        policy = policy - 100
        
    if (policy >= 10):
        returnString = returnString + ("Warning: There is no firewall set up for forwarding traffic.\n");
        policy = policy - 10
        
    if (policy >= 1):
        returnString = returnString + ("Warning: There is no firewall set up for outgoing traffic.\n");
        policy = policy - 1
        
    print "final2 policy: " + str(policy) + "####\n####\n####"
    
    print returnString
    print dict
    return returnString

def read_groups_info(file):
    
    values = dict()
    
    while True:
        nextLine = file.readline()
        innerValues = nextLine.split(":")
        print innerValues
        values[innerValues[0]] = innerValues
        
    return values
        
        
def evaluate_groups_info(dict):
    
    returnString = ""
    return returnString


def read_lastlog_info(file):
    pass

def evaluate_lastlog_info(dict):
    pass

def read_modprobe_info(file):
    pass

def evaluate_modprobe_info(dict):
    pass

def test2(file):
    print("RJParser/test2")
    print file.read()
    pass


def readwords(mfile):
    byte_stream = itertools.groupby(
        itertools.takewhile(lambda c: bool(c),
            map(mfile.read,
                itertools.repeat(1))), str.isspace)

    return ("".join(group) for pred, group in byte_stream if not pred)