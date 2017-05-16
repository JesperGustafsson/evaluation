'''
Created on May 16, 2017

@author: jesper
'''

def read(file):
    values = dict()
    
    next_line = file.readline()
    
    while next_line:
        if "WARNING:" in next_line:
            warning = next_line.replace("WARNING: ", "")[:-1]
            if values.has_key("warnings"):
                values["warnings"].append(warning)
            else:
                values["warnings"] = [warning]
    
        next_line = file.readline()
    return values


def evaluate(info):
    
    returnString = ""
    
    
    if info.has_key("warnings"):
        returnString += "The unix audit has found the following warnings:\n\n"
        
        for warning in info["warnings"]:
            
            returnString += warning + "\n"
    
    
    return returnString