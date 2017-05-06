'''
Created on May 3, 2017

@author: jesper
'''

import itertools


def read_cron_at_info(file):
    
    values = dict()
    files = ["null", "/etc/cron.allow", "/etc/at.allow"]
    fileIndex = 0
  
    while True:
        nextLine = file.readline()
        if (nextLine == ""):
            if (file.read() == ""):
                break
        
        elif "No such file or directory" in nextLine:
            fileIndex = fileIndex + 1
            values[files[fileIndex]] = "No such file or directory"
        
        elif "total" in nextLine:
            fileIndex = fileIndex + 1
        
        else: 
            innerValues = nextLine.split()
            values[files[fileIndex]+innerValues[8]] = innerValues
            
    return values

def evaluate_cron_at_info(dict):
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
    values = dict()
    notSetupString = "No crontab has been set up for the following: \n"
    
    next_line = file.readline()[:-1]
    while (next_line): 
        notSetupString += (next_line.split(" ")[3]);
        next_line = file.readline()[:-1]    
    return values

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
        values[innerValues[5]] = innerValues

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
        nLineSplit = nextLine.split()
        
        for i in range(1, len(nLineSplit)):
            nLineSSPlit = nLineSplit[i].split("=")

            innerValues[nLineSSPlit[0]] = nLineSSPlit[1]
            
        values[nLineSplit[0]] = innerValues
    
    return values

def evaluate_encrypted_disk_info(dict):
    
    returnString = ""
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
        if (innerValues and innerValues[0] == "Chain"):
            chain = innerValues[1]
            policy = innerValues[3].split(")")[0]
            values[chain] = policy
            
    return values

def evaluate_firewall_info(dict):
    returnString = ""
    
    policy = 000
    
    if dict["INPUT"] == "ACCEPT": 
        print "InputAcc" 
        policy = policy + 100
        
    if dict["FORWARD"] == "ACCEPT":
        print "ForwardAcc"
        policy = policy + 10
        
    if dict["OUTPUT"] == "ACCEPT":
        print "OutputAcc"
        policy = policy + 1
        
    
    if (policy >= 100):
        returnString = returnString + ("Warning: There is no firewall set up for incoming traffic.\n");
        policy = policy - 100
        
    if (policy >= 10):
        returnString = returnString + ("Warning: There is no firewall set up for forwarding traffic.\n");
        policy = policy - 10
        
    if (policy >= 1):
        returnString = returnString + ("Warning: There is no firewall set up for outgoing traffic.\n");
        policy = policy - 1

    return returnString

def read_groups_info(file):
    
    values = dict()
    
    next_line = file.readline()[:-1]
    
    while next_line:
        inner_values = next_line.split(":")
        values[inner_values[0]] = inner_values
        next_line = file.readline()[:-1]

        
    return values
        
        
def evaluate_groups_info(dict):
    
    returnString = ""
    return returnString


def read_lastlog_info(file):
    value = dict()
    
    return value

def evaluate_lastlog_info(dict):
    returnString = ""
    return returnString
    

def read_modprobe_info(file):
    values = dict()
    modprobes = ""
    
    while True:
        nextLine = file.readline()    
        if ("Module" in nextLine): break
        modprobes = modprobes + "%" + nextLine
    
    values["modprobe.d"] = modprobes
    
    while True:
        nextLine = file.readline()
        if (nextLine == ""): break
        innerValues = nextLine.split()

        values[innerValues[0]] = innerValues
        
    return values

def evaluate_modprobe_info(dict):
    pass

def read_networkvolume_info(file):
    values = dict()
    
    while True:
        nextLine = file.readline()
        if ("#" in nextLine): break
        innerValues = nextLine.split()
        values[innerValues[2]] = innerValues
        
    while True:
        nextLine = file.readline()
        if ("#" in nextLine): continue
        if (nextLine == ""): break
        innerValues = nextLine.split()
        values[innerValues[1]] = innerValues
        
    return values

def evaluate_networkvolume_info(dict):
    pass

def read_open_connections_info(file):
    values = dict()
    
    file.readline() #Skip first line
    next_line = file.readline()
    print not "COMMAND" in next_line
    while (next_line and not "COMMAND" in next_line):
        innerValues = next_line.split()
        values[innerValues[4]] = innerValues
        next_line = file.readline()
        
    while (next_line):
        innerValues = next_line.split()
        #Unsure what should be the key..
        values[innerValues[0] + "#" + innerValues[3]] = innerValues
        next_line = file.readline()

    return values

def evaluate_open_connections_info(dict):
    returnString = ""
    
    return returnString

def read_passwdpolicy_info(file):
    values = dict()
    
    next_line = file.readline()
    
    while(next_line):

        if "#" not in next_line and not next_line.isspace():

            key_value = next_line.split()
            values[key_value[0]] = key_value[1]
            
        next_line = file.readline()
        
    return values

def evaluate_passwdpolicy_info(dict):

        
    returnString = "";

    if dict["ENCRYPT_METHOD"] == "MD5":
        returnString = (returnString + "Your currently password encrypting method is MD5. " + 
                        "\nYou should consider changing the encrypting method to SHA256 or SHA516.")
        
        
    if dict["PASS_MIN_DAYS"] > '0': 
        returnString = (returnString + "Warning: You have to wait " + dict["PASS_MIN_DAYS"] + 
                        " days to change password, this can be a security risk in case of accidental password change.")



    return returnString;
    
def read_processes_info(file):
    
    values = dict()
    
    next_line = file.readline()
    
    while (next_line):
        splitted_line = next_line.split()
        innerValues = ["" for i in range(11)] # Init the list with empty strings
        for i in range (0, 10):
            innerValues[i] = splitted_line[i]
        for i in range (10, len(splitted_line)):
            innerValues[10] = str(innerValues[10]) + splitted_line[i] + " "
        next_line = file.readline()
        
        values[innerValues[1]] = innerValues

        
    pass

def evaluate_processes_info(dict):
    returnString = ""
    
    return returnString

def read_samba_info(file):
    
    values = dict()
    
    
    next_line = file.readline()
    
    while (next_line):
        if "No such file or directory" in next_line:
            
            values["/etc/samba/smb.conf"] = "No such file or directory"
            return values
        
        if "#" in next_line or "" in next_line:
            next_line = file.readline()
            continue
        
        if "[" in next_line:
            level = next_line
            continue
        
        next_values = next_line.split("=")
        
        values[next_values[0]] = [next_values[1], level]
        
        next_line = file.readline()
    
    return values

def evaluate_samba_info(dict):
    returnString = ""
    
    return returnString


def read_sshd_info(file):
    values = dict()
    
    next_line = file.readline()
    
    while (next_line):
        if "No such file or directory" in next_line:
            values["/etc/ssh/sshd_config"] = "No such file or directory"
            
        if "#" not in next_line:
            next_values = next_line.split()
            values[next_values[0]] = next_values[1]
        
        next_line = file.readline()
    
    return values

def evaluate_sshd_info(dict):
    returnString = ""
    return returnString

def read_startup_info(file):
    values = dict()
    
    file.readline() #Skip first line (/etc/init.d)
    file.readline() #Skip second line (total 216) //maybe use?
    
    next_line = file.readline()
    
    while (next_line):
        next_values = next_line.split()
        values[next_values[8]] = next_values
        next_line = file.readline()
        
    
    return values
    


def evaluate_startup_info(dict):
    returnString = ""
    return returnString

def read_sudoers_info(file):
    
    values = dict()
    username = ""
    hosts = ""
    run_as_users = ""
    run_as_groups = ""
    command = ""
    
    
    next_line = file.readline()
    
    while (next_line):
        group = False

        
        if "#" in next_line or "Defaults" in next_line or next_line.isspace(): 
            next_line = file.readline()
            continue
        
        inner_values = next_line.split()
        username = inner_values[0]
        command = inner_values[2]
        
        inner_values = inner_values[1].split("=")
        
        hosts = inner_values[0]
        
        inner_values = inner_values[1].split(":")

        
        
        if (len(inner_values) > 1):
            run_as_users = inner_values[0][1:]
            run_as_groups = inner_values[1][:-1]
        else:
            run_as_users = inner_values[0][-1:-1]


        
        next_line = file.readline()

            
        
        
        
    
    return values

def evaluate_sudoers_info(dict):
    returnString = ""
    return returnString


def read_suid_files_info(file):
    values = dict()
    
    next_line = file.readline()
    
    while (next_line):
        values[next_line] = next_line
        next_line = file.readline()
        
        
    
    return values

def evaluate_suid_files_info(dict):
    returnString = ""
    return returnString

    

def read_system_info(file):
    
    values = dict()
    
    next_line = file.readline()
    
    while (next_line):
        values[next_line] = next_line
        next_line = file.readline()
        
    return values

def evaluate_system_info(dict):
    returnString = ""
    return returnString


def read_users_info(file):
    values = dict()
    
    next_line = file.readline()
    
    while (next_line):    
        inner_values = next_line.split(":")
        
        values[inner_values[0]] = inner_values
        
        next_line = file.readline()
    
    
    return values

def evaluate_users_info(dict):
    returnString = ""
    
    
    for key in dict:
        
        risks = [False, False, False]

        value = dict[key]
        if value[2] == "0" and not key == "root":
            returnString = returnString + "User " + "'" + key + "'" + " has super user rights\n"
            risks[0] = True
            
        if value[1] == "!":
            returnString = returnString = "User " + "'" + key + "'" + " is stored in /etc/security/passwd and is not encrypted\n"
            risks[1] = True
            
        elif value[1] == "*":
            returnString = returnString + "User " + "'" + key + "'" + " has an invalid password\n"
            risks[2] = True
            
        
        if risks[0]:
            returnString += "\nYou should change the users' priviliges"
        
        if risks[1]:
            returnString += "\nYou should encrypt the users' password"
        
        if risks[2]:
            returnString += "\nYou should change users' password to a valid one"
                  
    return returnString
    


def readwords(mfile):
    byte_stream = itertools.groupby(
        itertools.takewhile(lambda c: bool(c),
            map(mfile.read,
                itertools.repeat(1))), str.isspace)

    return ("".join(group) for pred, group in byte_stream if not pred)