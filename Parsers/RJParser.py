'''
Created on May 3, 2017

@author: jesper
'''

import itertools

class AuditModule():
    @staticmethod
    def read(file):
        pass
    @staticmethod
    def evaluate(dict):
        pass

class cron_at(AuditModule):   
    @staticmethod
    def read(file):        
        values = dict()
        files = ["null", "/etc/cron.allow", "/etc/at.allow"]
        fileIndex = 0
      
        next_line = file.readline()
        
        while next_line:
            if (next_line == ""):
                if (file.read() == ""):
                    break
            
            elif "No such file or directory" in next_line:
                fileIndex = fileIndex + 1
                values[files[fileIndex]] = "No such file or directory"
            
            elif "total" in next_line:
                fileIndex = fileIndex + 1
            
            else: 
                innerValues = next_line.split()
                values[files[fileIndex]+innerValues[8]] = innerValues
                
            next_line = file.readline()
                
        return values

    @staticmethod
    def evaluate(dict):
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

class crontab(AuditModule):
    @staticmethod
    def read(file):
        values = dict()
        notSetupString = "No crontab has been set up for the following: \n"
        
        next_line = file.readline()[:-1]
        while (next_line): 
            notSetupString += (next_line.split(" ")[3]);
            next_line = file.readline()[:-1]    
        return values

    @staticmethod
    def evaluate(dict):
        """Already implemented in the read method"""
        pass

class diskvolume(AuditModule):
    @staticmethod
    def read(file):
        values = dict()
        file.readline() #Skip first line
        
        while True:
            #[Filesystem][Size][Used][Avail][Use%][Mounted on]
            nextLine = file.readline()
            
            if (nextLine == ""): 
                break
            
            innerValues = nextLine.split()
            values[innerValues[5]] = innerValues

        return values

    @staticmethod
    def evaluate(dict):
        returnString = ""
        
        for key in dict:
            if dict[key][4][:-1] > 80:
                returnString += "The filesystem " + key + " is at " + dict[key][4] + " capacity."
            
        return returnString

class encrypted_disk(AuditModule):
    @staticmethod
    def read(file):
        values = dict()

        next_line = file.readline()
        while next_line:
            inner_values = dict()
            

            n_line_split = next_line.split()
            
            for i in range(1, len(n_line_split)):
                n_line_ssplit = n_line_split[i].split("=")

                inner_values[n_line_ssplit[0]] = n_line_ssplit[1]
                
            values[n_line_split[0]] = inner_values
            next_line = file.readline()

        
        return values

    @staticmethod
    def evaluate(dict0):
        returnString = ""
        uuid_dict = {}
        
        print dict
        
        for key in dict0:
            for key_key in dict0:
                if ("UUID" in key_key):
                    uuid_dict[dict0[key][key_key]].append(key)
                    
        
        for key in uuid_dict:
            if len(uuid_dict[key]) != len(set(uuid_dict[key])):
                returnString += "The UUID " + key + " is shared between the filesystems: " + set(uuid_dict[key]) 
                + "Because of the low chance of UUID duplication in proper generation it is possible this has been altered maliciously."
                
        return returnString

class environment(AuditModule):
    @staticmethod
    def read(file):
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

    @staticmethod
    def evaluate(info):
        print "WAOW"
        returnString = ""
        env_file = open("acceptable_env.txt", "r")
        env_dict = dict()
        
        next_line = env_file.readline()
        while next_line:
            print "[" + next_line + "]"
            if not("%" in next_line or next_line.isspace()):
                print "[" + next_line + "]"
                key = next_line.split("=")[0]
                values = next_line.split("=")[1].split("|")
                values[len(values) - 1] = values[len(values) - 1][:-1]
                env_dict[key] = values
            
            next_line = env_file.readline()
            
            
        print env_dict
        print info
        
        for key in env_dict:
            #check if key exists in customer file
            if info.has_key(key[1:]):
                #check if key is dangerous
                if key.startswith("^"):
                    returnString += "The environment key " + key 
                    + " is considered dangerous. Consider removing it\n"
            
                else:
                    customer_value = info[key[1:]]
                    values = env_dict[key]
                    
                    #check if value is dangerous
                    if "^" + customer_value in values:
                        returnString += "The value for the environment key " + key 
                        + "is considered dangerous. " + "Consider changing to " 
                        + [x for x in list if not x.startswith("^")] 
                        + "preferably" +[x for x in list if x.startswith("*") + "\n"]
                        
                    #check if value is not preferable
                    if "<" + customer_value in values:
                        returnString += "The value for the environment key " + key 
                        + "is not considered preferable. " + "Consider changing to " 
                        + [x for x in list if not x.startswith("<", "^")] 
                        + " preferably" +[x for x in list if x.startswith("*") + "\n"]  
                        
                    
            if (key.startswith("#")):
                returnString += "The environment key " + key + " could not be found. It is considered important.\n"

        return returnString

class firewall(AuditModule):
    @staticmethod
    def read(file):
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
    @staticmethod
    def evaluate(dict):
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

class groups(AuditModule):
    @staticmethod        
    def read(file):
        
        values = dict()
        
        next_line = file.readline()[:-1]
        
        while next_line:
            inner_values = next_line.split(":")
            values[inner_values[0]] = inner_values
            next_line = file.readline()[:-1]

            
        return values
            
    @staticmethod        
    def evaluate(dict):
        returnString = ""
        return returnString

class lastlog(AuditModule):

    @staticmethod
    def read(file):
        value = {}   
        return value
    @staticmethod
    def evaluate(dict):
        returnString = ""
        return returnString

class modprobe(AuditModule):    
    @staticmethod
    def read(file):
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
    @staticmethod
    def evaluate(dict):
        pass

class networkvolume(AuditModule):
    @staticmethod
    def read(file):
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
    @staticmethod
    def evaluate(dict):
        pass

class open_connections(AuditModule):

    @staticmethod
    def read(file):
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

    @staticmethod
    def evaluate(dict):
        returnString = ""
        
        return returnString

class passwdpolicy(AuditModule):

    @staticmethod
    def read(file):
        values = dict()
        
        next_line = file.readline()
        
        while(next_line):

            if "#" not in next_line and not next_line.isspace():

                key_value = next_line.split()
                values[key_value[0]] = key_value[1]
                
            next_line = file.readline()
            
        return values

    @staticmethod
    def evaluate(dict):

            
        returnString = ""

        if dict["ENCRYPT_METHOD"] == "MD5":
            returnString = (returnString + "Your currently password encrypting method is MD5. " + 
                            "\nYou should consider changing the encrypting method to SHA256 or SHA516.")
            
            
        if dict["PASS_MIN_DAYS"] > '0': 
            returnString = (returnString + "Warning: You have to wait " + dict["PASS_MIN_DAYS"] + 
                            " days to change password, this can be a security risk in case of accidental password change.")



        return returnString

class processes(AuditModule):
    @staticmethod    
    def read(file):
        
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

    @staticmethod
    def evaluate(dict):
        returnString = ""
        return returnString

class samba(AuditModule):
    @staticmethod
    def read(file):
        
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
    @staticmethod
    def evaluate(dict):
        returnString = ""
        
        return returnString

class sshd(AuditModule):
    @staticmethod
    def read(file):
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
    @staticmethod
    def evaluate(dict):
        returnString = ""
        return returnString

class startup(AuditModule):
    @staticmethod
    def read(file):
        values = dict()
        
        file.readline() #Skip first line (/etc/init.d)
        file.readline() #Skip second line (total 216) //maybe use?
        
        next_line = file.readline()
        
        while (next_line):
            next_values = next_line.split()
            values[next_values[8]] = next_values
            next_line = file.readline()
            
        return values
        

    @staticmethod
    def evaluate(dict):
        returnString = ""
        return returnString
    
class sudoers(AuditModule):
    @staticmethod
    def read(file):
        
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


            values[username] = [hosts, run_as_users, run_as_groups, command]
            
            next_line = file.readline()

        return values
    @staticmethod
    def evaluate(dict):
        returnString = ""
        return returnString

class suid_files(AuditModule):
    @staticmethod
    def read(file):
        values = dict()
        
        next_line = file.readline()
        
        while (next_line):
            values[next_line] = next_line
            next_line = file.readline()
             
        return values
    @staticmethod
    def evaluate(dict):
        returnString = ""
        return returnString

class system(AuditModule):
    @staticmethod
    def read(file):
        
        values = dict()
        
        next_line = file.readline()
        
        while (next_line):
            values[next_line] = next_line
            next_line = file.readline()
            
        return values
    @staticmethod
    def evaluate(dict):
        returnString = ""
        return returnString

class users(AuditModule):
    @staticmethod
    def read(file):
        values = dict()
        
        next_line = file.readline()
        
        while (next_line):    
            inner_values = next_line.split(":")
            
            values[inner_values[0]] = inner_values
            
            next_line = file.readline()
        
        
        return values
    @staticmethod
    def evaluate(dict):
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