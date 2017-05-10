'''
Created on May 3, 2017

@author: jesper
'''

import itertools
import yaml
from symbol import comparison

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
            
            print next_line
            inner_values = next_line.split()

            
            if "No such file or directory" in next_line:
                values[inner_values[3][1:-2]] = ["No such file or directory"] #[1:-2] is to trim the filename from ' and ':
            
            elif "total" in next_line:
                fileIndex = fileIndex + 1
            
            else: 
                #[permissions][?][owner][group][size][month][day][hour:min][filename]
                    values[inner_values[8]] = inner_values
                
            next_line = file.readline()
                
        return values

    @staticmethod
    def evaluate(dict):
        returnString = ""
        
        print dict
        
        with open("cron_at.yaml", "r") as stream:
            data_loaded = yaml.load(stream)
            
        print data_loaded
    
        for key in data_loaded:
            if dict.has_key(key):
                customer_value = dict[key][0]

                for comparison in data_loaded[key]:
                    values = data_loaded[key][comparison]         
                    message = compare(customer_value, values, comparison)
                    if message is not None: returnString += message + "\n"

        return returnString

class crontab(AuditModule):
    @staticmethod
    def read(file):
        values = dict()
        notSetupString = "No crontab has been set up for the following: \n"
        
        
        next_line = file.readline()[:-1]
        while (next_line): 
            crontab = next_line.replace("no crontab for ", "")
            values[crontab] = "no"
            next_line = file.readline()[:-1]    
        return values

    @staticmethod
    def evaluate(info):
        returnString = ""

        with open("crontab.yaml", "r") as stream:
            data_loaded = yaml.load(stream)
        
        for key in data_loaded:
            if info.has_key(key):
                customer_value = info[key]
                
                for comparison in data_loaded[key]:
                    values = data_loaded[key][comparison]
                    print customer_value
                    print values
                    print comparison
                    message = compare(customer_value, values, comparison)
                    if message is not None: returnString += message + "\n"

        
        return returnString

class diskvolume(AuditModule):
    @staticmethod
    def read(file):
        values = dict()
        file.readline() #Skip first line
        next_line = file.readline()
        column = ["filesystem", "size", "used", "avail", "use%", "mount"]
        while next_line:
            inner_dict = dict()
            #[Filesystem][Size][Used][Avail][Use%][Mounted on]
            inner_values = next_line.split()
            for index in range(0, 6):
                inner_dict[column[index]] = inner_values[index]

            inner_dict["use%"] = inner_dict["use%"][:-1]        # Removes the % sign
            values[inner_values[5]] = inner_dict
            next_line = file.readline()

        return values

    @staticmethod
    def evaluate(info):
        returnString = ""
        
        with open ("diskvolume.yaml", "r") as stream:
            loaded_data = yaml.load(stream)
        for key in loaded_data:
            if info.has_key(key):
                customer_map = info[key]
                for column in customer_map:
                    customer_value = customer_map[column]
                    if not loaded_data[key].has_key(column): continue
                    for comparison in loaded_data[key][column]:
                        values = loaded_data[key][column][comparison]
                        message = compare(customer_value, values, comparison)
                        if message is not None: returnString += message + "\n"
        
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
            
            values[innerValues[0]] = innerValues[1][:-1]
        return values

    @staticmethod
    def evaluate(info):
        returnString = ""

        
        with open("environment.yaml", "r") as stream:
            data_loaded = yaml.load(stream)

        for key in data_loaded:
            #check if key exists in customer file
            if info.has_key(key):
                customer_value = info[key]
                values = data_loaded[key]
                for comparison in values:
                    message = compare(customer_value, values[comparison], comparison)
                    if message is not None: returnString += message + "\n"
                
                
                

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
            returnString = returnString + ("Warning: There is no firewall set up for incoming traffic.\n");


        if dict["FORWARD"] == "ACCEPT":
            returnString = returnString + ("Warning: There is no firewall set up for forwarding traffic.\n");

            
        if dict["OUTPUT"] == "ACCEPT":
            returnString = returnString + ("Warning: There is no firewall set up for outgoing traffic.\n");

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
        
        for key in dict:
            if dict[key][1] == "!":
                #Unencrypted
                returnString += "The group " + dict[key] + "'s password is unencrypted and stored in /etc/security/passwd."
                
            elif dict[key][1] == "*":
                #Invalid
                returnString += "The group " + dict[key] + "'s password is invalid."
                
        
        return returnString

class lastlog(AuditModule):
    
    #Unsure how to parse...
    @staticmethod
    def read(file):
        value = dict()
        
        next_line = file.readline()
        
        
        while next_line and not "wtmp begins " in next_line:
            next_values = next_line.split()
            next_line = file.readline()
            
        next_line = file.readline() #Skip line    
        while next_line:
            next_values = next_line.split()
            next_line = file.readline()

            
            
            
        return value
    @staticmethod
    def evaluate(dict):
        #Not sure how to evaluate...
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
            modprobes = modprobes + nextLine[:-1] + "%"
        
        values["modprobe.d"] = modprobes
        
        while True:
            nextLine = file.readline()
            if (nextLine == ""): break
            innerValues = nextLine.split()

            values[innerValues[0]] = innerValues
            
        return values
    @staticmethod
    def evaluate(dict):
        
        returnString = ""
        
        modprobe_file = open("modprobe_folders", "r")
        
        config_list = []
        blacklist = []
        important_list = []
        
        customer_modules = []
        
        
        next_line = modprobe_file.readline() #Skip line
        next_line = modprobe_file.readline()
        
        while next_line and not next_line.startswith("#"):
            config_list.append(next_line[:-1])
            next_line = modprobe_file.readline()
            
        next_line = modprobe_file.readline() # Skip line
        
        while next_line and not next_line.startswith("#"):
            blacklist.append(next_line[:-1])
            next_line = modprobe_file.readline()        

        next_line = modprobe_file.readline() # Skip line
        
        while next_line and not next_line.startswith("#"):
            important_list.append(next_line[:-1])
            next_line = modprobe_file.readline()   
            
        customer_config_list = dict["modprobe.d"].split("%")

        dict.pop("modprobe.d", None)
        dict.pop("", None)
        
        for key in dict:
            customer_modules.append(key)

        for config in config_list:
            if config not in customer_config_list:
                returnString += "The expected file " + config + " is not in your system.\n"
                
        for module in customer_modules:
            if module in blacklist:
                returnString += "The system contains the blacklisted module " + module + "\n"
        
        for module in important_list:
            if module not in customer_modules:
                returnString += "The system does not contain the important module " + module + "\n"


        return returnString 
    
class networkvolume(AuditModule):
    @staticmethod
    def read(file):
        values = dict()
        
        next_line = file.readline()
        
        while next_line and "#" not in next_line:
            innerValues = next_line.split()
            values["1" + innerValues[2]] = innerValues
            next_line = file.readline()

        while next_line:
            if ("#" in next_line): 
                next_line = file.readline()
                continue
            innerValues = next_line.split()
            values["2" + innerValues[1]] = innerValues
            next_line = file.readline()

        
            
        return values
    @staticmethod
    def evaluate(info):
        returnString = ""
    
        uuid_dict = dict()
        
        mount_keys = []
        fstab_keys = []
        
        for key in info:
            if key.startswith("1"): mount_keys.append(key)
            elif key.startswith("2"): fstab_keys.append(key)
        
        returnString += "\n ###Unsure how to evaluate this part... [networkvolume/evaluate] ###\n"
        for key in mount_keys:
            need_this_temp_var = "to_keep_the_for_loop"
            #Unsure how to parse the first part...
        
        
        for key in fstab_keys:
            inner_key = info[key][0].split("=")[1]
            inner_value = key[1:]
            old_value = uuid_dict.get(inner_key, "")
            uuid_dict[inner_key] = old_value + key[1:] 
            
        for key in uuid_dict:
            if len(uuid_dict[key]) > 1:
                returnString += "The UUID: " + key + " is shared between the filesystems: " + uuid_dict[key]
            
        
        return returnString

class open_connections(AuditModule):

    @staticmethod
    def read(file):
        values = dict()
        
        file.readline() #Skip first line
        next_line = file.readline()
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
        """Lists of listen ports, estab ports etc
        
        make sure that the ports are not bad according to open_connections file
        
        """
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
    def evaluate(info):
        
        returnString = ""

        
        passwd_file = open("passwdpolicy", "r")
        
        next_line = passwd_file.readline()
        
        important_keys = []
        passwd_dict = dict()
        
        while next_line:
            
            if (next_line.isspace() or next_line.startswith("%")):
                next_line = passwd_file.readline()
                continue
            
            passwd_key = next_line.split("=")[0]
            
            passwd_values = next_line.split("=")[1][:-1]
            
            passwd_dict[passwd_key] = passwd_values
            next_line = passwd_file.readline()
        
        print passwd_dict
        print info
        
        for key in passwd_dict:
            #If key is in customer
            if info.has_key(key[1:]):
                #If key is dangerous
                if (key.startswith("^")):
                    returnString += "The key " + key + " is considered dangerous.\n"
                
                else:
                    customer_value = info[key[1:]]
                    values = passwd_dict[key]
                    print key
                    print "customer: " + customer_value
                    print "values:   " + str(values)
                    #If value is dangerous
                    if "^" + customer_value in values:
                        returnString += "The value " + customer_value + " is considered dangerous. Consider switching to " + str([x for x in values if not x.startswith("^")] + ". prefeably one of " + str([x for x in values if x.startswith("*")])) + "\n"
                    
                    #If value is not prefered
                    if "<" + customer_value in values:
                        returnString += "The value " + customer_value + " is not considered preferable. Consider switching to one of " + str([x for x in values if x.startswith("*")]) + "\n"
                        
            #If not found in customer
            else:
                #If key is important
                if (key.startswith("#")):
                    important_keys.append(key[1:])
                    #Add recomended value?
        
        if len(important_keys) > 0:  
                returnString += "The following important keys were not found: " + str(important_keys) + "\n"
        
        

        """if info["ENCRYPT_METHOD"] == "MD5":
            returnString = (returnString + "Your currently password encrypting method is MD5. " + 
                            "\nYou should consider changing the encrypting method to SHA256 or SHA516.")
            
            
        if info["PASS_MIN_DAYS"] > '0': 
            returnString = (returnString + "Warning: You have to wait " + dict["PASS_MIN_DAYS"] + 
                            " days to change password, this can be a security risk in case of accidental password change.")

        """
        
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
        
        return values

    @staticmethod
    def evaluate(dict):
        returnString = ""
        
        processes_file = open("processes", "r")
        
        next_line = processes_file.readline() #Skip first line
        next_line = processes_file.readline()
                
        expected_processes = []
        non_root_blacklist = []
        blacklist = []
        
 
        while next_line and "#" not in next_line and not next_line.isspace():
            expected_processes.append(next_line[:-1])
            next_line = processes_file.readline()
        
        next_line = processes_file.readline()
        
        while next_line and "#" not in next_line and not next_line.isspace():
            non_root_blacklist.append(next_line[:-1])
            next_line = processes_file.readline()
    
        next_line = processes_file.readline()


        while next_line and "#" not in next_line and not next_line.isspace():
            blacklist.append(next_line[:-1])
            next_line = processes_file.readline()
            
        
        
        for key in dict.iterkeys():
            customer_process = dict[key][10][:-1]
            
            #if process is blacklist
            if customer_process in blacklist:
                returnString += "The process " + customer_process + " currently running on your service is in our blacklist\n"
            
            #if process is non root
            elif customer_process in non_root_blacklist and dict[key][0 != "root"]:
                returnString += "The process " + customer_process + " currently running on your service as a non-root. This is considered a security risk\n"

            #if expected process is found, it removes it from the exepcted processes list
            if customer_process in expected_processes:
                expected_processes = [x for x in expected_processes if x != customer_process]
                
        #if expected_processes is NOT empty
        if expected_processes:
            returnString += "The following processes were expected but could not be found on your system: " + str(expected_processes) + "\n"
            
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
            
            if "#" in next_line or next_line.isspace():
                next_line = file.readline()
                continue
            
            if "[" in next_line:
                level = next_line
                next_line = file.readline()
                continue
            
            next_values = next_line.split(" = ")
            
            values[next_values[0].lstrip()] = [next_values[1][:-1], level[:-1]]
            
            next_line = file.readline()
        
        return values
    @staticmethod
    def evaluate(info):
        returnString = ""
        
        samba_file = open("samba", "r")
        
        
        samba_dict = dict()
        
        samba_lists = [[]]
        
        
        samba_important_keys = []
        
        samba_lists[0] = ([1, 2, 3])
        samba_lists.append([17, 6, 5])
        
        next_line = samba_file.readline()
        
        while next_line:
            if next_line.startswith("%") or next_line.isspace():
                next_line = samba_file.readline()
                continue
            samba_k_v_l = next_line[:-1].split("=")
            samba_key = samba_k_v_l[0]
            samba_v_l = samba_k_v_l[1].split(",")
            
            
            next_line = samba_file.readline()
            samba_values = samba_v_l[0].split("|")
            samba_levels = samba_v_l[1].split("|")
            
            if samba_key.startswith("#"): samba_important_keys.append(samba_key[1:])
                
            samba_dict[samba_key] = [samba_values, samba_levels]
            
            
        for key in samba_dict:
            if key[1:] in info.keys():
                
                #if Dangerous key
                if key.startswith("^"):
                    returnString += "The key " + key + " is considered dangerous.\n"
                    
                else:
                    customer_value = info[key[1:]][0]
                    customer_level = info[key[1:]][1]
                    samba_values = samba_dict[key][0]
                    samba_levels = samba_dict[key][1]
                    #if Dangerous level
                    if "^" + customer_level in samba_levels:
                        returnString += "The level for the key " + key[1:] + " is considered dangerous. Consider changing to one of " + str([x[1:] for x in samba_levels if not x.startswith("^")]) + " preferably one of " + str([x[1:] for x in samba_levels if x.startswith("*")]) + "\n"
                        
                    #if not preferable level
                    elif "<" + customer_level in samba_levels:
                        if len([x for x in samba_levels if x.startswith("*")]) > 0:
                            returnString += "The level for the environment key " + key[1:] + " is not considered preferable. Consider changing to one of " + str([x[1:] for x in samba_levels if x.startswith("*")]) + "\n" 
                      
                    #cant find level in samba txt    
                    elif "*" + customer_level not in samba_levels:
                        returnString += "The level " + customer_value + " for the key " + key[1:] + " was not found in our list of \"predetermined\" levels. \n\tRecommended levels: " + str([x[1:] for x in samba_levels if x.startswith("*")]) + "\n\tOkay levels: " + str([x[1:] for x in samba_levels if x.startswith("<")]) + "\n"

                    
                    #if Dangerous value
                    if "^" + customer_value in samba_values:
                        returnString += "The value for the key " + key[1:] + " is considered dangerous. Consider changing to one of " + str([x[1:] for x in samba_values if not x.startswith("^")]) + " preferably one of " + str([x[1:] for x in samba_values if x.startswith("*")]) + "\n"

                    #if not preferable value
                    elif "<" + customer_value in samba_values:
                        if len([x for x in samba_levels if x.startswith("*")]) > 0:
                            returnString += "The value for the environment key " + key[1:] + " is not considered preferable. Consider changing to one of " + str([x[1:] for x in samba_values if x.startswith("*")]) + "\n" 
                         
                    #cant find value in samba txt
                    elif "*" + customer_level not in samba_values:
                        returnString += "The value " + customer_value + " for the key " + key[1:] + " was not found in our list of \"predetermined\" values. \n\tRecommended values: " + str([x[1:] for x in samba_values if x.startswith("*")]) + "\n\tOkay levels: " + str([x[1:] for x in samba_values if x.startswith("<")]) + "\n"
                  
                samba_important_keys = [x for x in samba_important_keys if x != key[1:]]
            #cant find key in samba  
            
        if len(samba_important_keys) > 0:
            returnString += "The following keys were not found in your system: " + str(samba_important_keys) + ". They are considered important."
                
                    
                    
            
        
        return returnString

class sshd(AuditModule):
    @staticmethod
    def read(file):
        values = dict()
        
        next_line = file.readline()
        
        while (next_line):

            if "No such file or directory" in next_line:
                values["/etc/ssh/sshd_config"] = "No such file or directory"
            
            if "#" in next_line or next_line.isspace(): 
                next_line = file.readline()
                continue

            next_values = next_line.split()
  
                

            values[next_values[0]] = next_values[1]
            
            next_line = file.readline()
        
        return values
    @staticmethod
    def evaluate(info):
        returnString = ""
        
        with open("sshd.yaml", "r") as stream:
            data_loaded = yaml.load(stream)        
            
        for key in data_loaded:
            if info.has_key(key):
                customer_value = info[key]
                values = data_loaded[key]
                
                for comparison in values:    
                    message = compare(customer_value, values[comparison], comparison)

                    if message is not None: returnString += message + "\n"

                
            
            
            
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
        
        blacklist = []
        expected  = []
        
        
        customer_startups = []
        
        startup_file = open("startup", "r")
        
        next_line = startup_file.readline() # Skip first line
        next_line = startup_file.readline()

        while next_line and "#" not in next_line:
            expected.append(next_line[:-1])
            next_line = startup_file.readline()
            
        next_line = startup_file.readline() # Skip line

        while next_line:
            blacklist.append(next_line[:-1])
            next_line = startup_file.readline()

        for key in dict:
            #If dangerous
            if key in blacklist:
                returnString += "The process " + key + " is started along the system. This is considered a security risk.\n"
            
            if key in expected:
                expected = [x for x in expected if x != key]

        if len(expected) > 0:
            returnString += "The processes: " + str(expected) + " were expected to start along with the systems but do not. This is considered a security risk.\n"
        
                
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

            if "#" in next_line or next_line.isspace(): 
                next_line = file.readline()
                continue
            
            if "Defaults" in next_line:
                inner_values = next_line.split()
                tmp = inner_values[1].split("=")
                username = tmp[0]
                values[username] = ['','','',command]
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

        if dict.has_key("env_reset") == True:
            returnString += "env_reset is available. The system will make sure the terminal environment remove any user variables and clear potentially harmful environmental variables from the sudo sessions \n \n"
        else:
            returnString += "env_reset variable has not been set. You should add it the variable in /etc/sudoers"    

        for key in dict:
            value = dict[key]

            if key == "secure_path":

                if value[3] != "[\'\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"\']":
                 continue

            if (value[0] and value[1] and value[2] and value[3]) == "ALL" and ("root" not in key) and ("%" not in key):
                 returnString += "User: " + "\"" + key + "\"" + " has super user rights.\n\n"
                 continue

            if (value[0] and value[2] and value[3] == "ALL") and (value[1] == '') and ("root" not in key) and ("%admin" not in key) and ("%sudo" not in key):
                 returnString += "Members of group: " + "\"" + key + "\"" + " may gain root privileges.\n\n"
                 continue

            if (value[0] and value[1] and value[2] and value[3] == "ALL") and ("root" not in key) and ("%admin" not in key) and ("%sudo" not in key):
                 returnString += "Members of sudo group: " + "\"" + key + "\"" + " can execute any command\n\n"
                 continue

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

def compare(customer_value, values, comparison):
    print "COMPARISON: " + comparison
    #Not equal 
    if comparison == "neq":
        values = values["values"]

        if customer_value in values.keys():
            message = values[customer_value]["msg"]
            severity = values[customer_value]["severity"]
            return message
            
    if comparison == "nlt":
        value = values["value"]
        
        if int(customer_value) < int(value):
            message = values["msg"]
            severity = values["severity"]
            return message
        
    if comparison == "ngr":
        value = values["value"]
        
        if int(customer_value) > int(value):
            message = values["msg"] 
            return message
            
    if comparison == "nbtwn":

        values = values["values"]
        for message in values:
            for ranges in values[message]["ranges"]:
                range_max = max(ranges)
                range_min = min(ranges)
                if int(customer_value) < range_max and int(customer_value) > range_min:
                    severity = values[message]["severity"]
                    return message
                
    if comparison == "permissions":
        for permission_group in values:
            if permission_group == "other":
                other_rwx = customer_value[7:]
                for permission in values[permission_group]:
                    if permission in other_rwx:
                        message = values[permission_group][permission]["msg"]
                        return message
                    
            if permission_group == "user":
                user_rwx = customer_value[1:4]
                for permission in values[permission_group]:
                    if permission in user_rwx:
                        message = values[permission_group][permission]["msg"]
                        return message
            
            if permission_group == "group":
                group_rwx = customer_value[4:7]
                for permission in values[permission_group]:
                    if permission in group_rwx:
                        message = values[permission_group][permission]["msg"]
                        return message
        
            
    pass