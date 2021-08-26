
#Read Event Logs from Local/Remote Hosts using logparser.exe
#Joe Avanzato

#TODO-Spaces in Paths breaking cmdline calls - normalize paths - NOT DONE !!!
#TODO - add argument for username filter - DONE
#TODO - strip extra garbage from resultant file (unnecessary data) - ALMOST DONE?
#TODO - Cleaning Everything Up...
#TODO - Hide Password in CS cmdline logs

import datetime, argparse, os, sys, subprocess, csv, traceback, re, xlsxwriter

global hostname
global default_log_path
global user_target
domain = 'PAYCHEX'
default_log_path = "%SystemRoot%\\System32\\winevt\\Logs\\" #Root path for Event Viewer Logs
hostname = ''
user_target = ''

starting_path = os.getcwd()
current_time = str(datetime.datetime.now())
current_time = current_time.replace(':', '-') #Becuase Windows File Names have terrible support for special characters
current_time = current_time.replace(' ', '-')

parser = argparse.ArgumentParser(usage = '\n################################################################\n Remote Retrieval, Analysis and Filtering of Windows Event Logs Using Python'
                                         '\n  -H -- [Target Host-Name (Only One)]'
                                        '\n  -C -- [ALT account Credentials in format Username Password OR Username - ex. -C javanzat_alt PASSWORD, javanzat_alt]'
                                        '\n  -U -- [Username to Filter Logs for]'
                                         '\n  -S -- [Security.evtx Local File Input]'
                                         '\n  -N -- [Network Share Letter Definition'
                                        '\n EXAMPLE USAGE: logon-grabber.exe -H IT-M-03DN8 -C javanzat_alt password -U javanzat'
                                        '\n EXAMPLE USAGE: logon-grabber.exe -H IT-M-03DN8 -C javanzat_alt -U javanzat <- No Password means Script will prompt at appropriate time'
                                        '\n EXAMPLE USAGE: logon-grabber.exe -H IT-M-03DN8 -C javanzat_alt <- Unfiltered logs include System Events'
                                        '\n################################################################')
parser.add_argument("-H", "--hostname", help='Specify Target Host Name for Event Log Retrieval', nargs=1)
parser.add_argument("-C", "--credentials", help='Provide User//Password OR Only User for Drive Mapping- ex. -C javanzat_alt PASSWORD', nargs='+')
parser.add_argument("-U", "--username", help='Target User to Filter Security Logs in Relation to', nargs=1)
parser.add_argument("-N", "--share", help='Target Network Share Letter Mapping', nargs=1)
parser.add_argument("-S", "--sfile", help='Provide File Name for Security.evtx Event Log (Same Folder would be nice until I make this better)')
args = parser.parse_args()

print("\n\n")
print("#### Remote Reading of Windows Event Logs ####\n")
print("##############################################\n")
print("##############################################\n")
print("##############################################\n")

def main():     #Initialization/Main Routine
    global hostname #Target Host
    global log_type #Target Log Types (Application, Security, System, etc..)
    global event_ID #Target Event IDs
    global user_target
    global new_log_name
    
    if args.hostname == None: #HostName is necessary if not using -S
        hostname = "Unknown-Host"
    else:
        hostname = args.hostname[0]
        print("Host Name : " + hostname)

    if args.username == None: #No Username = No Filtering
        user_target = 'None'
    else:
        user_target = args.username[0]

    if args.sfile == None: #No input file, normal operations - if input file exists, skip netmap/copyover and jump to log analysis
        ping(hostname)
        copy_over()  ###
    else:
        new_log_name = args.sfile

    log_parse(new_log_name)
    filter_csv()
    color_sort()
    clean_up()

def ping(host): #Checks if specified hostname responds to ping
    print("\nPinging Host Name : "+host)
    print("\nUser Target : "+user_target)
    status,result = subprocess.getstatusoutput("ping -n 1 "+host) #Status output of 0 indicates success
    if status == 0:
        print("Host " + host + " is Responding")
    else:
        print("Host " + host + " is NOT Responding")
        print("Shutting Down...")
        exit(0)


def copy_over(): #Maps hostname to network drive and retrieves Security.evtx, copying to local folder
    global new_log_name
    print("Copying Over Security.evtx...")
    print("Attempting to Map Network Drive")
    share = '\\\\'+hostname+'\\C$'
    try:
        password = args.credentials[1]
        nopass = 0
    except:
        print("No Password Provided Initially, Prompting for Password..")
        nopass = 1
    try:
        user = args.credentials[0]
        print("User Mapping Drive : "+user)
    except:
        print("No User Provided!")
        print("Shutting Down...")
        exit(0)
    #localname = None
    #win32wnet.WNetAddConnection2(win32netcon.RESOURCETYPE_DISK, 'Z:', share, None, user, password, 0)
    if nopass == 1:
        try:
            print("Executing Command : " + r'net use * ' + share +' /user:PAYCHEX\\' + user)
            subprocess.call(r'net use * ' + share +' /user:PAYCHEX\\' + user, shell=True)
        except:
            print("Drive could NOT be mapped!")
            print(traceback.print_exc(sys.exc_info()))
            disconnect()
            exit(0)
    else:
        try:
            print("Executing Command : " + r'net use * ' + share + ' ' + password + ' /user:PAYCHEX\\' + user)
            subprocess.call(r'net use * '+share+' '+password+' /user:PAYCHEX\\'+user, shell=True)
        except:
            print("Drive could NOT be mapped!")
            print(traceback.print_exc(sys.exc_info()))
            disconnect()
            exit(0)
    print("Drive Successfully Mapped!")
    try:
        os.chdir('\\\\'+hostname+r'\C$\Windows\System32\winevt\Logs')
        if os.path.isfile('\\\\'+hostname+r'\C$\Windows\System32\winevt\Logs\Security.evtx') == True:
            print(r"Copying Security Log File to Current Working Directory ("+str(starting_path)+")")
            subprocess.call('copy ' + '\\\\'+hostname+'\C$\Windows\System32\winevt\Logs\Security.evtx '+str(starting_path), shell=True)
            os.chdir(str(starting_path))
            new_log_name = "Security-"+hostname+'.evtx'
            new_log_location = "%SystemRoot%\\"+new_log_name
            print("Copying Log To New File [ "+new_log_name+" ]")
            subprocess.call('copy Security.evtx '+new_log_name, shell=True)
        else:
            print("Security Log File Not Found!")
            disconnect()
            exit(0)
    except:
        print("Failure copying files!")
        print(traceback.print_exc(sys.exc_info()))
        disconnect()
        exit(0)

    disconnect()


def log_parse(new_log_name): #Runs logparser.exe against Security event log, converting to csv
    print("Checking PowerShell Execution Policy..")
    policy_checker()
    print("Writing parser.ps1..")
    x = os.getcwd()
    try:
        with open ("parser.ps1", 'w+') as f:
            script = 'Get-WinEvent -FilterHashTable @{ID=@(4624,4634,4647,4648,4800,4801,4802,4803); Path=\".\\'+new_log_name+"\"} | Export-CSV "+x+"\Security-"+hostname+"-"+str(current_time)+".csv"
            #script = "Get-EventLog -ComputerName \""+hostname+"\" -LogName \"Security\" -InstanceID 4624,4634,4647,4648,4800,4801,4802,4803 | Export-CSV "+x+"\Security-"+hostname+"-"+str(current_time)+".csv"
            f.write(script)
    except:
        print(traceback.print_exc(sys.exc_info()))
        disconnect()
        exit(0)
    fullname = x+"\Security-"+hostname+"-"+str(current_time)+".csv"
    #print(fullname)
    print("Executing: "+script)
    y = x+"\parser.ps1"
    subprocess.call(['powershell.exe', y], stdout=sys.stdout)

    #print("Attempting LogParse Execution against Security Event Log...(Can take 30-90 Seconds depending on log size)..")
    #print("LogParser \"Select * INTO Security-"+hostname+"-"+str(current_time)+".csv FROM "+new_log_name+"\" -i:EVT -o:csv")
    #try:
    #    subprocess.call("LogParser \"Select * INTO Security-"+hostname+"-"+str(current_time)+".csv FROM "+new_log_name+"\" -i:EVT -o:csv", shell=True)
    #except:
    #    print("Failed Parsing Log with LogParser")
    #    print(traceback.print_exc(sys.exc_info()))
    print("Finished parsing log...")
    print("Changing Policy Back...")
    set_policy(old_policy)
    print("Confirming Old Policy Restored..")
    y = check_policy()
    if old_policy == y:
        print("Policy Restored to:"+y)
    else:
        print("Error Restoring PowerShell Policy..")


def policy_checker():
    global old_policy
    policy = check_policy()
    old_policy = policy
    print("Current Policy: "+policy)
    if policy == "Unrestricted":
        pass
    else:
        result = set_policy("Unrestricted")
        print("Confirming Policy...")
        policy = check_policy()
        if policy == "Unrestricted":
            print("Current Policy: "+policy)
        else:
            print("Failed to Set Policy Correctly..Try Running from Administrator Terminal")

def check_policy():
    print("Checking CurrentUser PowerShell Policy...")
    print("Running: powershell Get-ExecutionPolicy -Scope CurrentUser")
    x = subprocess.check_output("powershell Get-ExecutionPolicy -Scope CurrentUser", shell=True)
    x = str(x).strip().replace('\'', "").replace('\\r', '').replace('\\n', '')
    x = x[1:]
    return x

def set_policy(policy):
    print("Setting "+policy+" PowerShell Execution Policy for CurrentUser...")
    print("Running: powershell Set-ExecutionPolicy -Scope CurrentUser "+policy)
    y = subprocess.check_output("powershell Set-ExecutionPolicy -Scope CurrentUser "+policy, shell=True)

def filter_csv(): #Takes logparser output and re-runs it to a new csv by filtering for specific events while also writing specific text related to each event
    global new_file_filtered
    global new_file
    new_file = "Security-"+hostname+"-"+str(current_time)+".csv"
    new_file_filtered = "Security-Filtered-"+hostname+"-"+str(current_time)+".csv"
    with open(new_file_filtered, 'w') as n:
        writer = csv.writer(n, lineterminator='\n')
        with open(new_file, 'r') as f:
            reader = csv.reader(f)
            x = 0
            for line in reader:
                if x == 0:
                    x = x + 1
                elif x == 1:
                    line[3] = "Event Message"
                    writer.writerow(line)
                    x = x + 1
                else:
                    # test_array = line.split(',')
                    event_id = str(line[1])
                    print(event_id + " - " + str(x))
                    x = x + 1
                    if user_target == 'None':
                        if (event_id == '4624'):
                            line[3] = "An Account was Successfully Logged On"
                            writer.writerow(line)
                        elif (event_id == '4634'):
                            line[3] = "An Account was Logged Off"
                            writer.writerow(line)
                        elif (event_id == '4647'):
                            line[3] = "User Initiated Logoff"
                            writer.writerow(line)
                        elif (event_id == '4648'):
                            line[3] = "Explicit Credential Logon"
                            writer.writerow(line)
                        elif (event_id == '4800'):
                            line[3] = "The Workstation was Locked"
                            writer.writerow(line)
                        elif (event_id == '4801'):
                            line[3] = "The Workstation was Unlocked"
                            writer.writerow(line)
                        elif (event_id == '4802'):
                            line[3] = "The Screensaver was Invoked"
                            writer.writerow(line)
                        elif (event_id == '4803'):
                            line[3] = "The Screensaver was Dismissed"
                            writer.writerow(line)
                    else:
                        if (event_id == '4624') and (str(user_target) in line[0]):
                            line[3] = "An Account was Successfully Logged On"
                            writer.writerow(line)
                        elif (event_id == '4634') and (str(user_target) in str(line[0])):
                            line[3] = "An Account was Logged Off"
                            writer.writerow(line)
                        elif (event_id == '4647') and (str(user_target) in str(line[0])):
                            line[3] = "User Initiated Logoff"
                            writer.writerow(line)
                        elif (event_id == '4648') and (str(user_target) in str(line[0])) and ('winlogon.exe' in str(line[0])):
                            line[3] = "Explicit Credential Logon"
                            writer.writerow(line)
                        elif (event_id == '4800') and (str(user_target) in str(line[0])):
                            line[3] = "The Workstation was Locked"
                            writer.writerow(line)
                        elif (event_id == '4801') and (str(user_target) in str(line[0])):
                            line[3] = "The Workstation was Unlocked"
                            writer.writerow(line)
                        elif (event_id == '4802') and (str(user_target) in str(line[0])):
                            line[3] = "The Screensaver was Invoked"
                            writer.writerow(line)
                        elif (event_id == '4803') and (str(user_target) in str(line[0])):
                            line[3] = "The Screensaver was Dismissed"
                            writer.writerow(line)


def color_sort(): #Use xlsxwriter package to format events by color and write xlsx file
    print("Preparing .xlsx file with color formatting...")
    new_file_colored = "Security-Final-"+hostname+"-"+str(current_time)+".xlsx"
    workbook = xlsxwriter.Workbook(new_file_colored)
    worksheet = workbook.add_worksheet('Login Data')
    format_4624 = workbook.add_format(properties={'bg_color': '#00B050'})
    format_4634 = workbook.add_format(properties={'bg_color': '#FFC7CE'})
    format_4647 = workbook.add_format(properties={'bg_color': '#FF0000'})
    format_4648 = workbook.add_format(properties={'bg_color': '#D8E4BC'})
    format_4800 = workbook.add_format(properties={'bg_color': '#FFC000'})
    format_4801 = workbook.add_format(properties={'bg_color': '#C6EFCE'})
    format_4802 = workbook.add_format(properties={'bg_color': '#F8CBAD'})
    format_4803 = workbook.add_format(properties={'bg_color': '#A9D08E'})
    format_null = workbook.add_format(properties={'bg_color': 'white'})
    with open(new_file_filtered, 'r') as f:
        reader = csv.reader(f)
        row = 0
        for line in reader:
            # del line[3]
            col = 0
            if "An Account was Successfully Logged On" in line:
                type = format_4624
            elif "An Account was Logged Off" in line:
                type = format_4634
            elif "User Initiated Logoff" in line:
                type = format_4647
            elif "Explicit Credential Logon" in line:
                type = format_4648
            elif "The Workstation was Locked" in line:
                type = format_4800
            elif "The Workstation was Unlocked" in line:
                type = format_4801
            elif "The Screensaver was Invoked" in line:
                type = format_4802
            elif "The Screensaver was Dismissed" in line:
                type = format_4803
            else:
                type = format_null
            line[2] = line[1]  # Replace Version with EventID
            line[4] = line[14]  # Replace Level with Asset Name
            line[5] = line[0]  # Replace Task with Message Details
            line[0] = line[16]  # Replace Message Details with Time
            line[1] = line[3]
            del line[6:27]
            del line[3]
            for item in line:
                if col == 0:
                    print("Row : " + str(row) + ", Column : " + str(col))
                    worksheet.write(row, col, item, format_null)
                    col = col + 1
                else:
                    print("Row : " + str(row) + ", Column : " + str(col))
                    worksheet.write(row, col, item, type)
                    col = col + 1
            row = row + 1
    workbook.close()


def clean_up(): #Delete unnecessary files - keeps final output and original Security.evtx concatenated with hostname
    print("Deleting extraneous files...")
    try:
        subprocess.call('del Security.evtx', shell=True)
    except:
        print("Failed to Delete Security.evtx..'")
        print(traceback.print_exc(sys.exc_info()))
    try:
        subprocess.call('del '+new_file, shell=True)
    except:
        print("Failed to Delete "+new_file+"..")
        print(traceback.print_exc(sys.exc_info()))
    try:
        subprocess.call('del '+new_file_filtered, shell=True)
    except:
        print("Failed to Delete "+new_file_filtered+"..")
        print(traceback.print_exc(sys.exc_info()))


def disconnect(): #Delete Network Mapped Drive connection
    try:
        subprocess.call(r'net use * '+hostname+' /delete', shell=True)
        print("Connection Closed Successfully")
    except:
        print("Failed to Close Connection")
        print(traceback.print_exc(sys.exc_info()))
        exit(0)


main()


