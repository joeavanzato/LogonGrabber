
#Read Event Logs from Local/Remote Hosts
#Joe Avanzato

#Filter on specific Event Logs and Event IDs
#Default behavior is to Read Remotely into Memory and Write-Out CSV Only
#Using -C flag with elevated credentials allows for mapping of network drive and copying over Event Log to local host for local reading (potentially more reliable/less room for error)
#By Default, -C also copies the specific Registry Key from the remote host and puts it at HKLM\SYSTEM\CurrentControlSet\Services\EventLog\ with the name 'Log-Host'
#This functionality unfortunately seems to require a Windows restart as reading the specified log results in the default ReadEventLog() behavior of grabbing the 'Application' log when it cannot find the log specified
#Using -S flag skips the Remote Registry copy and instead alters the existing key for the log in question - meaning the local host MUST have the same log in order for this to work - it removes the edit once the log has been processed
#This can result in a few events from the local host being written to the remote logs file as processing/reading is occurring, something to keep in mind

#To - do - eliminate flags to make default activity copy/skip instead of specifying - make - L include login events by default


import win32evtlog, win32evtlogutil, win32con, winerror, win32security, time, datetime, argparse, os, sys, subprocess, csv, traceback, codecs, re, winreg, getpass


global hostname
global log_type
global event_ID
global event_data
global default_log_path
default_log_path = "%SystemRoot%\\System32\\winevt\\Logs\\" #Root path for Event Viewer Logs
hostname = '' #
log_type = [] #List of logs given by user (I.E. Application Security etc)
event_ID = [] #List of Event IDs given by user
event_data = [] #Event 'Message' Body

current_time = str(datetime.datetime.now())
current_time = current_time.replace(':', '-') #Becuase Windows File Names have terrible support for special characters

parser = argparse.ArgumentParser(usage = '\n Remote Retrieval of Windows Event Logs Using Python\n  -H -- [Target Host-Name (Only One)]\n  -L -- [Specify Log Types for Retrieval, '
                                         'Space-Separated Values]\n  -E -- [Event ID #s for Filtering, Space-Separated Values]'
                                         '\n  -C -- [Copy Logs from Remote Host to Local Host using given User//Password - ex. -C javanzat_alt PASSWORD]'
                                         '\n  -S -- [Skip copying remote Registry Keys - edit local registry to temporarily point to copied Event Log]')
parser.add_argument("-H", "--hostname", help='Specify Target Host Name for Event Log Retrieval', required = True)
parser.add_argument("-L", "--log_type", help='Specify Log Types for Retrieval (Space Separated - Application, Security, System, etc, default = Security)', nargs="+", required = False)
parser.add_argument("-E", "--event_ID" , help='Specify Event IDs for Retrieval from Specified Logs (Space-Separated, default = ALL, default = Login/Logout/Lock/Unlock Events)', nargs="+" , required = False)
parser.add_argument("-C", "--copy_over", help='Copy Logs from Remote Host to Local Host using given User//Password - ex. -C javanzat_alt PASSWORD', nargs=2)
parser.add_argument("-S", "--skip", help='Skip copying remote Registry Keys - edit local registry to temporarily point to copied Event Log', action = 'store_true')
#parser.add_argument("-L", "--login_events", help='Use with USERNAME PASSWORD combo to automatically copy over and scan for login events', nargs=2)
args = parser.parse_args()

print("\n\n")
print("#### Remote Reading of Windows Event Logs ####\n")
print("##############################################\n")
print("##############################################\n")
print("##############################################\n")

def main():     #Gets hostname, log list and event id list from arguments passed to script
    global hostname #Target Host
    global log_type #Target Log Types (Application, Security, System, etc..)
    global event_ID #Target Event IDs
    hostname = args.hostname


    if args.log_type == None: #If no log type specified, default to 'Security'
        log_type.append("Security")
    else:
        length_logs = len(args.log_type)
        for i in range(length_logs):
            log = args.log_type[i]
            log_type.append(log)


    if args.event_ID == None: #If no Event ID specified, use 'event_ID[0] == All' to modify retrieval loop
        event_ID.append("All")
    else:
        length_events = len(args.event_ID)
        for i in range(length_events):
            id = args.event_ID[i]
            event_ID.append(id)


    print("Host Name : "+hostname)
    print("Log Types : "+str(log_type))
    print("Event IDs : "+str(event_ID))


    if args.copy_over is not None: #If Copy Over flag is set..
        print("Copying Over...")
        ping(hostname)
        copy_over()  ###

    else:
        print("No Copy-Over Set, reading Remote Log into Memory...") #If copy over flag is NOT set - default behavior- remote reading
        ping(hostname)

        length_log = len(log_type) ###
        for i in range(length_log): ###
            log = log_type[i] ###
            read_log(str(log)) ###

    #for i in log_type:
    #    print(str(i)+"\n")
    #for i in event_ID:
    #    print(str(i)+"\n")



def ping(host): #Checks if specified hostname responds to ping
    print("\nPinging Host Name : "+host)
    status,result = subprocess.getstatusoutput("ping -n 1 "+host) #Status output of 0 indicates success
    if status == 0:
        print("Host " + host + " is Responding")
    else:
        print("Host " + host + " is NOT Responding")
        print("Quitting Program...")
        exit(0)


def read_log(log): #Reads specified event log from newest to oldest in sequential manner
    global event_data
    global append
    print("\nReading Event Log : "+log)
    try:
        if args.copy_over is not None:
            log_handle = win32evtlog.OpenEventLog("localhost", log)   #If using local registry
        else:
            log_handle = win32evtlog.OpenEventLog(hostname, log) #Handle used in ReadEventLog using host and log-type
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ #Flags are mutually exclusive - can be SEEK (based on offset) or FORWARDS
        event_sum = win32evtlog.GetNumberOfEventLogRecords(log_handle) #Just checking total events in log file
        print("Total Events in Log :"+str(event_sum))
    except:
        print("Error Setting Log Handles/Flags/Reading Total Events..")
        print("Quitting...")
        print(traceback.print_exc(sys.exc_info()))
        exit(0)
    evt_dict={win32con.EVENTLOG_AUDIT_FAILURE:'EVENTLOG_AUDIT_FAILURE', #This Dictionary gives KEY:VALUE pairs for event types
              win32con.EVENTLOG_AUDIT_SUCCESS:'EVENTLOG_AUDIT_SUCCESS',
              win32con.EVENTLOG_INFORMATION_TYPE:'EVENTLOG_INFORMATION_TYPE',
              win32con.EVENTLOG_WARNING_TYPE:'EVENTLOG_WARNING_TYPE',
              win32con.EVENTLOG_ERROR_TYPE:'EVENTLOG_ERROR_TYPE'}
    if event_ID[0] == "All":
        print("Reading All Events...")
        with codecs.open(hostname+' - '+log+' Log - Parsed At '+str(current_time)+'.csv', 'w', encoding='utf-8') as f: #Sets up new CSV file using name of log being read
            writer = csv.writer(f, delimiter = ',')

            try:
                #all_events = 1
                #all_events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                while True:
                    try:
                        all_events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                    except:
                        print(traceback.print_exc(sys.exc_info()))
                        pass
                    for event in all_events:
                        try:
                            try:
                                event_time = str(event.TimeGenerated.Format())
                            except:
                                event_time = "Time: Error Reading"
                            try:
                                event_identifier =  str(winerror.HRESULT_CODE(event.EventID))
                            except:
                                event_identifier = "EID: Error Reading"
                            try:
                                pc = str(event.ComputerName) #Not Yet Used
                            except:
                                pc = "PC Name: Error Reading"
                            try:
                                event_category = str(event.EventCategory)
                            except:
                                event_category = "Category: Error Reading"
                            try:
                                event_record = str(event.RecordNumber)
                            except:
                                event_record = "Record: Error Reading"
                            try:
                                event_source = str(event.SourceName)
                            except:
                                event_source = "Source: Error Reading"
                            try:
                                event_message = (win32evtlogutil.SafeFormatMessage(event, log))
                                event_message = event_message.replace('\n', ' ').replace('\r', '')
                            except:
                                event_message = "Error Reading Event Message"
                            #event_message = event_message.rstrip('\r\n')
                            if not event.EventType in evt_dict.keys():
                                event_type = "Unknown Type"
                            else:
                                event_type = str(evt_dict[event.EventType])
                            if event.Sid is not None:
                                try:
                                    domain, user, type = win32security.LookupAccountSid(hostname, event.Sid)
                                    sid_description = (domain+user)
                                except win32security.error:
                                    sid_description = str(event.Sid)
                                event_user = sid_description
                            else:
                                event_user = "No Associated User"
                            #f.write(event_time+","+event_identifier+","+event_type+","+event_record+","+event_source+","+event_message+","+"\n")
                            event_data = []
                            event_data.extend((event_time, event_identifier, event_user, event_type, event_record, event_source))
                            total_data = event_message #
                            append = 0
                            parse_event(total_data, str(event_identifier)) #
                            if append == 1:
                                event_data.append(event_message)
                            length_event = len(event_data)
                            #print(str(length_event))
                            for i in range(length_event):
                                cur = event_data[i]
                                print(cur)
                            writer.writerow(event_data)
                        except:
                            print("Error Reading Event")
                            pass
                    if not all_events:
                        break
            except:
                print(traceback.print_exc(sys.exc_info()))

    else:
        print("Reading Specific Event IDs...")
        with codecs.open(hostname+' - '+log+' Log - Parsed At '+str(current_time)+' for Event IDs - '+str(event_ID)+'.csv', 'w', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter = ',')
            try:
                #all_events = 1
                #all_events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                while True:
                    try:
                        all_events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                    except:
                        print(traceback.print_exc(sys.exc_info()))
                        pass
                    for event in all_events:
                        try:
                            event_time = str(event.TimeGenerated.Format())
                        except:
                            event_time = "Time: Error Reading"
                        try:
                            event_identifier =  str(winerror.HRESULT_CODE(event.EventID))
                        except:
                            event_identifier = "EID: Error Reading"
                        try:
                            pc = str(event.ComputerName) #Not Yet Used
                        except:
                            pc = "PC Name: Error Reading"
                        try:
                            event_category = str(event.EventCategory)
                        except:
                            event_category = "Category: Error Reading"
                        try:
                            event_record = str(event.RecordNumber)
                        except:
                            event_record = "Record: Error Reading"
                        try:
                            event_source = str(event.SourceName)
                        except:
                            event_source = "Source: Error Reading"
                        try:
                            event_message = (win32evtlogutil.SafeFormatMessage(event, log))
                            event_message = event_message.replace('\n', ' ').replace('\r', '')
                        except:
                            event_message = "Error Reading Event Data"
                        #event_message = event_message.rstrip('\r\n')
                        if not event.EventType in evt_dict.keys():
                            event_type = "Unknown Type"
                        else:
                            event_type = str(evt_dict[event.EventType])
                        if event.Sid is not None:
                            try:
                                domain, user, type = win32security.LookupAccountSid(hostname, event.Sid)
                                sid_description = (domain+user)
                            except win32security.error:
                                sid_description = str(event.Sid)
                            event_user = sid_description
                        else:
                            event_user = "No Associated User"
                        #f.write(event_time+","+event_identifier+","+event_type+","+event_record+","+event_source+","+event_message+","+"\n")
                        event_data = []
                        event_data.extend((event_time, event_identifier, event_user, event_type, event_record, event_source))
                        total_data = event_message #
                        append = 0
                        parse_event(total_data, str(event_identifier)) #
                        if append == 1:
                            event_data.append(event_message)
                        length_event = len(event_data)
                        #print(str(length_event))
                        for i in range(length_event):
                            cur = event_data[i]
                            print(cur)
                        if event_identifier in str(event_ID):
                            writer.writerow(event_data)
                    if not all_events:
                        break
            except:
                print(traceback.print_exc(sys.exc_info()))

    win32evtlog.CloseEventLog(log_handle)


def parse_event(data, id): #Takes in event_message and event ID, uses RegEx to parse appropriate fields/values, extends list that gets written to CSV with event-specific expected values
    global event_data
    global append
    if data == "Error Reading Event Data":
        append = 1


    if id == str(4624):
        current_event = [] #Eventually - check each for "None' result/white-space only, append to list, iterate through list and extend to 'event_data' in order to remove fields which are solely white-space, saving file-size
        print("Logon Success Event") #Test
        event_string = "An account was successfully logged on."
        #event_subject = "Subject: "+re.search(r'Subject:(.*?)Security', data, re.DOTALL).group(1) #Removed
        try:
            event_sid = "Security ID: "+re.search(r'Security ID:(.*?)Account Name', data, re.DOTALL).group(1)
            event_data.append(event_sid)
        except:
            event_sid = "Security ID: Error Reading"
            event_data.append(event_sid)
        try:
            event_account = "Account Name: "+re.search(r'Name:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_account)
        except:
            event_account = "Account Name: Error Reading"
            event_data.append(event_account)
        try:
            event_domain = "Account Domain: "+re.search(r'Domain:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_domain)
        except:
            event_domain = "Account Domain: Error Reading"
            event_data.append(event_domain)
        try:
            event_logon_id = "Logon ID: "+re.search(r'Logon ID:(.*?)Logon Information', data, re.DOTALL).group(1)
            event_data.append(event_logon_id)
        except:
            event_logon_id = "Logon ID: Error Reading"
            event_data.append(event_logon_id)

        #event_logon_info = "Logon Information: "+re.search(r'Information:(.*?)Logon', data, re.DOTALL).group(1) #Removed
        try:
            event_logon_type = "Logon Type: "+re.search(r'Type:(.*?)Restricted', data, re.DOTALL).group(1)
            event_data.append(event_logon_type)
        except:
            event_logon_type = "Logon Type: Error Reading"
            event_data.append(event_logon_type)
        try:
            event_admin_mode = "Restricted Admin Mode: "+re.search(r'Mode:(.*?)Virtual', data, re.DOTALL).group(1)
            event_data.append(event_admin_mode)
        except:
            event_admin_mode = "Restricted Admin Mode: Error Reading"
            event_data.append(event_admin_mode)
        try:
            event_virtual_account = "Virtual Account: "+re.search(r'Account:(.*?)Elevated', data, re.DOTALL).group(1)
            event_data.append(event_virtual_account)
        except:
            event_virtual_account = "Virtual Account: Error Reading"
            event_data.append(event_virtual_account)
        try:
            event_elevated_token = "Elevated Token: "+re.search(r'Token:(.*?)Impersonation', data, re.DOTALL).group(1)
            event_data.append(event_elevated_token)
        except:
            event_elevated_token = "Elevated Token: Error Reading"
            event_data.append(event_elevated_token)
        try:
            event_impersonation_level = "Impersonation Level: "+re.search(r'Level:(.*?)New Logon', data, re.DOTALL).group(1)
            event_data.append(event_impersonation_level)
        except:
            event_impersonation_level = "Impersonation Level: Error Reading"
            event_data.append(event_impersonation_level)
        #event_new_logon = "New Logon: "+re.search(r'Logon:(.*?)Security', data, re.DOTALL).group(1) #Removed
        try:
            event_network_name = "Network Account Name: "+re.search(r'Network Account Name:(.*?)Network Account', data, re.DOTALL).group(1)
            event_data.append(event_network_name)
        except:
            event_network_name = "Network Account Name: Error Reading"
            event_data.append(event_network_name)
        try:
            event_network_domain = "Network Account Domain: " + re.search(r'Network Account Domain:(.*?)Logon GUID', data, re.DOTALL).group(1)
            event_data.append(event_network_domain)
        except:
            event_network_domain = "Network Account Domain: Error Reading"
            event_data.append(event_network_domain)
        try:
            event_logon_guid = "Logon GUID: "+re.search(r'GUID:(.*?)Process', data, re.DOTALL).group(1)
            event_data.append(event_logon_guid)
        except:
            event_logon_guid = "Logon GUID: Error Reading"
            event_data.append(event_logon_guid)
        #event_proc_info = "Process Information: "+re.search(r'Process Information:(.*?)Process ID', data, re.DOTALL).group(1) #Removed
        try:
            event_proc_id = "Process ID: " + re.search(r'Process ID:(.*?)Process Name', data, re.DOTALL).group(1)
            event_data.append(event_proc_id)
        except:
            event_proc_id = "Process ID: Error Reading"
            event_data.append(event_proc_id)
        try:
            event_proc_name = "Process Name: " + re.search(r'Process Name:(.*?)Network Information', data, re.DOTALL).group(1)
            event_data.append(event_proc_name)
        except:
            event_proc_name = "Process Name: Error Reading"
            event_data.append(event_proc_name)

        #event_network_info = "Network Information: "+re.search(r'Network Information:(.*?)Workstation Name', data, re.DOTALL).group(1) #Removed
        try:
            event_workstation_name = "Workstation Name: "+re.search(r'Workstation Name:(.*?)Source Network', data, re.DOTALL).group(1)
            event_data.append(event_workstation_name)
        except:
            event_workstation_name = "Workstation Name: Error Reading"
            event_data.append(event_workstation_name)
        try:
            event_source_address = "Source Network Address: "+re.search(r'Address:(.*?)Source', data, re.DOTALL).group(1)
            event_data.append(event_source_address)
        except:
            event_source_address = "Source Network Address: Error Reading"
            event_data.append(event_source_address)
        try:
            event_source_port = "Source Port: "+re.search(r'Port:(.*?)Detailed', data, re.DOTALL).group(1)
            event_data.append(event_source_port)
        except:
            event_source_port = "Source Port: Error Reading"
            event_data.append(event_source_port)
        #event_detail_auth = "Detailed Authentication Information: "+re.search(r'Detailed Authentication Information:(.*?)Logon Process', data, re.DOTALL).group(1)#Removed
        try:
            event_logon_proc = "Logon Process: "+re.search(r'Process:(.*?)Authentication', data, re.DOTALL).group(1)
            event_data.append(event_logon_proc)
        except:
            event_logon_proc = "Logon Process: Error Reading"
            event_data.append(event_logon_proc)
        try:
            event_auth_package = "Authentication Package: "+re.search(r'Package:(.*?)Transited', data, re.DOTALL).group(1)
            event_data.append(event_auth_package)
        except:
            event_auth_package = "Authentication Package: Error Reading"
            event_data.append(event_auth_package)
        try:
            event_tran_services = "Transited Services: "+re.search(r'Services:(.*?)Package', data, re.DOTALL).group(1)
            event_data.append(event_tran_services)
        except:
            event_tran_services = "Transited Services: Error Reading"
            event_data.append(event_tran_services)
        try:
            event_package_name = "Package Name (NTLM only): "+re.search(r'only\):(.*?)Key', data, re.DOTALL).group(1)
            event_data.append(event_package_name)
        except:
            event_package_name = "Package Name (NTLM only): Error Reading"
            event_data.append(event_package_name)
        try:
            event_key_length = "Key Length: "+re.search(r'Length:(.*?)This', data, re.DOTALL).group(1)
            event_data.append(event_key_length)
        except:
            event_key_length = "Key Length: Error Reading"
            event_data.append(event_key_length)

        #event_data.extend((event_string, event_sid, event_account, event_domain, event_logon_id, event_logon_type, event_admin_mode, event_virtual_account, event_elevated_token, event_impersonation_level,
                           #event_network_name, event_network_domain, event_logon_guid, event_proc_id, event_proc_name, event_workstation_name, event_source_address, event_source_port,
                           #event_logon_proc, event_auth_package, event_tran_services, event_package_name, event_key_length))
        return

    elif id == str(4634):
        print(4634)
        event_string = "An account was successfully logged off."
        event_data.append(event_string)
        #event_subject = "Subject: "+re.search(r'Subject:(.*?)Security', data, re.DOTALL).group(1) #Removed
        try:
            event_sid = "Security ID: "+re.search(r'ID:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_sid)
        except:
            event_sid = "Security ID: Error Reading"
            event_data.append(event_sid)
        try:
            event_account = "Account Name: "+re.search(r'Name:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_account)
        except:
            event_account = "Account Name: Error Reading"
            event_data.append(event_account)
        try:
            event_domain = "Account Domain: "+re.search(r'Domain:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_domain)
        except:
            event_domain = "Account Domain: Error Reading"
            event_data.append(event_domain)
        try:
            event_logon_id = "Logon ID: "+re.search(r'Logon ID:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_logon_id)
        except:
            event_logon_id = "Logon ID: Error Reading"
            event_data.append(event_logon_id)
        try:
            event_logon_type = "Logon Type: "+re.search(r'Type:(.*?)This', data, re.DOTALL).group(1)
            event_data.append(event_logon_type)
        except:
            event_logon_type = "Logon Type: Error Reading"
            event_data.append(event_logon_type)
        #event_data.extend((event_string, event_sid, event_account, event_domain, event_logon_id, event_logon_type))
        return
    elif id == str(4647):
        print(4647)
        event_string = "User Initiated Logoff."
        event_data.append(event_string)
        #event_subject = "Subject: "+re.search(r'Subject:(.*?)Security', data, re.DOTALL).group(1) #Removed
        try:
            event_sid = "Security ID: "+re.search(r'ID:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_sid)
        except:
            event_sid = "Security ID: Error Reading"
            event_data.append(event_sid)
        try:
            event_account = "Account Name: "+re.search(r'Name:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_account)
        except:
            event_account = "Account Name: Error Reading"
            event_data.append(event_account)
        try:
            event_domain = "Account Domain: "+re.search(r'Domain:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_domain)
        except:
            event_domain = "Account Domain: Error Reading"
            event_data.append(event_domain)
        try:
            event_logon_id = "Logon ID: "+re.search(r'Logon ID:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_logon_id)
        except:
            event_logon_id = "Logon ID: Error Reading"
            event_data.append(event_logon_id)
        #event_data.extend((event_string, event_sid, event_account, event_domain, event_logon_id))
        return
    elif id == str(4800):
        print(4800)
        event_string = "The Workstation was Locked"
        event_data.append(event_string)
        #event_subject = "Subject: "+re.search(r'Subject:(.*?)Security', data, re.DOTALL).group(1) #Removed
        try:
            event_sid = "Security ID: "+re.search(r'ID:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_sid)
        except:
            event_sid = "Security ID: Error Reading"
            event_data.append(event_sid)
        try:
            event_account = "Account Name: "+re.search(r'Name:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_account)
        except:
            event_account = "Account Name: Error Reading"
            event_data.append(event_account)
        try:
            event_domain = "Account Domain: "+re.search(r'Domain:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_domain)
        except:
            event_domain = "Account Domain: Error Reading"
            event_data.append(event_domain)
        try:
            event_logon_id = "Logon ID: "+re.search(r'Logon ID:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_logon_id)
        except:
            event_logon_id = "Logon ID: Error Reading"
            event_data.append(event_logon_id)
        try:
            event_session_id = "Session ID: "+re.search(r'Session ID:(.*?)This', data, re.DOTALL).group(1)
            event_data.append(event_session_id)
        except:
            event_session_id="Session ID: Error Reading"
            event_data.append(event_session_id)
        return
        #event_data.extend((event_string, event_sid, event_account, event_domain, event_logon_id, event_session_id))

    elif id == str(4801):
        print(4801)
        event_string = "The Workstation was Unocked"
        event_data.append(event_string)
        #event_subject = "Subject: "+re.search(r'Subject:(.*?)Security', data, re.DOTALL).group(1) #Removed
        try:
            event_sid = "Security ID: "+re.search(r'ID:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_sid)
        except:
            event_sid = "Security ID: Error Reading"
            event_data.append(event_sid)
        try:
            event_account = "Account Name: "+re.search(r'Name:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_account)
        except:
            event_account = "Account Name: Error Reading"
            event_data.append(event_account)
        try:
            event_domain = "Account Domain: "+re.search(r'Domain:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_domain)
        except:
            event_domain = "Account Domain: Error Reading"
            event_data.append(event_domain)
        try:
            event_logon_id = "Logon ID: "+re.search(r'Logon ID:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_logon_id)
        except:
            event_logon_id = "Logon ID: Error Reading"
            event_data.append(event_logon_id)
        try:
            event_session_id = "Session ID: "+re.search(r'Session ID:(.*?)This', data, re.DOTALL).group(1)
            event_data.append(event_session_id)
        except:
            event_session_id="Session ID: Error Reading"
            event_data.append(event_session_id)
        return
        #event_data.extend((event_string, event_sid, event_account, event_domain, event_logon_id, event_session_id))

    elif id == str(4802):
        print(4802)
        event_string = "The Screen-Saver was Invoked"
        event_data.append(event_string)
        #event_subject = "Subject: "+re.search(r'Subject:(.*?)Security', data, re.DOTALL).group(1) #Removed
        try:
            event_sid = "Security ID: "+re.search(r'ID:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_sid)
        except:
            event_sid = "Security ID: Error Reading"
            event_data.append(event_sid)
        try:
            event_account = "Account Name: "+re.search(r'Name:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_account)
        except:
            event_account = "Account Name: Error Reading"
            event_data.append(event_account)
        try:
            event_domain = "Account Domain: "+re.search(r'Domain:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_domain)
        except:
            event_domain = "Account Domain: Error Reading"
            event_data.append(event_domain)
        try:
            event_logon_id = "Logon ID: "+re.search(r'Logon ID:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_logon_id)
        except:
            event_logon_id = "Logon ID: Error Reading"
            event_data.append(event_logon_id)
        try:
            event_session_id = "Session ID: "+re.search(r'Session ID:(.*?)This', data, re.DOTALL).group(1)
            event_data.append(event_session_id)
        except:
            event_session_id="Session ID: Error Reading"
            event_data.append(event_session_id)
        return
        #event_data.extend((event_string, event_sid, event_account, event_domain, event_logon_id, event_session_id))

    elif id == str(4803):
        print(4803)
        event_string = "The Screen-Saver was Dismissed"
        event_data.append(event_string)
        #event_subject = "Subject: "+re.search(r'Subject:(.*?)Security', data, re.DOTALL).group(1) #Removed
        try:
            event_sid = "Security ID: "+re.search(r'ID:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_sid)
        except:
            event_sid = "Security ID: Error Reading"
            event_data.append(event_sid)
        try:
            event_account = "Account Name: "+re.search(r'Name:(.*?)Account', data, re.DOTALL).group(1)
            event_data.append(event_account)
        except:
            event_account = "Account Name: Error Reading"
            event_data.append(event_account)
        try:
            event_domain = "Account Domain: "+re.search(r'Domain:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_domain)
        except:
            event_domain = "Account Domain: Error Reading"
            event_data.append(event_domain)
        try:
            event_logon_id = "Logon ID: "+re.search(r'Logon ID:(.*?)Logon', data, re.DOTALL).group(1)
            event_data.append(event_logon_id)
        except:
            event_logon_id = "Logon ID: Error Reading"
            event_data.append(event_logon_id)
        try:
            event_session_id = "Session ID: "+re.search(r'Session ID:(.*?)This', data, re.DOTALL).group(1)
            event_data.append(event_session_id)
        except:
            event_session_id="Session ID: Error Reading"
            event_data.append(event_session_id)
        return
        #event_data.extend((event_string, event_sid, event_account, event_domain, event_logon_id, event_session_id))
    else:
        print("No Specific RegEx Data")
        append = 1 #Flag indicating no specific regex exists for handling specific event




def copy_over():
    print("Attempting to Map Network Drive")
    share = '\\\\'+hostname+'\\C$'
    password = args.copy_over[1]
    user = args.copy_over[0]
    #localname = None
    #win32wnet.WNetAddConnection2(win32netcon.RESOURCETYPE_DISK, 'Z:', share, None, user, password, 0)
    print("Executing Command : "+r'net use Z: '+share+' '+password+' /user:PAYCHEX\\'+user)

    try:
        subprocess.call(r'net use Z: '+share+' '+password+' /user:PAYCHEX\\'+user)
        print("Drive Successfully Mapped!")
    except:
        print("Drive could NOT be mapped!")
        print(traceback.print_exc(sys.exc_info()))
        disconnect()
        exit(0)

    try:
        #print(os.listdir(r'Z:\Windows\System32\winevt\Logs'))              #Testing
        os.chdir(r'Z:\Windows\System32\winevt\Logs')
        if os.path.isfile(r'Z:\Windows\System32\winevt\Logs\\'+log_type[0]+'.evtx') == True:
            print(r"Copying Log File(s) to C:\\")
            print(str(log_type[0])+'.evtx')
            subprocess.call('copy '+r'Z:\Windows\System32\winevt\Logs\\'+str(log_type[0])+'.evtx C:\\Windows\\', shell=True)
            os.chdir('C:\\Windows\\')
            new_log_name = str(log_type[0])+"-"+hostname+'.evtx'
            new_log_location = "%SystemRoot%\\"+new_log_name
            print("Renaming Log To [ "+new_log_name+" ]")
            os.rename(str(log_type[0])+'.evtx', new_log_name)
        else:
            print("Log File Not Found!")
            disconnect()
            exit(0)
    except:
        print("Failure copying files!")
        print(traceback.print_exc(sys.exc_info()))
        disconnect()


    if args.skip == False: #This won't work unless computer is restarted unfortunately - doesn't seem to recognize the 'new log' and defaults to Application log instead of named log
        try:
            print("Adding Registry Keys for "+new_log_name)
            print("Executing : "+'REG COPY '+"\\\\"+hostname+"\\"+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+" "+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname+' /s /f')
            subprocess.call('REG COPY '+"\\\\"+hostname+"\\"+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+" "+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname+' /s /f', shell=True)
            print("Successfully copied Registry Key "+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0]+" from Remote Host to Local Host"))
            print("Attempting to Modify Copied Key...")
            reg_path = r"SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname
            #reg_handle = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS)
            winreg.SetValueEx(key, "File", 0, winreg.REG_EXPAND_SZ, new_log_location)
            print("Successfully copied Registry Key from Remote Host and Inserted New Values!")
            print("Using newly copied Key/Values to read copied Log...")
            read_log(new_log_name)     #TEMPORARY
            print("Finished reading log, attempting to delete/cleanup registry")
            #delete_current_key(key)
            winreg.CloseKey(key)
            try:
                print("Executing : "+'REG DELETE '+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname+' /f')
                subprocess.call('REG DELETE '+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname+' /f')
            except:
                print("Failed to delete registry key...")
        except:
            print("Failed to Copy Registry, Falling back to Standard")
            print(traceback.print_exc(sys.exc_info()))
            disconnect()
    elif args.skip == True:
        print("Using localhost Registry Values for Event Message Files")
        try:

            reg_path = r"SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])
            #reg_handle = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS)
            winreg.SetValueEx(key, "File", 0, winreg.REG_EXPAND_SZ, new_log_location)
            print("Editing existing Registry Key...")
            #winreg.SetValueEx(key, "File", 0, winreg.REG_EXPAND_SZ, new_log_location)
            try:
                read_log(str(log_type[0]))
                winreg.SetValueEx(key, "File", 0, winreg.REG_EXPAND_SZ, default_log_path + str(log_type[0]) + ".evtx")
            except:
                winreg.SetValueEx(key, "File", 0, winreg.REG_EXPAND_SZ, default_log_path + str(log_type[0]) + ".evtx")
                pass

            winreg.CloseKey(key)

            #print("Adding Registry Keys for "+new_log_name)
            #print("Executing : REG COPY HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+" "+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname+' /s /f')
            #subprocess.call('REG COPY HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\'+str(log_type[0])+" "+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname+' /s /f', shell=True)
            #print("Successfully copied Registry Key "+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0]+" from Local Host to Local Host"))
            #print("Attempting to Modify Copied Key...")
            #reg_path = r"SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname
            ##reg_handle = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            #key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS)
            #winreg.SetValueEx(key, "File", 0, winreg.REG_EXPAND_SZ, new_log_location)
            #print("Successfully copied Registry Key from Remote Host and Inserted New Values!")
            #print("Using newly copied Key/Values to read copied Log...")
            #read_log(new_log_name)     #TEMPORARY
            #print("Finished reading log, attempting to delete/cleanup registry")
            ##delete_current_key(key)
            #winreg.CloseKey(key)
            #try:
            #    print("Executing : "+'REG DELETE '+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname+' /f')
            #    subprocess.call('REG DELETE '+"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\\"+str(log_type[0])+"-"+hostname+' /f')
            #except:
            #    print("Failed to delete registry key...")
        except:
            print("Failed to Copy Registry, Falling back to Standard")
            print(traceback.print_exc(sys.exc_info()))
            disconnect()


    username = getpass.getuser()
    try:
        username = getpass.getuser()
        print("Moving Log File and Resultant CSV to C:\\Users\\"+username+"\\Documents\\")
        os.rename("C:\\Windows\\"+str(log_type[0])+"-"+hostname+'.evtx', "C:\\Users\\"+username+"\\Documents\\"+str(log_type[0])+"-"+hostname+" Parsed At "+str(current_time)+'.evtx')
        if args.skip == False:
            os.rename("C:\\Windows\\"+hostname+' - '+str(log_type[0])+"-"+hostname+".evtx"+' Log - Parsed At '+str(current_time)+' for Event IDs - '+str(event_ID)+'.csv', "C:\\Users\\"+username+"\\Documents\\"+hostname+' - '+str(log_type[0])+' Log - Parsed At '+str(current_time)+' for Event IDs - '+str(event_ID)+'.csv')
        else:
            os.rename("C:\\Windows\\"+hostname+' - '+str(log_type[0])+' Log - Parsed At '+str(current_time)+' for Event IDs - '+str(event_ID)+'.csv', "C:\\Users\\"+username+"\\Documents\\"+hostname+' - '+str(log_type[0])+' Log - Parsed At '+str(current_time)+' for Event IDs - '+str(event_ID)+'.csv')
    except:
        print("Failed moving "+str(log_type[0])+"-"+hostname+'.evtx'+" to C:\\Users\\"+username+"\\Documents\\"+" OR "+hostname+'.evtx'+' Log - Parsed At '+str(current_time)+' for Event IDs - '+str(event_ID)+'.csv')
        print(traceback.print_exc(sys.exc_info()))
        pass

    disconnect()


def disconnect():
    try:
        subprocess.call(r'net use Z: /delete', shell=True)
        print("Connection Closed Successfully")
    except:
        print("Failed to Close Connection")
        print(traceback.print_exc(sys.exc_info()))
        exit(0)

#def delete_current_key(key0):
#    try:
#        winreg.DeleteKey(key0)
#    except:
#        print("Failed to delete "+str(key0))



#        key_info = winreg.QueryInfoKey(key)
#        for subkey in range(0, key_info[0])
#           new_subkey = winreg.EnumKey(key, 0)
#            try:
#                winreg.DeleteKey(key, new_subkey)
#                print("Deleted "+key+"\\\\"+subkey)
#            except:
#               delete_current_key()
#    except:

main()


