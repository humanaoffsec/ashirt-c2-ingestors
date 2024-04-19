import os
import sys
import time
import argparse
import re
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ashirt_worker import FileData, CreateEvidenceInput, api_handler

# Filter out concurrent events from the observer (set at <1s in the watchdog)
LAST_EVENT_TIME = None
DELAY = 1

# Server particulars (API/Secret key stored in env variables)
OP_SLUG = ""
SERVER_ADDRESS = ""
API_HANDLER = None

# Store some persistent variables so that they don't need to be parsed repeatedly
LINE_POINTERS = {} # dict of filename:last observed line - watchdog does not provide the changes

BEACON_INFO = {} # dict of {id: {hostname, user, process, pid, source-ip, dest-ip}}
QUEUED_TASKS = {} # dict of filename: [array of {operator, task}] - cleared on next checkin for the beacon
                  # to get the timestamp of execution

class WatchdogHandler(FileSystemEventHandler):
    """
    Implements the on_modified function defined by the watchdog event handler. This implementation
    de-duplicates events sent in rapid succession and ensures that the modified file is a beacon log
    file and not something else.

    This implementation only focuses on file modification events, which also get fired on creation.
    If the file hasn't been encountered before it won't have an entry in the LINE_POINTER variable
    and will do initial triage of the file to grab the metadata from the top of the log.
    """

    @staticmethod
    def on_modified(event):
        if event.is_directory:
            return None
        
        # Deconflict modification events
        global LAST_EVENT_TIME
        global DELAY

        timestamp = datetime.now()
        if LAST_EVENT_TIME is not None:
            delta = (timestamp - LAST_EVENT_TIME).total_seconds()
            if delta < DELAY:
                return None
        
        # Set the new event time
        LAST_EVENT_TIME = datetime.now()

        # Ensure the file is a beacon log and not something else (like a swp)
        head, tail = os.path.split(event.src_path)
        if re.search("beacon_\d+\.log(?!\.swp)", tail):

            # determine if this is a new creation or just a mod, both events fire with watchdog
            if event.src_path not in LINE_POINTERS:
                time.sleep(1) # Ensure the first line gets written otherwise it won't find [metadata]
                handle_file_creation(event.src_path)

            else:
                handle_file_modification(event.src_path)


#                       #
#   HELPER FUNCTIONS    #
#                       #

def get_file_contents(path):
    try:
        with open(os.path.abspath(path), 'r') as f:
            content = f.readlines()
            return content
    except Exception as e:
        raise e

def get_beacon_id(path):
    id = "na"

    head, tail = os.path.split(path)
    try:
        id = re.search("\d+", tail)[0]
    except:
        print("{0} Failed to get beacon ID from {1}".format(datetime.now(), path), file=sys.stderr)

    return id

def send_to_api_handler(task, id):
    """
    This leverages the ASHIRT template worker (ashirt_worker.py)
    Combines the queued information for the task into a dict that
    gets submitted as the "file" element of the request, and hard-codes
    C2 log information before passing to the ashirt_worker file.

        BEACON_INFO[id] = {
                "victim-hostname", "victim-user",
                "process", "pid", "victim-ip",
                "destination-ip"
        }

    The ashirt_worker create_evidence function contains nested calls that issue
    the actual request to the server after it is created.
    """
    # Craft the "file" materials
    content = {
        "c2": "Cobalt Strike",
        "c2Operator": task["operator"],
        "beacon": id,
        "externalIP": BEACON_INFO[id]["destination-ip"],
        "internalIP": BEACON_INFO[id]["victim-ip"],
        "hostname": BEACON_INFO[id]["victim-hostname"],
        "userContext": BEACON_INFO[id]["victim-user"],
        "integrity": "na",
        "processName": BEACON_INFO[id]["process"],
        "processID": BEACON_INFO[id]["pid"],
        "command": task["command"],
        "result": "Result Pending",
        "metadata":{}
    }
    json_content = json.dumps(content)

    file_data: FileData = {
        "filename": "blob", 
        "mimetype": "multipart/form-data", 
        "content": json_content.encode()
    }

    # create_evidence ultimately returns the server response
    return API_HANDLER.create_evidence(
        CreateEvidenceInput(
            notes="C2 Event from Cobalt Strike", 
            content_type="c2-event", 
            tag_ids=[], 
            file=file_data
        ))


#                       #
#   WATCHDOG FUNCTIONS  #
#                       #

def handle_file_modification(path):
    """
    Called from on_modified in the Handler class. Reads the content from the last line stored in the
    LINE_POINTERS variable because watchdog does not supply the change message. Then parses each line
    looking for the desired entries. [input] lines are parsed for operator and command, [checkin] lines 
    clear the queued tasks and send them to the server.
    """
    global LINE_POINTERS
    
    id = get_beacon_id(path)
    
    content = []
    try:
        content = get_file_contents(path)
    except Exception as e:
        print("{0} Failed to get file contents on creation: {1}, {2}".format(datetime.now(), path, e),
               file=sys.stderr)
        return None
    
    # Create a subslice of only the new lines
    if LINE_POINTERS[path]:
        sub_slice = content[LINE_POINTERS[path]:]
    else:
        sub_slice = content

    for index, line in enumerate(sub_slice):
        # Queues issued commands for later submission
        if re.search("\[input\]", line):
            parse_user_input(line, path, id)

        # Sends all queued commands to the ASHIRT server
        elif re.search("\[checkin\]", line):
            handle_checkin(id)

    # Keep the last line in this specific log to avoid duplication
    LINE_POINTERS[path] = len(content)
    

def handle_file_creation(path):
    """
    Called from on_modified, but this will only trigger if there isn't a file entry in the 
    LINE_POINTERS dict. Sets the new line pointer and gets the metadata from the top of the file
    for persistent use, and then calls the handle_file_modification function to ensure any commands
    that were issued to create the log file are captured.
    """
    global LINE_POINTERS
    global BEACON_INFO

    id = get_beacon_id(path)

    # If this is a new checkin, get the basic info, otherwise set the pointer for
    # the new file's line to after the metadata
    if not id in BEACON_INFO:
        try:
            content = get_file_contents(path)
        except Exception as e:
            print("{0} Failed to get file contents on creation: {1}, {2}".format(datetime.now(), path, e),
                file=sys.stderr)
            return None
        
        # Grab the content if it's there
        if re.search("[metadata]", content[0]):
            ips = parse_ip_addresses(content[0], path)
            hostname = parse_computer_name(content[0], path)
            user = parse_user(content[0], path)
            proc_info = parse_process_info(content[0], path)

            BEACON_INFO[id] = {
                "victim-hostname": hostname,
                "victim-user": user,
                "process": proc_info["name"],
                "pid": proc_info["pid"],
                "victim-ip": ips["source"],
                "destination-ip": ips["dest"]
            }

    # set the line pointer to the next line and call the normal "modified" parser
    LINE_POINTERS[path] = 1


def parse_user_input(content, path, id):
    """
    This returns a dict combining the operator and the command, skipping
    any sleep or empty commands. Tasks are queued and not sent to the server
    until the next [checkin] is encountered to ensure the timestamp matches
    when the implant picked it up.
    """
    global QUEUED_TASKS

    operator = "Operator Not Found"
    try:
        operator = re.search("(?<=\[input\]\s\<)\w+(?=\>)", content)[0].split(";")[0]
    except:
        print("{0} Failed to get operator name from {1}".format(datetime.now(), path), file=sys.stderr)
    

    command = "Command Not Found"
    try:
        command = re.search("(?<=\> ).*", content)[0]
    except:
        print("{0} Failed to get command name from {1}".format(datetime.now(), path), file=sys.stderr)

    
    # Skip sleep commands
    if re.match("sleep", command):
        return None

    # Skip empty commands
    if command == "":
        return None

    # Queue the task for submission - don't submit now because the timestamp in ASHIRT won't match actual exec
    if id not in QUEUED_TASKS:
        QUEUED_TASKS[id] = [{"operator": operator, "command": command}]
    else:
        QUEUED_TASKS[id] += [{"operator": operator, "command": command}]


def handle_checkin(id):
    """
    Checkin events send all queued tasks to the server so that the
    timestamp indicates when it was picked up by the implant, not when
    it was issued by the operator
    """
    global QUEUED_TASKS

    if not id in QUEUED_TASKS:
        return None

    for task in QUEUED_TASKS[id]:
        if task["command"] == "":
            pass

        # The example worker from ASHIRT has several nested calls. This will
        # compile the task data and the API handler will issue the request
        # after compiling the body and HMAC
        response = send_to_api_handler(task, id)

        if response.get("error", None) != None:
            print("{0} Task not uploaded to the server:\n"
                  "Task: {1}\n"
                  "Server Response: {2}".format(datetime.now(), task, response, file=sys.stderr))
            
    QUEUED_TASKS[id] = []


#                       #
#   PARSING FUNCTIONS   #
#                       #

def parse_ip_addresses(content, path):
    """
    Note: Dest IP may be useless. For example, with the TS behind a redirector
    the log will pull the IP address of the redirector as it is known to the
    client - meaning this could be an IP not exposed to the victim.
    """
    global IP_ADDRESSES

    dest_ip = "IP Not Parsed"
    try:
        # This is the left side of the <-
        dest_ip = re.search("(?<=\[metadata\]\s)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?=\s\<\-)", content)[0]
    except:
        print("{0} Failed to get destination IP from {1}".format(datetime.now(),path), file=sys.stderr)
    
    # Source IP translates to the victim's IP address
    source_ip = "IP Not Parsed"
    try:
        source_ip = re.search("(?<=\<\-\s)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?=;)", content)[0]
    except:
        print("{0} Failed to get source IP from {1}".format(datetime.now(),path), file=sys.stderr)

    return {"source": source_ip, "dest": dest_ip}


def parse_computer_name(content, path):
    global COMPUTER_NAMES
    computer_name = "Computer Name Not Parsed"

    try:
        computer_name = re.search("(?<=computer\:\s).*;", content)[0].split(";")[0]
    except:
        print("{0} Failed to get computer name from {1}".format(datetime.now(),path), file=sys.stderr)

    return computer_name


def parse_user(content, path):
    global USERNAMES
    username = "User Name Not Parsed"

    try:
        username = re.search("(?<=user\:\s).*;", content)[0].split(";")[0]
    except:
        print("{0} Failed to get user name from {1}".format(datetime.now(),path), file=sys.stderr)

    return username


def parse_process_info(content, path):
    """
    Returns a dict with both the PID and name together
    """
    global PROCESS_INFO
    process_name = "Process Name Not Parsed"
    process_id = "PID Not Parsed"

    try:
        process_name = re.search("(?<=process\:\s).*;", content)[0].split(";")[0]
    except:
        print("{0} Failed to get process name from {1}".format(datetime.now(),path), file=sys.stderr)
    
    try:
        process_id = re.search("(?<=pid\:\s).*;", content)[0].split(";")[0]
    except:
        print("{0} Failed to get pid from {1}".format(datetime.now(),path), file=sys.stderr)

    return {"name": process_name, "pid": process_id}


def main():

    parser = argparse.ArgumentParser(description="Watches for file changes in a target directory and "
                                    "parses the incoming log file (Cobalt Strike) to extract information to send "
                                    "to the ASHIRT server. Ensure ASHIRT_API and ASHIRT_SECRET environment vars "
                                    "are set with the access and secret keys for the user you want submitting the "
                                    "information. Supply the secret key in its Base64 form.")
    parser.add_argument('-p', '--path',
                        help="The base log directory where Cobalt Strike logs will be placed")
    parser.add_argument('-s', '--slug',
                        help="The operation slug (the operation name) from ASHIRT")
    parser.add_argument('-a', "--address",
                        help="The address of the ASHIRT server to which to send API calls. Must have http[s]\n"
                        "Ex: http://192.168.1.234:5555")

    args = parser.parse_args()

    log_directory = args.path
    op_name = args.slug
    server_address = args.address

    # strip out the trailing slash if it exists
    if server_address[-1] == "/":
        server_address = server_address[:-1]

    # Check for arguments being present, if any are missing exit
    if log_directory == None or op_name == None or server_address == None:
        print("{0} FATAL - One or more mandatory arguments are missing:\n"
                  "Log Directory: {1}\n"
                  "Op Name (Slug): {2}\n"
                  "Server Address: {3}".format(datetime.now(), log_directory, op_name, server_address), file=sys.stderr)
        sys.exit(-1)

    # If the log directory doesn't exist the watchdog will fail
    if not os.path.exists(log_directory):
        try:
            os.mkdir(log_directory)
        except Exception as e:
            print("{0} FATAL - The log directory at did not exist and could not be created:\n"
                  "Directory: {1}\n"
                  "Error: {2}".format(datetime.now(), log_directory, e), file=sys.stderr)
            sys.exit(-1)

    # Get the environment variables and exit if not found
    access_key = os.getenv("ASHIRT_API")
    secret_key = os.getenv("ASHIRT_SECRET")

    if access_key is None or secret_key is None:
        print("{0} FATAL - The access and secret keys for the desired ASHIRT user must "
              "be supplied as ASHIRT_API and ASHIRT_SECRET env variables. "
              "NOTE: The secret key should be provided as Base64", file=sys.stderr)
        sys.exit(-1)

    # Set up the api handler
    global API_HANDLER
    API_HANDLER = api_handler(server_address, op_name, access_key, secret_key)

    # Create and run the Watchdog
    observer = Observer()
    event_handler = WatchdogHandler()
    observer.schedule(event_handler, log_directory, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(5)
    except Exception as e:
        observer.stop()
        print("{0} FATAL - The watchdog encountered an error:\n"
                "Error: {1}".format(datetime.now(), e), file=sys.stderr)

    observer.join()


if __name__ == "__main__":
    main()
