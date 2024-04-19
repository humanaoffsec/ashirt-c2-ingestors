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
LINE_POINTER = None # basic_logger writes to a single file, no need for a dict
BEACON_INFO = {} # dict of {id: {mythic-user, victim-user, victim-hostname, 
                 #              victim-ip, victim-external-ip, process, pid, integrity}}

INTEGRITY_LEVELS = {
    1: "Low",
    2: "Medium",
    3: "High",
    4: "SYSTEM"
}

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
        global LINE_POINTER

        timestamp = datetime.now()
        if LAST_EVENT_TIME is not None:
            delta = (timestamp - LAST_EVENT_TIME).total_seconds()
            if delta < DELAY:
                return None
        
        # Set the new event time
        LAST_EVENT_TIME = datetime.now()

        # basic_logger defaults to "mythic.log" as a single file
        head, tail = os.path.split(event.src_path)
        if re.search("mythic\.log(?!\.swp)", tail):

            # determine if this is a new creation or just a mod, both events fire with watchdog
            if LINE_POINTER == None:
                time.sleep(1) # Ensure the first line gets written
                LINE_POINTER = 0
            
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
    
def send_to_api_handler(task_data):
    """
    This leverages the ASHIRT template worker (ashirt_worker.py)
    Combines the beacon info from checkins and the submitted task data. This has the
    following formats:

        task_info = {
            "beacon": callback ID to query with BEACON_INFO,
            "command": command string,
            "operator": operator username - note: may be blank, falls back to mythic user
        }

        BEACON_INFO[id] = {
            "mythic-user": the default username if operator is empty,
            "victim-user", "victim-hostname", "victim-ip",
            "victim-external-ip", "process", "pid", integrity
        }


    The ashirt_worker create_evidence function contains nested calls that issue
    the actual request to the server after it is created.
    """
    global BEACON_INFO
    beacon_data = BEACON_INFO[task_data["beacon"]]

    # The operator may be empty, in which case default to the callback user
    if task_data["operator"] == "":
        task_data["operator"] = beacon_data["mythic-user"]

    # Craft the "file" materials
    content = {
        "c2": "Mythic C2",
        "c2Operator": task_data["operator"],
        "beacon": task_data["beacon"],
        "externalIP": beacon_data["victim-external-ip"],
        "internalIP": beacon_data["victim-ip"],
        "hostname": beacon_data["victim-hostname"],
        "userContext": beacon_data["victim-user"],
        "integrity": beacon_data["integrity"],
        "processName": beacon_data["process"],
        "processID": beacon_data["pid"],
        "command": task_data["command"],
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
            notes="C2 Event from Mythic", 
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
    global LINE_POINTER
    
    content = []
    try:
        content = get_file_contents(path)
    except Exception as e:
        print("{0} Failed to get file contents: {1}, {2}".format(datetime.now(), path, e),
               file=sys.stderr)
        return None
    
    # Create a subslice of only the new lines
    sub_slice = content[LINE_POINTER:]
    
    for index, line in enumerate(sub_slice):
        LINE_POINTER += 1
        
        try:
            data = json.loads(line)
        except Exception as e:
            print("{0} Failed to parse JSON line. Error: {1}".format(datetime.now(), e),
               file=sys.stderr)
            continue
        
        # Queues issued commands for later submission
        match data["message"]:
            case "new_callback":
                parse_callback(data)
            case "new_task":
                parse_task(data) # If the task parent ID is 0, will send to server
    

#                       #
#   PARSING FUNCTIONS   #
#                       #

def parse_callback(data):
    """
    Store any new callback information for later use when creating the ASHIRT
    API call with received tasks
    """
    global BEACON_INFO
    global INTEGRITY_LEVELS

    # Most information is in a double-nested "data" field, shorten this
    nested_data = data["data"]["data"]
    id = nested_data["id"]
    integrity = "na"

    # Check if the integrity level exists and is 1-4
    if re.search("[1-4]", str(nested_data["integrity_level"])):
        integrity = INTEGRITY_LEVELS[nested_data["integrity_level"]]

    BEACON_INFO[id] = {
        "mythic-user": data["data"]["username"],
        "victim-user": nested_data["user"],
        "victim-hostname": nested_data["host"],
        "victim-ip": nested_data["ip"],
        "victim-external-ip": nested_data["external_ip"], # may be empty
        "process": nested_data["process_name"],
        "pid": nested_data["pid"],
        "integrity": integrity
    }


def parse_task(data):
    """
    Mythic issues multiple new_task events. Ideally, looking for one marked "complete"
    would be the cue to send to the server, but if an action is caught and killed
    this would result in missing executed behavior. Instead, we capture events with
    parent ID = 0. 
    
    This might mean the fully translated command isn't captured - e.g. "shell whoami" 
    gets run as "run cmd.exe /S /c whoami" which is in a separate new_task event. 
    But without knowing future translation needs, this significantly complicates the
    scenario by requiring waiting + correlation.
    """
    # Most information is in a single-nested data field, shorten this
    data = data["data"]

    # ignore help and sleep commands
    if data["command_name"].lower() == "help" or data["command_name"].lower() == "sleep":
        return

    # ignore duplicate new_task events
    if not data["parent_task_id"] == 0:
        return

    # Build the task info
    task_info = {
            "beacon": data["callback_id"],
            "command": f"{data['command_name']} {data['params']}",
            "operator": data["operator_username"]
    }

    response = send_to_api_handler(task_info)
    if response.get("error", None) != None:
        print("{0} Task not uploaded to the server:\n"
                "Task: {1}\n"
                "Server Response: {2}".format(datetime.now(), task_info, response, file=sys.stderr))
            
    


def main():

    parser = argparse.ArgumentParser(description="Watches for file changes in a target directory and "
                                    "parses the incoming log file (MYTHIC) to extract information to send "
                                    "to the ASHIRT server. Ensure ASHIRT_API and ASHIRT_SECRET environment vars "
                                    "are set with the access and secret keys for the user you want submitting the "
                                    "information. Supply the secret key in its Base64 form.")
    parser.add_argument('-p', '--path',
                        help="The base log directory where Cobalt Strike logs will be placed")
    parser.add_argument('-s', '--slug',
                        help="The operation slug (the operation name) from ASHIRT")
    parser.add_argument('-a', "--address",
                        help="The address of the ASHIRT server to which to send API calls. Must have http[s] and "
                        "no trailing /. Ex: http://192.168.1.234:5555")

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
