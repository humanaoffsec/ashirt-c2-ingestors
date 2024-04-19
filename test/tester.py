import os
import sys
import argparse
import time

LOG_NAMES = {
    "cobalt-strike": "beacon_12345.log",
    "brute-ratel": "b-9.log",
    "mythic": "mythic.log"
}

def get_file_contents(path):
    try:
        with open(os.path.abspath(path), 'r') as f:
            content = f.readlines()
            return content
    except Exception as e:
        raise e
    
def write_to_log(log_path, destination_path, framework):
    global LOG_NAMES
    destination_log = os.path.join(destination_path, LOG_NAMES[framework])

    content = get_file_contents(log_path)

    try:
        with open(destination_log, "w") as f:
            f.write(content[0])
    except Exception as e:
        print("Could not open the file for writing: {0}".format(e))
        sys.exit(-1)
    
    inp = "c"
    timed = False
    for i, line in enumerate(content[1:]):
        try:
            with open(destination_log, "a") as f:
                f.write(line)

                if timed:
                    time.sleep(.5)

                else:
                    print("Next Line: {0}".format(line))
                    if not inp.lower() == 'a':
                        inp = input("Continue (C), Stop (S), Send All (A), Send on .5s Timer (T) ")
                        match inp.lower():
                            case 's':
                                break
                            case 't':
                                timed = True
                    
        except Exception as e:
            print("Could not open the file for writing: {0}".format(e))
            sys.exit(-1)

def main():
    parser = argparse.ArgumentParser(description="Supply the c2 framework from the following list: "
                                     "cobalt-strike\nbrute-ratel\nmythic")
    parser.add_argument('-f', '--framework',
                        help="The framework to use")
    parser.add_argument('-l', '--log',
                        help="Full path to the source log file to read from")
    parser.add_argument('-d', "--destination",
                        help="The full path where the new log file will be written - do not include "
                        "a log file name - will use beacon_12345.log, b-9.log")

    args = parser.parse_args()
    
    if not args.log or not args.destination or not args.framework:
        print("Please supply all of the required arguments")
        sys.exit(-1)

  
    match args.framework:
        case "cobalt-strike":
            write_to_log(args.log, args.destination, "cobalt-strike")
        case "brute-ratel":
            write_to_log(args.log, args.destination, "brute-ratel")
        case "mythic":
            write_to_log(args.log, args.destination, "mythic")
        case _:
            print("Supplied framework does not match one of:\n"
                  "cobalt-strike\nbrute-ratel\nmythic")
            sys.exit(-1)


if __name__ == "__main__":
    main()
