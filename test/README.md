# Test Usage

This isn't a proper unit test, but the supplied Python file will take a supplied log file (Cobalt Strike, Brute Ratel, or Mythic)
and write it to a target location to simulate creation of the log from the C2 (i.e., you don't need to spin up a C2 server to test
the ingestor if you have a representative log file).

The tester can:
- Send lines one at a time, with user confirmation, and show a preview of what's being sent next
- Send the lines one at a time on a .5s timer (no preview)
- Send all of the lines at once (not recommended, the watchdog doesn't seem to handle this well - probably need to send an extra line in after to trigger
the file mod event)

```bash
usage: parser_tester.py [-h] [-f FRAMEWORK] [-l LOG] [-d DESTINATION]

Supply the c2 framework from the following list: cobalt-strike brute-ratel
mythic

options:
  -h, --help            show this help message and exit
  -f FRAMEWORK, --framework FRAMEWORK
                        The framework to use
  -l LOG, --log LOG     Full path to the source log file to read from
  -d DESTINATION, --destination DESTINATION
                        The full path where the new log file will be written
                        - do not include a log file name - will use
                        beacon_12345.log, b-9.log, mythic.log
```
