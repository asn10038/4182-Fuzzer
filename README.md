# 4182-Fuzzer
This is the fuzzer for Security II.

#### General Info
* This runs with Python version 3.6.7


#### Running -- temp
* Set up with `pip install -r requirements.txt`
* Run fuzzer with `python Main.py [args]` -- NOT IMPLEMENTED
* Run servier with `python MainServer.py [args]`
* **NOTE**: Only runs with python v3.6 and later

## TO BE IMPLEMENTED

### IP Layer Fuzzing -- TCP layer is valid and IP Header is fuzzed
  * Run a default set of tests where each field is fuzzed individually with all possible values tested for each field
  * The user can specify what fields to fuzz but use the default tests
  * Running a set of tests where content of fields is read in as hex from a file.
  * The user can specify multiple tests in the same file
  * Each line can correspond to a given packet with tag:value pairs
  * Set a maximum on the number of tests in a given file
  * The fuzzer must include a small default payload that is specified in a file and can be edited by the user

### TCP Layer Fuzzing -- IP Layer is valid and TCP layer is fuzzed
  * Run a default set of tests where each field is fuzzed individually with all possible values tested for each field
  * The user can specify what fields to fuzz but use the default tests
  * Run a set of tests where the content of the fields is read in as hex from a file.
  * The user can specify multiple tests in the same file
  * Each line can correspond to a given packet with tag:value pairs
  * Set a maximum on the number of tests in a given file
  * The fuzzer must include a small default payload that is specified in a file and can be edited by the user

### Application Layer Fuzzing -- Valid IP & TCP Layers
  * Run a set of default tests where random payloads are sent to the Server
  * User specifies the number of tests to run
  * User can specify a fixed payload size
  * User can specify size of the fixed payload
  * User can specify a varied payload
  * User can specify the range in a varied payload
  * User can specify payload in a file
  * Each line in the file is a separate payload
  * There is a maximum number of tests in the file
  * The fuzzer processes the response from the server
  * The fuzzer tracks the number of valid and invalid responses
  * When the fuzzer completes it will print the total number of tests, valid, and invalid counts


### Server
  * Normal socket library that does not parse the IP and Transport Layers -- DONE
  * Inspect the payload for a series of bytes (referred to as the *pattern* ) at the start of the payload -- DONE
  * The pattern should be specified in hex in a file and read when the server starts -- DONE
  * The pattern may not exceed the maximum allowed payload length -- DONE
  * The server will send a response with payload 0x00 if valid -- DONE
  * The server will send a response with payload 0xFF if invalid -- DONE
  * The server will keep a count of the number of valid payloads received -- DONE
  * The server will keep a count of the number of invalid payloads received -- DONE
  * When the server is done or stopped it will either display the counts or write them to a file before exiting -- DONE
