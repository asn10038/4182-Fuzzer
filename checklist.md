## Evaluation Criteria

### Installation (10 pts)
  * Are the installation instructions clear?
  * Does the installation work per the instructions with no problems?

### User Guide (10 pts)
  * Are the fuzzer instructions clear and do they cover fuzzing each layer (IP, TCP, Application) and include examples?
    * Deduct 1 point if how to specify the destination of the packets (IP address, port) is not included in the user guide.
    * Deduct 2 points for each layer (IP, TCP, Application) not included in the user guide.
    * Deduct 1 point for each layer (IP, TCP, Application) the user guide includes but for which an example is not included.
    * Deduct 1 point for each layer (IP, TCP, Application) the user guide includes but for which how to run default tests is not described.
    * Deduct 1 point for each layer (IP, TCP, Application) for which the user guide includes fuzzing the layer but for which how to run tests when values are read from a file is not described.
  * Are the instructions for how to use the server and specify the pattern clear and include examples?
    * Deduct 2 points if how to use the server is not included in the user guide.
    * Deduct 1 point if how to user the server is included but how to specify a pattern is not included in the user guide.
  * Does the program work per the instructions with no problems? This means in the case that the program works, if you type exactly what is in the instructions does it work as described by the user guide or do you have to alter the instructions?

### Program Functionality (50 pts)

#### Fuzzer
  * Deduct 5 points if the fuzzer does not allow the user to specify the destination IP and port.
  * Deduct 2 points if the fuzzer does not support including a small default payload when fuzzing the IP or TCP layer.
  * Deduct 5 points if the fuzzer does not allow fuzzing all fields in the IP layer.
  * Deduct 5 points if the fuzzer does not allow running a default set of tests as specified in the first bullet under “IP Layer” in the project part 1 description.
  * Deduct 5 points if the fuzzer does not allow running a set of tests as specified in the second bullet under “IP Layer” in the project part 1 description.
  * Deduct 5 points if the fuzzer does not allow the user to fuzz all fields in the TCP layer.
  * Deduct 5 points if the fuzzer does not allow running a default set of tests as specified in the first bullet under “TCP Layer” in the project part 1 description.
  * Deduct 5 points if the fuzzer does not allow running a set of tests as specified in the second bullet under “TCP Layer” in the project part 1 description.
  * Deduct 5 points if the fuzzer does not allow running a default set of tests as specified in the first bullet under “Application Layer” in the project part 1 description.
  * Deduct 5 points if the fuzzer does not allow running a set of tests as specified in the second bullet under “Application Layer” in the project part 1 description.
  * Deduct 5 points if the fuzzer does not receive and process the server’s response when the server sends a response as specified in the 4th bullet under “Application Layer” in the project part 1 description.

#### Server
  * Deduct 2 points if the server does not read a hex pattern from a file.
  * Deduct 3 points if the server does not match pattern when the correct pattern is at the start of the payload.
  * Deduct 3 points if the server matches on payloads that do not begin with the correct pattern.
  * Deduct 2 points if the server does not send the appropriate response to the client.

### Program Error Handling (20 pts)
  * Test the fuzzer with invalid command line arguments for each command line argument in each usage case that requires command line arguments.
  * Test the fuzzer with missing and/or inaccessible files for the cases where the fuzzer reads from a file.
  * Test the fuzzer with invalid file contents for the cases where the fuzzer reads from a file.
  * Test the server with invalid command line arguments, if any.
  * Test the server with a missing and/or inaccessible pattern file.
  * Test the server with invalid file contents in the pattern file.

### Clarity of the Code/Comments (10 pts)
