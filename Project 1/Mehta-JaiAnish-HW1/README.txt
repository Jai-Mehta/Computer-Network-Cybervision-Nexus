EXTERNAL LIBRARIES USED: dnspython
The library dnspython can be installed on windows os using the pip command as shown below:
pip3 install dnspython
Once the DNS python library will be installed, the code will run by following the steps below.


##############################################################################################################################################################################################################################

INSTRUCTION TO RUN THE PROGRAM for part A: 
To run the program, open the terminal in the folder Mehta-JaiAnish-HW1.
In the terminal type a line as shown below:
python mydig.py domain_name record_type

Instead of domain_name type the name of the domain for which you want to resolve the address.
Instead of record_type, type the record type for the respective domain name resolution.

EXAMPLE:
python mydig.py www.google.com A.

Following the above steps will print the output in the terminal.
The code also has a part to print the output in the mydig_output.txt file at the bottom. If desired to be run that way, it can be uncommented and run by changing the file names and respective record types in the code file.
!!!Please take care, running the code with the output in mydig_output.txt will overwrite or add new output to the mydig_output.txt file. thereby changing the originally submitted file.

###############################################################################################################################################################################################################################

INSTRUCTION TO RUN THE PROGRAM for part B: 
To run the program, open the terminal in the folder Mehta-JaiAnish-HW1.
In the terminal type a line as shown below:
python dnssec.py domain_name record_type

Instead of domain_name type the name of the domain for which you want to resolve the address.
Instead of record_type, type the "A".

EXAMPLE:
python mydig.py www.google.com A.

Following the above steps will print the output in the terminal.
The inputs can even be hardcoded into the program file.