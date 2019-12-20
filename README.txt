This script will try to create a TCP-handshake with the specified 
maschine and then send data using the established connection. 
Because the application is using raw sockets, the TCP-header and 
IP-header have to be added by the script as well. Note that this 
socket will wait for the client to close the connection. 
As the kernel is usually keeping track of sockets and ports, it 
will interrupt the attempt of creating a TCP-connection, by sending 
RST-packets to the other machine. Therefore, the kernel has to be 
prevented from doing so.

Prevent the kernel from sending RST-packets:
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

You can simply drop this rule, by running the following command:
$ sudo iptables -F

To compile the script just run:
$ bash ./build.sh

To use the tool, use the following command:
$ sudo ./bin/rawtcp <Src-IP> <Src-Port> <Dest-IP> <Dest-Port>

Note that a used port on the client-side is blocked for a short
amount of time. Therefore you have to change the port after every use,
to ensure functionality. Replace the <Src-Port> with the following
statement, to generate a random port every time you will run the
script: $(perl -e 'print int(rand(4444) + 1111)')