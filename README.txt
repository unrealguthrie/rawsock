This script will send a predefined message to a specified ip using raw 
socket. It creates a datagram with TCP/IP-headers and then sends it.
But as this script uses raw sockets, you have to run a command before. 
The kernal automatically sends RST-packets to the other maschine,
and therefore interrupts the TCP-handshake. To prevent that, you have
to run the following command, to stop the kernal from sending 
RST-apckets on it's own:
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

You can simply drop this rule, by simply running the following command:
$ sudo iptables -F

To compile the script just run:
$ make

To use the tool, run the following command: 
$ sudo ./rawtcp <Src-IP> <Src-Port> <Dest-IP> <Dest-Port>
