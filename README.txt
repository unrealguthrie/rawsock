This script will create a TCP-handshake with the specified maschine
and then send the data using the established connection. Because
the application is using raw sockets, the TCP-header and IP-header
have to be added by the script aswell. As the kernel is usually
keeping track of sockets and ports, it will interrupt the attempt
of creating a TCP-connection, by sending RST-packets to the other
maschine. Therefore, the kernel has to be prevent from doing so.

Prevent the kernel from sending RST-packets:
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

You can simply drop this rule, by running the following command:
$ sudo iptables -F

To compile the script just run:
$ make

To use the tool, run the following command:
$ sudo ./rawtcp <Src-IP> <Src-Port> <Dest-IP> <Dest-Port>
