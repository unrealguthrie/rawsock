Prevent the kernal from sending RST-packets:
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

You can simply drop this rule, by running the following command:
$ sudo iptables -F

To compile the script just run:
$ make

To use the tool, run the following command:
$ sudo ./rawtcp <Src-IP> <Src-Port> <Dest-IP> <Dest-Port>
