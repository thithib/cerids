# README #


DOCUMENTATION
-------------

The best documentation at this time is the code itself.


INSTALL
-------

To install, install both libpcre and libpcap, cd into the src
directory and run the make command.


USAGE
-----

At this time, the software only supports live capture and
prints back the hexadecimal value of the packets captured
on port 80.

To run cerIDS you must execute, as root, ./cerids -i <ifname>
where ifname is the name of the device to listen on.
