README 
=====

Documentation
--------------

You can find the documentation at doc/html/index.html or doc/latex/refman.pdf.


Installation
------------

Clone the git repository:


`$ git clone <bitbuckCerids> cerids`


To install CerIDS on a Debian stable (jessie) host, you must install the 
following packages :


`$ apt install build-essential libpcap-dev libpcre3-dev`


Then, cd to the source directory and run make


`$ cd src/ && make`


USAGE
-----

To listen on the eth0 interface, launch cerids as root with this command:


`# ./cerids -i eth0`


To enable the debug mode (no background, messages to stdout):


`# ./cerids -i eth0 -d`


To run on a pcap file (for instance, example.pcap):


`# ./cerids -f example.pcap`


To get some help:


`# ./cerids -h`
