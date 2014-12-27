#FTP Enum

FTP Enum is a tool designed to grab FTP banner's and attempt to log in anonymously.

This script was written out of necessity on my pen tests and to learn a little python.  You can grab a list of FTP servers with a quick nmap scan of a network.  Use Grep and cut to narrow down your list to just IPs then use that as an input file to ftp_enum.

##Software Requiremts
1. Just make sure you have python 2.7 installed

### Linux
1. Install python 2.7
2. python ftp_enum.py -h

### Windows
1. same thing ;)
