
import socket
from ftplib import FTP
import argparse
import sys

'''
Name: ftp_tool.py
Author: Jason Hill
Description:  This tool will take a single IP or a file containg a list of IPs and try to 
connect to each one and grab the banner.  It will then try to log into the FTP server Anonymously.
If it can log in it will attempt to list the root directory.  This was built to rummage through a list of 
FTP servers during a pentest.
'''


def ftplist(host):
    try:
        file_list = []
        ftp=FTP(host)
        ftp.login('anonymous','@anonymous')
        # set passive or sometimes it will hang when trying to grab list
        ftp.set_pasv("TRUE")
        ftp.retrlines('LIST', callback = file_list.append)
        return file_list
        ftp.quit()
    except:
        return False
        

def ftpconnect(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((host, 21))
        data = s.recv(2048)
        # return the data we grabbed and close the socket so it doesn't hang
        return data
        s.close()
    # some exceptions to handle, just in case   
    except socket.error:
        return 'socketError'
    except socket.timeout:
        return 'socketTimeout'
    except socket.gaierror:
        return 'wtf'

def getinfo(host,output_file_exists,oFile):

    connect_output = ftpconnect(host)
    if output_file_exists:
        if connect_output == 'socketError':
            oFile.write("*" * 64 + "\n[+] " + host)
            oFile.write("[-] Socket Error\n" + "*" * 64)
        elif connect_output == 'socketTimeout':
            oFile.write("*" * 64 + "\n[+] " + host)
            oFile.write("[-] Socket Timedout\n" + "*" * 64) 
        elif connect_output == 'wtf':
            oFile.write("*" * 64 + "\n[+] " + host)
            oFile.write("[-] Error Connecting\n" + "*" * 64)
        else:
            oFile.write("*" * 64)
            oFile.write("\n[+] " + host)
            oFile.write("\n[+] Success!")
            oFile.write("\n[+] " + connect_output)
            anon = ftplist(host)
            if anon:
                oFile.write("\n[+] Anonymous Login Allowed!\n")
                for item in anon:
                    oFile.write("[+] %s\n" % item)
                oFile.write("\n" + "*" * 64)
            else:
                oFile.write("\n[-] No ANON login\n")
    else:
        if connect_output == 'socketError':
            print("*" * 64 + "\n[+] " + host)
            print("[-] Socket Error\n" + "*" * 64)
        elif connect_output == 'socketTimeout':
            print("*" * 64 + "\n[+] " + host)
            print("[-] Socket Timedout\n" + "*" * 64)   
        elif connect_output == 'wtf':
            print("*" * 64 + "\n[+] " + host)
            print("[-] Error Connecting\n" + "*" * 64)
        else:
           
            print("*" * 64)
            print("\n[+] " + host)
            print("\n[+] Success!")
            print("\n[+] " + connect_output)
            anon = ftplist(host)
            if anon:
                print("\n[+] Anonymous Login Allowed!\n")
                for item in anon:
                    print("[+] %s" % item)
                print("\n" + "*" * 64)
            else:
                print("\n[-] No ANON login\n")


try:
    # Grab the command line arguments
    parser = argparse.ArgumentParser(description='Grab banner from an FTP server and attempt to connect Anonymously.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--ip_addr", help='single IP address')
    group.add_argument("-f", "--input_file", help='input file')
    parser.add_argument("-o", "--output_file", help='save output to file')
    args = parser.parse_args()

    # If at least -i or -f is not present then show usage and die
    if not args.ip_addr and not args.input_file:
        parser.print_help()
        sys.exit()

    # grab the ip from the arguments
    # need an error if the use supplies invalid ip or FQDN
    if args.ip_addr:
        host=''.join(args.ip_addr)
        # if there is a file to output to grab it here
        if args.output_file:
            # only way I could figure out how to break up file or single IPs
            output_file_exists = True
            # open output file for writing and send up to function
            with open(args.output_file,'w') as oFile:
                getinfo(host,output_file_exists,oFile)
            oFile.close()
            sys.exit()
        else:
            oFile = False
            output_file_exists = False
            getinfo(host,output_file_exists,oFile)
        
    # Grab the input file name from the arguments
    if args.input_file:
        num_of_lines = sum(1 for line in open(args.input_file))
        count = 0
        # if there is a file to output to grab it here
        if args.output_file:
            # see above for same comment, I'll figure it out later.
            output_file_exists = True
            print "[!] Writing output to %s" % args.output_file
            print "[!] Standby\n"
            with open(args.output_file,'w') as oFile:
                try:
                    with open(args.input_file) as f:
                        for line in f:
                            host = line.rstrip("\n")
                            count = count + 1
                            percentage = round(100 * float(count) / float(num_of_lines),0)
                            sys.stdout.write("\r%d%% Percent Complete!" % percentage)
                            sys.stdout.flush()
                            if not line.strip():
                                print ""
                            else:
                                getinfo(host,output_file_exists,oFile)
                    print "\n[!] Complete"
                    f.close()
                except IOError:
                    print "\n[!] Check your file and try again\n"
                    print "[!] Exiting...\n"
                    sys.exit()
            oFile.close()
        else:
            output_file_exists = False
            oFile = False
            with open(args.input_file) as f:
                for line in f:
                    host = line.rstrip("\n")
                    if not line.strip():
                        print ""
                    else:
                        getinfo(host,output_file_exists,oFile)

except KeyboardInterrupt:
    print "\n\n[!] Exiting...\n"
    if oFile:
        oFile.close()
    if f:
        f.close()
    sys.exit()


