#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Nov 11 09:32:10 2021

@author: eusebio

https://pawelgrzes.pl/security/mikrotik-blocking-unwanted-connections-with-external-ip-list/
https://github.com/firehol/blocklist-ipsets
https://web.uvic.ca/~infosec/blocklists/
https://www.threatshub.org/download/
http://www.blocklist.de/en/export.html

/ip firewall filter add chain=input action=drop connection-state=new src-address-list=eusebio-blacklist in-interface=wan1
/ip firewall address-list print
/import file-name=blacklist.rsc
"""

import sys,os,re,time,multiprocessing,itertools,netaddr,datetime,pwd,grp,socket,pickle
from urllib.parse import urlparse
import requests
import numpy as np 
from multiprocessing import Pool
from subprocess import PIPE, Popen
from functools import partial
import pandas as pd

# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


#%%

Debug=True
if Debug: StartTime = time.time()
NumCores=multiprocessing.cpu_count()
Directorio=os.path.dirname(os.path.realpath('__file__'))
MainDirectory="/opt/BlackList"
TmpDirectory=os.path.join(MainDirectory,"Temp")
PkDirectory=os.path.join(MainDirectory,"PK")
BlackListFile=os.path.join(MainDirectory,"blacklist.rsc")
BlackListAdsFile=os.path.join(PkDirectory,"blacklistads.pk")

#########################################
###########       Get BlackList
#########################################

BlockIps = [{"url":"https://www.dshield.org/block.txt","WithoutDns":True,"IpRange":True},
            {"url":"https://lists.blocklist.de/lists/all.txt"},
            {"url":"https://lists.blocklist.de/lists/bots.txt"},
            {"url":"https://lists.blocklist.de/lists/strongips.txt"},
            {"url":"https://lists.blocklist.de/lists/apache.txt"},
            {"url":"https://lists.blocklist.de/lists/ssh.txt"},
            {"url":"https://lists.blocklist.de/lists/bruteforcelogin.txt"},
            {"url":"http://www.blocklist.de/lists/bruteforcelogin.txt"},
            {"url":"http://cinsscore.com/list/ci-badguys.txt"},
            {"url":"http://infosec.uvic.ca/blocklists/spamhaus-drop"},
            {"url":"http://infosec.uvic.ca/blocklists/spamhaus-edrop"},
            {"url":"http://infosec.uvic.ca/blocklists/dshield"},
            {"url":"https://bitbucket.org/threatshub/th-dfbase/raw/master/data/blacklist-ip/ThreatsHub_Blacklist-ip_DataFeed"},
            {"url":"http://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
            {"url":"http://www.dshield.org/ipsascii.html?limit=10000"},
            {"url":"https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"},
            {"url":"http://www.binarydefense.com/banlist.txt"},
            {"url":"https://www.spamhaus.org/drop/drop.txt"},
            {"url":"https://www.spamhaus.org/drop/edrop.txt"},
            {"url":"https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/blob/master/ips/ips0.list?raw=true"},
            {"url":"https://github.com/stamparm/ipsum/blob/master/ipsum.txt?raw=true"},
            {"url":"https://www.matthewroberts.io/api/threatlist/latest"},
            {"url":"https://reputation.alienvault.com/reputation.generic"},
            {"url":"https://raw.githubusercontent.com/tg12/bad_packets_blocklist/master/bad_packets_list.txt"},
            {"url":"https://github.com/firehol/blocklist-ipsets/blob/master/malwaredomainlist.ipset"},
            {"url":"https://github.com/firehol/blocklist-ipsets/blob/master/dshield_top_1000.ipset"},
            {"url":"https://github.com/firehol/blocklist-ipsets/blob/master/alienvault_reputation.ipset"},
            {"url":"https://raw.githubusercontent.com/firehol/blocklist-ipsets/d11704a705c314baa17668225c0cb23382f496f4/firehol_webclient.netset"},
            {"url":"https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Malware/Browser"},
            {"url":"https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Malware/Hackers"},
            {"url":"https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Malware/Hosting"},
            {"url":"https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/BruteForce/Extreme"},
            {"url":"https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/BruteForce/High"},
            {"url":"https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/BruteForce/Low"},
            {"url":"https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/BruteForce/Medium"}]

BlockAdsDns=[{"url":"https://adaway.org/hosts.txt"},
             {"url":"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
             {"url":"https://raw.githubusercontent.com/pantsufan/Magisk-Ad-Blocking-Module/master/hosts"}]

# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
######################################
##
##             Functions
##
######################################

def StrFechaDatetime(Fecha=datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'),
                     Year=datetime.datetime.now().strftime('%Y'),
                     OnlyDate=True,
                     DiaEnFinal=False):
    
    if type(Fecha) is str:
        if len(Fecha) > 10:
            Troceado=Fecha.split(" ")
            Date=Troceado[0]
            Time=Troceado[1]
        else:
            Date=Fecha
            Time=None
        
        if "/" in Date:
            Troceado=Date.split("/")
        elif "-" in Date:
            Troceado=Date.split("-")
        elif "_" in Date:
            Troceado=Date.split("_")
        else:
            print("No puedo Trocear la fecha")
            return None
        
        if len(Troceado)==3:
            if len(Troceado[0])==4:
                FechaSalida=datetime.datetime(int(Troceado[0]),int(Troceado[1]),int(Troceado[2]),0,0,0)
            else:
                FechaSalida=datetime.date(int(Troceado[2]),int(Troceado[1]),int(Troceado[0]))
        else:
            if int(Troceado[0])>2000:
                FechaSalida=datetime.datetime(int(Troceado[0]),int(Troceado[1]),1,0,0,0)
            else:
                if DiaEnFinal or int(Troceado[1])>12:
                    FechaSalida=datetime.datetime(int(Year),int(Troceado[0]),int(Troceado[1]),0,0,0)
                else:
                    FechaSalida=datetime.datetime(int(Year),int(Troceado[1]),int(Troceado[0]),0,0,0)
            
        if OnlyDate and type(FechaSalida) is not datetime.date: FechaSalida=FechaSalida.date()
                
        if  not OnlyDate and Time is not None:
            Troceado=Time.split(":")
            FechaSalida=FechaSalida.replace(hour=int(Troceado[0]), minute=int(Troceado[1]), second=int(Troceado[2]))
            return FechaSalida
        else:
            return FechaSalida
    
    elif type(Fecha) is datetime.datetime:
        if OnlyDate:
            return Fecha.strftime('%Y/%m/%d')
        else:
            return Fecha.strftime('%Y/%m/%d %H:%M:%S')
    elif type(Fecha) is datetime.date:
        return Fecha.strftime('%Y/%m/%d')
    elif type(Fecha) is pd.Timestamp:
        return StrFechaDatetime(str(Fecha).split()[0])
    
    return None

if False:
    FechaInicio=StrFechaDatetime("2021-11-19 17:00:00",OnlyDate=False)
    FechaInicio-datetime.timedelta(weeks=1)

def CheckDirectorios(Directorios):
    if type(Directorios) is not list:
        Directorios=[Directorios]
    for Directorio in Directorios:
        Directorio_way=os.path.join(Directorio,"")
        if not os.path.exists(os.path.dirname(Directorio_way)):
            os.makedirs(Directorio_way)
            
def PrintTimeLog(Text,StartTime,FinishTime=None):
    if FinishTime is None:
        FinishTime = time.time()
    Hours,Rem=divmod(FinishTime-StartTime,3600)
    Minutes, Seconds=divmod(Rem,60)
    print(Text+" Tiempo Transcurrido: {:0>2}:{:0>2}:{:0.2f}".format(int(Hours),int(Minutes),Seconds), flush=True, file=sys.stdout)

def cmdline(command,shell=True,sub=False):
    if not sub:
        process = Popen(args=command,
                        stdout=PIPE,
                        shell=shell)
        return process.communicate()[0]
    else:
        process = Popen(args=command.split(),
                        stdout=PIPE,
                        shell=False)
        return process

def GetWhiteIpList():
    WebsValidas=["81.88.52.114","209.2.64.196"]
    #https://www.lifewire.com/what-is-the-ip-address-of-google-818153
    GoogleRange=["64.233.160.0-64.233.191.255","66.102.0.0-66.102.15.255","66.249.64.0-66.249.95.255","72.14.192.0-72.14.255.255","74.125.0.0-74.125.255.255",
                 "209.85.128.0-209.85.255.255","216.239.32.0-216.239.63.255","64.18.0.0-64.18.15.255","108.177.8.0-108.177.15.255","172.217.0.0-172.217.31.255",
                 "173.194.0.0-173.194.255.255","207.126.144.0-207.126.159.255","216.58.192.0-216.58.223.255"]
    Important=["46.24.51.75","95.63.181.112","149.154.167.220","185.73.172.0/24"]
    DnsServers=["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4"]
    White=["127.0.0.1","0.0.0.0","192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"]+DnsServers+WebsValidas+Important+GoogleRange
    WhiteList=netaddr.IPSet()
    for WhiteIp in White:
        if "-" in WhiteIp:
            IpsLimpias=WhiteIp.split("-")
            WhiteList.add(netaddr.IPRange(str(IpsLimpias[0]).strip(),str(IpsLimpias[1]).strip()))
        elif "/" in WhiteIp:
            WhiteList.add(netaddr.IPNetwork(WhiteIp))
        else:
            WhiteList.add(netaddr.IPAddress(WhiteIp))
    return WhiteList

def GetIpsFromAdsDns(Urls,Force=False,FirstPk=True,AsNetAddr=False):
    AddAdsIps=["tpc.googlesyndication.com","adservice.google.com","static.adsafeprotected.com","cdn.adsafeprotected.com","securepubads.g.doubleclick.net","an.yandex.ru","relap.io","static.criteo.net"]
    AddAdsIps=ThreadIps(AddAdsIps,AsNetAddr=AsNetAddr)
    
    if Force or not os.path.exists(BlackListAdsFile):
        AdsTotales=GetIpsFromDictUrls(Urls,FirstPk=FirstPk,AsNetAddr=AsNetAddr)
        
        with open(BlackListAdsFile, 'wb') as AdsFile:
            pickle.dump(AdsTotales, AdsFile)
    else:
        with open(BlackListAdsFile, 'rb') as AdsFile:
            AdsTotales = pickle.load(AdsFile)
    
    AdsTotales=AddAdsIps+AdsTotales
    return AdsTotales
    
def ToupleToList(Inputs):
    Salida=list()
    for Input in Inputs:
        if type(Input) is tuple:
            for Inp in Input:
                if Inp != '' and Inp[-1]!=".":
                    Salida.append(Inp)
    return Salida

def GetHostFromText(Texts):
    Salida=list()
    if type(Texts) is not list:
        Texts=Texts.split()
    for Text in Texts:
        try:
            Ip=socket.gethostbyname(Text)
            if Ip!=Text:
                Salida.append(Ip)
        except:
            pass
    return Salida

def GetIpsFromText(Text,WithoutDns=False,AsNetAddr=False,Debug=False):
    IpSalida=list()
    RegIp=r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/\d{1,2})?'
    RegDns=r"((localhost)|((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,253})"
    Ips=ToupleToList(re.findall(RegIp,Text.strip()))
    if len(Ips)==2 and Ips[1].startswith("/"):
        Ips=["".join(Ips)]
        
    if not WithoutDns:
        Dns=GetHostFromText(ToupleToList(re.findall(RegDns,Text.strip())))
    else:
        Dns=[]
    IpsInText=Ips+Dns
    for Ip in IpsInText:
        try:
            if "/" not in Ip: 
                if AsNetAddr:
                    IpSalida.append(netaddr.IPAddress(Ip))
                else:
                    IpSalida.append(Ip)
            else:
                if AsNetAddr:
                    IpSalida.append(netaddr.IPNetwork(Ip))
                else:
                    IpSalida.append(Ip)
        except:
            if Debug: print("GetIpsFromText:: Len='"+str(len(Ip))+"' Ip='"+str(Ip)+"'", flush=True, file=sys.stdout)
            pass
    return IpSalida

def ThreadIps(Text,WithoutDns=False,IpRange=False,Parameters=None,NetworkToListIps=False,AsNetAddr=True,Debug=False):
    IpsSalida=list()
    
    if type(Text) not in [list,np.ndarray]:
        Text=Text.split("\n")
        
    if type(Parameters) is dict:
        if "WithoutDns" in Parameters.keys():
            WithoutDns=Parameters["WithoutDns"]
        if "IpRange" in Parameters.keys():
            IpRange=Parameters["IpRange"]
        if "AsNetAddr" in Parameters.keys():
            AsNetAddr=Parameters["AsNetAddr"]
        
    for Line in Text:
        if Line!='' and Line[0] not in ["#",":"]:
            IpsLimpias=GetIpsFromText(Line,WithoutDns=WithoutDns,AsNetAddr=AsNetAddr)
            if not AsNetAddr:
                IpsLimpias=sorted(list(set(IpsLimpias)-set(['0.0.0.0','127.0.0.1'])))
            if IpRange and len(IpsLimpias)==2:
                RangoIps=[ip for ip in netaddr.IPRange(str(IpsLimpias[0]),str(IpsLimpias[1]))]
                if not AsNetAddr:
                    RangoIps=list(map(str,RangoIps))
                if Debug: print("ThreadIps::IpRange:: IpsLimpias='"+str(IpsLimpias)+"' len='"+str(len(RangoIps))+"'", flush=True, file=sys.stdout)
                for ip in RangoIps:
                    if ip not in IpsSalida and ip not in WhiteList:
                        IpsSalida.append(ip)
            else:
                for LocalIp in IpsLimpias:
                    if NetworkToListIps: #and type(LocalIp) is netaddr.ip.IPNetwork
                        if AsNetAddr:
                            LocalIps=list(netaddr.IPNetwork(LocalIp))
                        else:
                            LocalIps=list(map(str,netaddr.IPNetwork(LocalIp)))
                    else:
                        LocalIps=[LocalIp]
                    for ip in LocalIps:
                        if ip not in IpsSalida and ip not in WhiteList:
                            IpsSalida.append(ip)
                if Debug: print("ThreadIps:: IpsLimpias len='"+str(len(IpsLimpias))+"'", flush=True, file=sys.stdout)
    return IpsSalida

def GetIpsFromDictUrls(Urls,FirstPk=False,AsNetAddr=True,Debug=True):
    IpsLocalesCount=0
    IpsTotales = list()
    session = requests.Session()
    session.headers['User-Agent']='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
    for url in Urls:
        if Debug: StartTimeChunk = time.time()
        Parse=urlparse(url["url"])
        UrlParsed=(Parse.netloc.replace(".","_")+"_"+Parse.path.split("/")[-1]).replace(".","_")
        UrlParsedPk=os.path.join(PkDirectory,UrlParsed+".pk")
        
        if FirstPk and os.path.exists(UrlParsedPk):
            with open(UrlParsedPk, 'rb') as File:
                IpsLocales = pickle.load(File)
                IpsTotales.append(IpsLocales)
                if Debug: PrintTimeLog("Chunk FirstPk ("+str(len(IpsLocales))+") UrlParsed '"+UrlParsed+"'",StartTimeChunk)
            continue

        try:
            response = session.get(url["url"],verify=True, timeout=20)
        except Exception as error:
            print("Not retrieved because "+str(error)+" URL: '"+str(url["url"])+"'")
            if os.path.exists(UrlParsedPk):
                with open(UrlParsedPk, 'rb') as File:
                    IpsLocales = pickle.load(File)
                    IpsTotales.append(IpsLocales)
                    if Debug: PrintTimeLog("Chunk Http From PK ("+str(len(IpsLocales))+") UrlParsed '"+UrlParsed+"'",StartTimeChunk)
            continue

        Ips=response.text
        IpsSplit=Ips.split("\n")
        Parameters=dict()
        if "WithoutDns" in url.keys():
            Parameters["WithoutDns"]=url["WithoutDns"]
        if "IpRange" in url.keys():
            Parameters["IpRange"]=url["IpRange"]
        Parameters["AsNetAddr"]=AsNetAddr
        
        if len(IpsSplit)>1000:
            Procesos=Pool(NumCores).map(partial(ThreadIps, Parameters=Parameters), np.array_split(IpsSplit, NumCores))
            IpsLocales=list((itertools.chain.from_iterable(Procesos)))
            IpsLocalesCount=IpsLocalesCount+len(IpsLocales)
            IpsTotales.append(IpsLocales)
        else:
            IpsLocales=list(ThreadIps(IpsSplit,Parameters=Parameters))
            IpsLocalesCount=IpsLocalesCount+len(IpsLocales)
            IpsTotales.append(IpsLocales)
        
        if os.path.exists(UrlParsedPk):
            os.remove(UrlParsedPk)
        
        with open(UrlParsedPk, 'wb') as File:
            pickle.dump(IpsLocales, File)
        
        if Debug: PrintTimeLog("Chunk Http ("+str(len(IpsLocales))+") UrlParsed '"+UrlParsed+"'",StartTimeChunk)
    
    if Debug: PrintTimeLog("Webs Procesadas='"+str(len(IpsTotales))+"' Count='"+str(IpsLocalesCount)+"'",StartTime)
    
    IpsTotales=netaddr.IPSet(itertools.chain(*IpsTotales))
    
    return IpsTotales

# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
######################################
##
##             MAIN
##
######################################
    
if __name__ == '__main__':
   
    CheckDirectorios([PkDirectory,TmpDirectory])
    os.chdir(TmpDirectory)
    if os.path.exists(BlackListFile):
        os.remove(BlackListFile)
    
    #####################################
    #######       Leo Ips de las Webs
    #####################################
    if Debug: StartTimeChunk = time.time()
    AsNetAddr=True
    WhiteList=GetWhiteIpList()
    IpsTotales=GetIpsFromDictUrls(BlockIps,AsNetAddr=AsNetAddr)
    IpsTotalesAds=netaddr.IPSet(GetIpsFromAdsDns(BlockAdsDns,Force=False,FirstPk=True,AsNetAddr=AsNetAddr))
    IpsTotales.update(IpsTotalesAds)

    #%%
    #sys.exit(0)
    #####################################
    #######        Paso a IpSet
    #####################################
    if Debug: PrintTimeLog("Chunk Paso a IpSet IpsTotales='"+str(len(IpsTotales))+"'",StartTimeChunk)

    #####################################
    #######        Compacto IpSet
    #####################################
    if Debug: StartTimeChunk = time.time()
    _=IpsTotales.compact()
    Cidr=[Range for Range in IpsTotales.iter_cidrs()]
    if Debug: PrintTimeLog("Chunk Compacto Cidr='"+str(len(Cidr))+"'",StartTimeChunk)
    
    #####################################
    #######    Generate Blacklist File
    #####################################
    if Debug: StartTimeChunk = time.time()
    Fecha=datetime.datetime.now().strftime('%Y %B %d %H:%M:%S')
    with open(BlackListFile, 'w+') as File:
        File.write("# Generated on "+Fecha+"\n")
        File.write("/ip firewall address-list\n")
        for Ip in Cidr:
            IpRangeSplit=str(Ip).split("/")
            if IpRangeSplit[1] == "32":
                File.write("add list=eusebio-blacklist address="+str(IpRangeSplit[0])+"\n")
            else:
                File.write("add list=eusebio-blacklist address="+str(Ip)+"\n")
    if Debug: PrintTimeLog("Chunk Fichero BlackList='"+str(len(Cidr))+"'",StartTimeChunk)
    
    #####################################
    #######    Asigno Permisos Al BlackList
    #####################################
    try:
        #sudo chown www-data.www-data /opt/BlackList/blacklist.rsc
        uid=pwd.getpwnam("www-data").pw_uid
        gid=grp.getgrnam("www-data").gr_gid
        os.chown(BlackListFile, uid, gid)
    except:
        print("Error de Permisos")
        pass

    if Debug: PrintTimeLog("Total Procesado ='"+str(len(Cidr))+"'",StartTime)
