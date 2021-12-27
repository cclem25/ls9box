#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This library is free software
you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License aspublished by the  Free Software Foundation either version 2.1 of theLicense, or any later version.

This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along with this library if not, write to the Free Software Foundation, 
Inc., 
59 Temple Place, 
Suite 330, 
Boston, 
MA 02111-1307
USA

Copyright 2013 Clement MILLET
"""

__version__ = u"$ 0.4.3212.1 $"
__author__ = u"Clement MILLET <contact@ls9box.fr>"
__copyright__ = u"(C) 2013 - Clement MILLET"
__license__ = u"GNU GPL 2"
__revision__ = u"$Revision: 5 $"
__date__ = u"$Date: 2013-01-20 12:20:31 +0100 (dim., 20 janv. 2013) $"
__lastchangedby__ = "$Author: C. Millet $"


import httplib
import popen2
import re
import socket
import urllib
import urllib2
import xml.dom
import time
import datetime
import hashlib
import hmac
import getpass
from hashlib import sha256
from xml.dom.minidom import parseString


class NeufBox:
    """Lecture des données de la NeufBox 4"""

    #_DEFAULT_CGI_CMD = "/api/"
    #_DEFAULT_CGI_VAR = "method"
    #_DEFAULT_CGI_METHOD = "POST"
    _DEFAULT_IP = "192.168.1.1"
    _DEFAULT_CGI_PORT = "80"
    _DEFAULT_CGI_HEADERS = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
    _HTTP_TIMEOUT = 1.0
    _PINGCMD = "ping -q -c 1 -W 1 %s"
    _PINGRE = "(\d*) packets transmitted, (\d)* received, (\d)% packet loss"

    def __init__(self, ipaddr = _DEFAULT_IP, hashtag = "hashdeconnexion"):
        self.ipaddr = ipaddr
        self.hashtag = hashtag
        self.conn = None

    def set_box_lanipaddr(self, ipaddr = _DEFAULT_IP):
        """Spécifier l'adresse IP LAN"""
        self.__init__(ipaddr)

    def get_box_lanipaddr(self):
        """Obtenir l'adresse IP LAN"""
        return self.ipaddr

    def isready(self):
        """Renvoie True si la Neufbox répond aux requêtes"""
        try:
            ipbox = self.get_public("lan.getInfo")
            if not ipbox['ip_addr'] == self.ipaddr:
                return False
            else:
                return True
        except Exception:
            return False

    def isonlan(self):
        """Renvoie True si la Neufbox est accessible sur le réseau"""
        try:
            fout, fin = popen2.popen4(NeufBox._PINGCMD % self.ipaddr)
            outlines = fout.readlines()
            fout.close()
            fin.close()
        except Exception:
            if __debug__:
                raise
            return False
        for line in outlines:
            mobj = re.match(NeufBox._PINGRE, line)
            if not mobj == None:
                rest = mobj.groups()
                if len(rest) == 3 and rest[0] == rest[1]:
                    return True
        return False

    #########         Méthode GET Public        ############

    def get_status(self):
        """Renvoie le status principal de la NeufBox"""
        try:
            chaine  = self.get_ppp_info()
            chaine += u"Uptime 9box:\t"+self.uptime(int(self.get_public("system.getInfo")['uptime']))+"\n"
            chaine += u"Uptime adsl:\t"+self.uptime(int(self.get_public("dsl.getInfo")['uptime']))+"\n"
            chaine += u"Uptime wan:\t"+self.uptime(int(self.get_public("wan.getInfo")['uptime']))+"\n"
            return chaine
        except Exception:
            return u"Erreur status"

    def get_wan_info(self):
        """Renvoie le status de la connexion internet uptime infra(adsl)"""
        try:
            wanInfo = self.get_public("wan.getInfo")
            temps = int(wanInfo['uptime'])
            chaine  = u"Status ligne:\t"+wanInfo['status']+"\n"
            chaine += u"Uptime ADSL:\t"+self.uptime(temps)+"\n"
            chaine += u"IP externe:\t"+wanInfo['ip_addr']+"\n"
            chaine += u"Connexion:\t"+wanInfo['infra']+"\n"
            return chaine
        except Exception:
            return u"Erreur wan"

    def get_system_info(self):
        """Renvoie les informations sur la box, version firmware..."""
        try:
            sysInfo = self.get_public("system.getInfo")
            temps = int(sysInfo['uptime'])
            chaine  = u"ID du produit:\t"+sysInfo['product_id']+"\n"
            chaine += u"Adresse mac:\t"+sysInfo['mac_addr']+"\n"
            chaine += u"Box mode:\t"+sysInfo['net_mode']+"\n"
            chaine += u"Net mode:\t"+sysInfo['net_infra']+"\n"
            chaine += u"Uptime Box:\t"+self.uptime(temps)+"\n"
            chaine += u"Firmware:\t"+sysInfo['version_mainfirmware']+"\n"
            chaine += u"Firm secours:\t"+sysInfo['version_rescuefirmware']+"\n"
            chaine += u"Bootloader:\t"+sysInfo['version_bootloader']+"\n"
            chaine += u"Dsl driver:\t"+sysInfo['version_dsldriver']+"\n"
            if "current_datetime" in sysInfo.keys():
                chaine += u"Date:\t\t"+str(datetime.datetime(int(sysInfo['current_datetime'][0:4]),int(sysInfo['current_datetime'][4:6]),int(sysInfo['current_datetime'][6:8]),int(sysInfo['current_datetime'][8:10]),int(sysInfo['current_datetime'][10:12])))+"\n"
                if len(sysInfo['refclient']) > 0:
                    chaine += u"Référence client:\t"+sysInfo['refclient']+"\n"
            return chaine
        except Exception:
            return u"Erreur informations système"

    def get_ppp_info(self):
        """Renvoie les informations sur le lien établi"""
        try:
            pppInfo = self.get_public("ppp.getInfo")
            chaine  = u"Lien adsl:\t"+pppInfo['status']+"\n"
            chaine += u"IP externe:\t"+pppInfo['ip_addr']+"\n"
            return chaine
        except Exception:
            return u"Erreur ppp info"

    def get_ont_info(self):
        #firm 3.2.1
        # Vérifier et améliorer la fonction avec une box fibre
        """Renvoie l'état de l'adaptateur ONT (fibre/cuivre) pour ceux qui en possèdent"""
        try:
            ontInfo = self.get_public("ont.getInfo")
            return self.toString(ontInfo)
        except Exception:
            return u"Firmware > 3.2.1"

    def get_dsl_info(self):
        """Renvoie l'état de la synchro adsl uptime noise"""
        try:
            dslInfo = self.get_public("dsl.getInfo")
            temps = int(dslInfo['uptime'])
            chaine  = u"Connexion:\t"+dslInfo['linemode']+"\n"
            chaine += u"Uptime:\t\t"+self.uptime(temps)+"\n"
            chaine += u"Nb connexions:\t"+dslInfo['counter']+"\n"
            chaine += u"Nb err crc:\t"+dslInfo['crc']+"\n"
            chaine += u"Status du lien:\t"+dslInfo['status']+"\n"
            chaine += u"Bruit desc:\t"+dslInfo['noise_down']+" dB\n"
            chaine += u"Bruit montant:\t"+dslInfo['noise_up']+" dB\n"
            chaine += u"Att. desc.:\t"+dslInfo['attenuation_down']+" dB\n"
            chaine += u"Att. up:\t"+dslInfo['attenuation_up']+" dB\n"
            chaine += u"Débit desc.:\t"+dslInfo['rate_down']+" kbits/s\n"
            chaine += u"Débit up:\t"+dslInfo['rate_up']+" kbits/s\n"
            return chaine
        except Exception:
            return u"Erreur dsl info"

    def get_lan_info(self):
        """Renvoie l'état du réseau local"""
        try:
            lanInfo = self.get_public("lan.getInfo")
            chaine  = u"Adresse IP box:\t"+lanInfo['ip_addr']+"\n"
            chaine += u"Masque réseau:\t"+lanInfo['netmask']+"\n"
            chaine += u"Etat dhcp:\t"+lanInfo['dhcp_active']+"\n"
            chaine += u"IP de debut:\t"+lanInfo['dhcp_start']+"\n"
            chaine += u"IP de fin:\t"+lanInfo['dhcp_end']+"\n"
            chaine += u"Refresh IP:\t"+lanInfo['dhcp_lease']+"\n"
            return chaine
        except Exception:
            return u"Erreur lan info"

    def get_lan_hostlist(self):
        #firm 3.2.0
        """Renvoie la liste des machine connectés en local"""
        try:
            lanHostList = self.get_public("lan.getHostsList")
            chaine = ""
            for index in range(0, len(lanHostList)):
                chaine += u"Nom de machine:\t"+lanHostList[index]['name']+"\n"
                chaine += u"Status:\t\t"+lanHostList[index]['status']+"\n"
                chaine += u"Materiel:\t"+lanHostList[index]['type']+"\n"
                chaine += u"Interface: \t"+lanHostList[index]['iface']+"\n"
                chaine += u"Adresse IP:\t"+lanHostList[index]['ip']+"\n"
                chaine += u"Adesse Mac:\t"+lanHostList[index]['mac']+"\n"
                chaine += u"Découverte:\t"+lanHostList[index]['probe']+"\n"
                chaine += u"Tps connexion:\t"+self.uptime(int(lanHostList[index]['alive']))+"\n\n"
            return chaine
        except Exception:
            return u"Firmware > 3.2.0"

    def get_lan_dnslist(self):
        #firm 3.2.0
        """Renvoie la liste des entrées DNS"""
        try:
            dnsHostList = self.get_public("lan.getDnsHostList")
            chaine = ""
            if "name" in dnsHostList.keys():
                chaine += u"nom d\'hote:\t"+dnsHostList['name']+"\n"
                chaine += u"ip machine:\t"+dnsHostList['ip']+"\n"
            else:
                for index in range(0, len(dnsHostList)):
                    chaine += u"nom d\'hote:\t"+dnsHostList[index]['name']+"\n"
                    chaine += u"ip machine:\t"+dnsHostList[index]['ip']+"\n\n"
            return chaine
        except Exception:
            return u"Firmware > 3.2.0"

    def get_smb_info(self):
        #firm 3.2.1
        #Problème de compatibilité XML à tester avec des partages actifs !
        """Renvoie l'état du partage de fichier"""
        try:
            smbInfo = self.get_public("smb.getInfo")
            chaine  = u"Etat:\t\t"+smbInfo['active']+"\n"
            chaine += u"Status:\t\t"+smbInfo['status']+"\n"
            chaine += u"Nom du partage:\t"+smbInfo['name']+"\n"
            chaine += u"Groupe réseau:\t"+smbInfo['workgroup']+"\n"
            return chaine
        except Exception:
            return u"Firwmare > 3.2.1"

    def get_print_info(self):
        #firm 3.2.1
        """Renvoie l'état du partage d'imprimante"""
        try:
            printInfo = self.get_public("p910nd.getInfo")
            chaine  = u"Status:\t\t"+printInfo['status']+"\n"
            chaine += u"Bidirectionnel:\t"+printInfo['bidir']+"\n"
            return chaine
        except Exception:
            return u"Firmware > 3.2.1"
        
    #########         Méthode GET Pivées        ############

    def get_ddns_info(self):
        #firm 3.2.0
        """Renvoie l'état du service de dns dynamique"""
        try:
            ddnsInfo = self.get_prive("ddns.getInfo")
            if "domain" in ddnsInfo.keys():
                chaine  = u"Status:\t\t"+ddnsInfo['active']+"\n"
                chaine += u"Etat:\t\t"+ddnsInfo['status']+"\n"
                chaine += u"Identifiant:\t"+ddnsInfo['username']+"\n"
                chaine += u"Mot de passe:\t*********\n"
                chaine += u"Service:\t"+ddnsInfo['service']+"\n"
                chaine += u"Domaine:\t"+ddnsInfo['domain']+"\n"
                chaine += u"Mise à jour:\t"+self.uptime(int(ddnsInfo['lastupdate']))+"\n"
                chaine += u"Ip:\t\t"+ddnsInfo['lastupdateip']+"\n"
                if "lastfreeze" in ddnsInfo.keys() and not ddnsInfo['lastfreeze'] == "" :
                    chaine += u"Last freeze:\t"+ddnsInfo['lastfreeze']+"\n"
                    chaine += u"Durée gel:\t"+ddnsInfo['lastfreezetime']+"\n"

                return chaine
            elif "msg" in ddnsInfo.keys():
                return u"Veuillez vous connecter\n"
            else:
                return u"Firmware > 3.2.0\n"
        except Exception:
                return u"Erreur DynDns\n"

    def get_wlan_info(self):
        """Renvoie l'état du wifi privé"""
        try:
            wlanInfo = self.get_prive("wlan.getInfo")
            if 0 in wlanInfo.keys():
                chaine  = u"Etat:\t\t"+wlanInfo[0]['active']+"\n"
                chaine += u"Filtrage Mac:\t"+wlanInfo[0]['mac_filtering']+"\n"
                chaine += u"Mode:\t\t"+wlanInfo[0]['mode']+"\n"
                chaine += u"Cannal:\t\t"+wlanInfo[0]['channel']+"\n"
                chaine += u"SSID:\t\t"+wlanInfo['wl0']['ssid']+"\n"
                chaine += u"Codage:\t\t"+wlanInfo['wl0']['keytype']+"\n"
                chaine += u"Chiffrement:\t"+wlanInfo['wl0']['enc']+" ("+wlanInfo['wl0']['enctype']+")\n"
                chaine += u"Clef Wifi:\t"+wlanInfo['wl0']['wpakey']+wlanInfo['wl0']['wepkey']+"\n"
                return chaine
            elif "msg" in wlanInfo.keys():
                return u"Veuillez vous connecter\n"
            else:
                return "Erreur wifi"
        except Exception:
                return u"Erreur wifi\n"

    def get_wlan_client_list(self):
        """Renvoie la liste des client wifi privé si celui-ci est activé"""
        wlan = self.get_prive("wlan.getInfo")
        try:
            if wlan[0]['active'] == "on":
                wlanClientList = self.get_prive("wlan.getClientList")
                chaine = ""
                if "ip_addr" in wlanClientList.keys():
                    chaine += u"Adresse IP:\t"+wlanClientList['ip_addr']+"\n"
                    chaine += u"Adresse Mac:\t"+wlanClientList['mac_addr']+"\n"
                elif 0 in wlanClientList.keys():
                    for index in range(0, len(wlanClientList)):
                        chaine += u"Adresse IP:\t"+wlanClientList[index]['ip_addr']+"\n"
                        chaine += u"Adresse Mac:\t"+wlanClientList[index]['mac_addr']+"\n"
                else:
                    return u"Aucun périphérique connecté\n"
            else:
                chaine = u"Vous devez activer le wifi pour voir les matériels connectés\n"
            return chaine
        except Exception:
            return u"Veuillez vous connecter (ls9box --connect)\n"

    def get_hotspot_info(self):
        """Renvoie l'état du hotspot"""
        try:
            hotspotInfo = self.get_prive("hotspot.getInfo")
            if "enabled" in hotspotInfo.keys():
                chaine  = u"Status:\t\t"+hotspotInfo['enabled']+"\n"
                chaine += u"Liaison:\t"+hotspotInfo['status']+"\n"
                chaine += u"Service:\t"+hotspotInfo['mode']+"\n"
                return chaine
            elif "msg" in hotspotInfo.keys():
                return u"Veuillez vous connecter\n"
            else:
                return u"Erreur hotspot\n"
        except Exception:
                return u"Erreur hotspot\n"

    def get_hotspot_client_list(self):
        """Renvoie la liste des client connecté au hotspot si celui-ci est activé"""
        hotspot = self.get_prive("hotspot.getInfo")
        try:
            hotspotClientList = self.get_prive("hotspot.getClientList")
            chaine = ""
            if hotspot['enabled'] == "on":
                #print hotspotClientList
                if "ip_addr" in hotspotClientList.keys():
                    chaine += u"Adresse IP:\t"+hotspotClientList['ip_addr']+"\n"
                    chaine += u"Adresse Mac:\t"+hotspotClientList['mac_addr']+"\n"
                elif 0 in hotspotClientList.keys():
                    for index in range(0, len(hotspotClientList)):
                        chaine += u"Adresse IP:\t"+hotspotClientList[index]['ip_addr']+"\n"
                        chaine += u"Adresse Mac:\t"+hotspotClientList[index]['mac_addr']+"\n"
                else:
                    return u"Aucun périphérique connecté\n"
            else:
                chaine = u"Vous devez activer le hotspot pour voir les personnes connectés\n"
            return chaine
        except Exception:
            return u"Veuillez vous connecter (ls9box --connect)\n"

    def get_voip_info(self):
        """Renvoie l'état de la voip"""
        try:
            voipInfo = self.get_prive("voip.getInfo")
            if "hook_status" in voipInfo.keys():
                combine = {u"onhook":u"raccroché", u"offhook":u"décroché", u"unknown":u"inconnu"}
                chaine  = u"Status:\t\t"+voipInfo['status']+"\n"
                chaine += u"Type:\t\t"+voipInfo['infra']+"\n"
                chaine += u"Combiné:\t"+combine[voipInfo['hook_status']]+"\n"
                chaine += u"Historique:\t"+voipInfo['callhistory_active']+"\n"
                return chaine
            elif "msg" in voipInfo.keys():
                return u"Veuillez vous connecter\n"
            else:
                return u"Erreur voip\n"
        except Exception:
                return u"Erreur voip\n"

    def get_call_history_list(self):
        """Renvoie l'historique des appels téléphonique si l'historique est activé"""
        voip = self.get_prive("voip.getInfo")
        try:
            if voip['callhistory_active'] == "on":
                liste = self.get_prive("voip.getCallhistoryList")
                voipCallHistoryList = "---Historique---\n"
                for idx in range(0, len(liste)):
                    voipCallHistoryList += u"\nDate:\t\t"+str(datetime.date.fromtimestamp(int(liste[idx]['date'])))+"\n"
                    voipCallHistoryList += u"Durée:\t\t"+self.uptime(int(liste[idx]['length']))+"\n"
                    voipCallHistoryList += u"Type:\t\t"+liste[idx]['type']+"\n"
                    voipCallHistoryList += u"Direction:\t"+liste[idx]['direction']+"\n"
                    voipCallHistoryList += u"Numero:\t\t"+liste[idx]['number']+"\n"
            else:
                voipCallHistoryList = u"Vous devez activer l'historique pour consulter le journal des appels\n"
            return voipCallHistoryList
        except Exception:
            return u"Veuillez vous connecter (ls9box --connect)\n"

    def get_firewall_info(self):
        """Renvoie l'information d'état des filtrages du firewall"""
        try:
            firewallInfo = self.get_prive("firewall.getInfo")
            if "smtpdrop" in firewallInfo.keys():
                chaine  = u"Firewall:\tmode "+firewallInfo[0]['mode']+"\n"
                chaine += u"Sécurisation des ordinateurs sous windows:\t"+firewallInfo['winsharedrop']['active']+"\n"
                chaine += u"Blogage de ping entrant:\t"+firewallInfo['icmpdrop']['active']+"\n"
                chaine += u"Blocage mail autre que sfr:\t"+firewallInfo['smtpdrop']['active']+"\n"
                return chaine
            elif "msg" in firewallInfo.keys():
                return u"Veuillez vous connecter\n"
            else:
                return u"Erreur Firewall\n"
        except Exception:
                return u"Erreur Firewall\n"

    def get_ppp_access_code(self):
        """Renvoie le login et le mot de passe ppp"""
        pppAccessCode = self.get_prive("ppp.getCredentials")
        return self.toString(pppAccessCode)

    def get_backup3g_pin_code(self):
        """Renvoie le code pin de la clef 3g"""
        backup3gPinCode = self.get_prive("backup3g.getPinCode")
        return self.toString(backup3gPinCode)
        
    def get_system_default_wpa_key(self):
        """Renvoie la valeur de la clef wpa par défaut"""
        systemDefaultWpaKey = self.get_prive("system.getWpaKey")
        return self.toString(systemDefaultWpaKey)

    #########         Méthode POST Pivées        ############

    def set_backup3g_force_data_link(self):
        """ Définir la politique d'utilisation de la 3G pour la data """
        tiket = ['on', 'off', 'auto']
        mode = raw_input("mode"+tiket+" : ")
        if mode in tiket:
            return self.toString(self.set_param("backup3g.forceDataLink", {'mode':mode}))
        else:
            return u"Argument incorrecte, sont acceptés on, off, auto"

    def set_backup3g_force_voip_link(self):
        """ Définir la politique d'utilisation de la 3G pour la voip """
        tiket = ['on', 'off']
        mode = raw_input("mode"+tiket+" : ")
        if mode in tiket:
            return self.toString(self.set_param("backup3g.forceVoipLink", {'mode':mode}))
        else:
            return u"Argument incorrecte, sont acceptés on ou off"

    def set_backup3g_pin_code(self):
        """ Modifie le code pin de la clef 3g """
        pinCode = raw_input(u"Entrer le code pin : ")
        pinMatch = re.match('\d{4,8}', pinCode)
        if pinMatch :
            return self.toString(self.set_param("backup3g.setPinCode", {'pincode':pinCode}))
        else:
            return u"Fail."

    def set_ddns_enable(self):
        """ Activer le service dyndns """
        return self.toString(self.set_param("ddns.enable"))


    def set_ddns_disable(self):
        """ Désactiver le service dyndns"""
        return self.toString(self.set_param("ddns.disable"))


    def set_ddns_forceUpdate(self):
        """ Force la mise à jour du service dyndns"""
        retour = self.set_param("ddns.forceUpdate")
        if "stat" in retour.keys():
            return retour['stat']
        else:
            return self.toString(retour)

    def set_ddns_service(self):
        """ Configurer le compte dyndns """
        print u"nom du service: dyndns, no-ip, ovh, dyndnsit, changeip, sitelutions"
        service = raw_input(u"service : ")
        username = raw_input(u"identifiant : ")
        password = getpass.getpass()
        hostname = raw_input(u"hostname : ")
        params = {'service':service, 'username':username, 'password':password, 'hostname':hostname}
        print self.set_param("ddns.setService", params)

    def set_firewall_enable_smtp_filter(self):
        """ Active le filtre de service SMTP """
        return self.toString(self.set_param("firewall.enableSmtpFilter"))

    def set_firewall_disable_smtp_filter(self):
        """ Désactive le filtrage SMTP """
        return self.toString(self.set_param("firewall.disableSmtpFilter"))

    def set_hotspot_enable(self):
        """ Active le hotspot """
        return self.toString(self.set_param("hotspot.enable")) + self.toString(self.set_param("hotspot.start"))

    def set_hotspot_disable(self):
        """ Désactive le hotspot """
        return self.toString(self.set_param("hotspot.stop")) + self.toString(self.set_param("hotspot.disable"))

    def set_hotspot_restart(self):
        """ Redémare le hotspot """
        return self.toString(self.set_param("hotspot.restart"))

    def set_hotspot_mode(self):
        """ Défini le mode du hotspot """
        mode = raw_input(u"Saisir le mode voulu (sfr ou sfr_fon) : ")
        if mode in ["sfr", "sfr_fon"]:
            return self.toString(self.set_param("hotspot.setMode", {'mode':mode}))
        else:
            return u"Erreur"

    def set_lan_add_dns(self):
        #Attention aux retour ! a modifier
        """ Ajoute une entrée DNS dans le registre de la box """
        ip = raw_input(u"Ip de la machine : ")
        name = raw_input(u"Nom du champ DNS : ")
        if len(ip) > 0 and len(name) > 1:
            params = {'ip':ip, 'name':name}
            return self.toString(self.set_param("lan.addDnsHost", params))
        else:
            return u"Erreur de dns"

    def set_lan_delete_dns(self):
        #Attention aux retour ! a modifier
        """ Supprime une entrée DNS dans le registre de la box """
        ip = raw_input(u"Ip de la machine : ")
        name = raw_input(u"Nom du champ DNS : ")
        if len(ip) > 0 and len(name) > 1:
            params = {'ip':ip, 'name':name}
            return self.toString(self.set_param("lan.deleteDnsHost", params))
        else:
            return u"Erreur de dns"

    def set_ppp_credentials(self):
        """ Modifier le login et mot de passe ppp """
        login = raw_input(u"Login ppp : ")
        password = getpass.getpass()
        return self.toString(self.set_param("ppp.setCredentials", {'login':login, 'password':password}))

    def set_system_reboot(self):
        """ Rebooter la box """
        return self.toString(self.set_param("system.reboot"))

    def set_system_netmode(self):
        """ Modifier le mode de fonctionnement de la box """
        mode = raw_input("Mode de la box (router, bridge) : ")
        if mode in ["router", "bridge"]:
            return self.toString(self.set_param("system.setNetMode", {'mode':mode}))
        else:
            return u"Erreur de mode"

    def set_system_refclient(self):
        """ Défini la référence client """
        refClient = raw_input("Entrer votre identifiant : ")
        if len(refClient) > 0:
            return self.toString(self.set_param("system.setRefClient", {'refclient':refClient}))

    def set_voip_start(self):
        """ Démare le service de voip """
        return self.toString(self.set_param("voip.start"))

    def set_voip_stop(self):
        """ Arrête le service de voip """
        return self.toString(self.set_param("voip.stop"))

    def set_voip_restart(self):
        """ Redémare le service de voip """
        return self.toString(self.set_param("voip.restart"))

    def set_wlan_enable(self):
        """ Active le wifi """
        return self.toString(self.set_param("wlan.enable"))+ self.toString(self.set_param("wlan.start"))

    def set_wlan_disable(self):
        """ Désactive le wifi """
        return self.toString(self.set_param("wlan.stop"))+ self.toString(self.set_param("wlan.disable"))

    def set_wlan_restart(self):
        """ Redémare le wifi """
        return self.toString(self.set_param("wlan.restart"))

    def set_wlan_channel(self):
        """ Définir le cannal utilisé pour la wifi """
        channel = raw_input("Numero du cannal (1-13) : ")
        if channel > 0 and channel < 14 :
            return self.toString(self.set_param("wlan.setChannel", {'channel':channel}))

    def set_wlan_encryption(self):
        """ Défini le type de clef de sécurité du wifi """
        tiket = ['OPEN','WEP','WPA-PSK','WPA2-PSK','WPA-WPA2-PSK']
        print tiket
        encryption = raw_input("Encription type : ")
        if encryption in tiket:
            return self.toString(self.set_param("wlan.setWl0Enc", {'enc':encryption}))
        else:
            return "Erreur de type recommencez"

    def set_wlan_encryption_type(self):
        """ Défini le type de clef de sécurité du wifi """
        encryption = raw_input("Encription type (tkip, aes ou tkipaes) : ")
        tiket = ['tkip','aes','tkipaes']
        if encryption in tiket:
            return self.toString(self.set_param("wlan.setWl0EncType", {'enctype':encryption}))
        else:
            return "Erreur de type recommencez"

    def set_wlan_key_type(self):
        """ Défini ... de sécurité du wifi """
        encryption = raw_input("Encode clef wep : ")
        tiket = ['ascii','hexa']
        if encryption in tiket:
            return self.toString(self.set_param("wlan.setWl0KeyType", {'keytype':encryption}))

    def set_wlan_ssid(self):
        """ Défini le SSID du wifi """
        ssid = raw_input("SSID : ")
        if len(SSID) > 1:
            return self.toString(self.set_param("wlan.setWl0Ssid", {'ssid':ssid}))

    def set_wlan_wepkey(self):
        """ Défini le type de clef de sécurité du wifi """
        wepkey = raw_input("Clef Wep : ")
        if len(wepkey) in [1-100] :
            return self.toString(self.set_param("wlan.setWl0Wepkey", {'wepkey':wepkey}))

    def set_wlan_wpakey(self):
        """ Défini le type de clef de sécurité du wifi """
        wpakey = raw_input("Clef Wpa : ")
        if len(wpakey) in [1-100] :
            return self.toString(self.set_param("wlan.setWl0Wpakey", {'wpakey':wpakey}))

    def set_wlan_radio_mode(self):
        """ Défini le type de clef de sécurité du wifi """
        mode = raw_input("Mode radio : ")
        vbox = sysInfo = self.get_public("system.getInfo")['product_id'].split('-')
        if vbox[0] in ["NB5", "NB6"]:
            tiket = ["11n", "11ng", "11g"]
        else:
            tiket = ["11b", "11g", "auto"]
        if mode in tiket:
            return self.toString(self.set_param("wlan.setWlanMode", {'mode':mode}))
        else:
            return "Erreur mode wifi"


    #########         Méthode d'authentification        ############

    def authentification(self, opt = ""):
        """demande le token et le type de connexion (password, bouton, all)"""
        
        if self.conn == None:
            return None

        authToken = self.get_public("auth.getToken")
        #or opt = "bouton"

        if authToken['method'] == "bouton" :
            text = "appuyez sur le voyant de la box jusqu'a ce qu'il devienne violet clignotant puis appuyez sur entrée"
            authToken = self.get_public("auth.getToken")
            params = "/api/?method=auth.checkToken&token="+authToken['token']
        else:
            username = raw_input("identifiant : ")
            mdp = getpass.getpass()
            token = str(authToken['token'])
            user = hashlib.sha256(username)
            pswd = hashlib.sha256(mdp)
            hash1 = hmac.new(token, user.hexdigest(), sha256).hexdigest()
            hash2 = hmac.new(token, pswd.hexdigest(), sha256).hexdigest()
            hashCode = hash1 + hash2
            #print hashCode
            params = "/api/?method=auth.checkToken&token="+token+"&hash="+hashCode

        try:
            #self.conn.set_debuglevel(1)
            #params = "/api/?method="+method+"&token="+authToken['token']+"&hash="+hashCode
            #self.conn.request("GET", params)
            #response = self.conn.getresponse()
            response = urllib2.urlopen('http://'+self.ipaddr+'/'+params)
            #if response.status == 200:
            data = response.read()
            value = self.xml_to_dic(data)
            #else:
            #value = None

        except Exception:
            return None

        return value


    #########         Fonctions générales d'appel         ############
    
    def xml_to_dic(self, data):
        """Converti la réponse xml de la neufbox en tableau associatif (dictionnaire)"""
        dom = parseString(data)
        result = {}
        iterrator = 0
        d2={}
        for rsp in dom.getElementsByTagName('rsp'):
            for child in rsp.childNodes:
                if child.nodeType == xml.dom.Node.ELEMENT_NODE:
                    if child.hasAttributes():
                        attrs = child.attributes
                        for idx in range(0, attrs.length):
                            a = attrs.item(idx)
                            result[a.nodeName] = a.nodeValue
                        d2[iterrator] = result.copy()
                        iterrator += 1

                        resulta = {}
                        for chuld in child.childNodes:
                            if chuld.nodeType == xml.dom.Node.ELEMENT_NODE:
                                if chuld.hasAttributes():
                                    attr = chuld.attributes
                                    for idx in range(0, attr.length):
                                        a = attr.item(idx)
                                        resulta[a.nodeName] = a.nodeValue
                                    d2[chuld.nodeName] = resulta.copy()
                                    iterrator += 1
                    else:
                        indx = 0
                        d2.clear()
                        for chuld in child.childNodes:
                            if chuld.nodeType == xml.dom.Node.ELEMENT_NODE:
                                if chuld.hasAttributes():
                                    attr = chuld.attributes
                                    for idx in range(0, attr.length):
                                        a = attr.item(idx)
                                        result[a.nodeName] = a.nodeValue
                                    d2[indx] = result.copy()
                                    indx += 1
                        result = d2

            if iterrator > 1:
                result = d2

        return result

    def response_set(self, data):
        """Converti la réponse xml de la neufbox en tableau associatif (dictionnaire)"""
        dom = parseString(data)
        result = {}
        for rsp in dom.getElementsByTagName('rsp'):
            if rsp.nodeType == xml.dom.Node.ELEMENT_NODE:
                if rsp.hasAttributes():
                    attrs = rsp.attributes
                    for idx in range(0, attrs.length):
                        a = attrs.item(idx)
                        result[a.nodeName] = a.nodeValue
                    for child in rsp.childNodes:
                        if child.nodeType == xml.dom.Node.ELEMENT_NODE:
                            if child.hasAttributes():
                                attrs = child.attributes
                                for idx in range(0, attrs.length):
                                    a = attrs.item(idx)
                                    result[a.nodeName] = a.nodeValue
        return result


    def uptime(self, Tsec):
        """Converti un timestamp en affichage jours heures minutes secondes"""
        chaine = ""
        if Tsec < 86400:
            chaine = time.strftime('%H h, %M min, %S sec', time.gmtime(Tsec))
        else:
            chaine = str(Tsec/86400)+" jours, "+time.strftime('%H h, %M min, %S sec', time.gmtime(Tsec))
        return chaine
    
    
    def toString(self,data):
        """Utilise le formatage de xml_to_dic pour générer un affichage clef -> valeur"""
        chaine = ""
        try:
            for cle in data:
                chaine += cle + "\t" + data[cle] +"\n"
            return chaine
        except Exception:
            return None

    def get_public(self, paramname):
        """Obtenir la valeur d'un paramètre publiques de la neufBox avec une requête de type GET
           Renvoie None en cas de problème
        """
        if self.conn == None:
            return None

        try:
            params = "/api/?method="+paramname
            self.conn.request("GET", params)
            response = self.conn.getresponse()
            
            if response.status == 200:
                data = response.read()
                value = self.xml_to_dic(data)
            else:
                value = None

        except Exception:
            return None

        return value

    def get_prive(self, method):
        """Obtenir la valeur d'un paramètre privé de la neufBox avec une requête de type GET 
           Renvoie None en cas de problème
        """
        if self.conn == None:
            return None

        try:
            token = self.hashtag
            params = "/api/?method="+method+"&token="+token
            self.conn.request("GET", params)
            response = self.conn.getresponse()
            
            if response.status == 200:
                data = response.read()
                value = self.xml_to_dic(data)
            else:
                value = None

        except Exception:
            return None

        return value

    def set_param(self, method, paramlist = {}):
        """Modifie la valeur d'un paramètre de la neufBox avec une requête de type POST privé
           Renvoie None en cas de problème
        """
        if self.conn == None:
            return None

        try:
            token = self.hashtag
            paramlist.update({"token": token})
            params = urllib.urlencode(paramlist) # attention ! paramlist doit etre un dictionnaire
            self.conn.request("POST", "/api/?method="+method, params, NeufBox._DEFAULT_CGI_HEADERS)
            response = self.conn.getresponse()
            
            if response.status == 200:
                data = response.read()
                value = self.response_set(data)
            else:
                value = None

        except Exception:
            return None

        return value

    def open_HTTPConnection(self):
        """Ouverture d'une connexion HTTP ou None si erreur"""
        socket.setdefaulttimeout = NeufBox._HTTP_TIMEOUT
        try:
            self.conn = httplib.HTTPConnection(self.ipaddr,NeufBox._DEFAULT_CGI_PORT,False)
        except Exception:
            self.conn = None
        return self.conn

    def close_HTTPConnection(self):
        """Fermeture de la connexion HTTP"""
        if not self.conn == None:
            self.conn.close()


if __name__ == '__main__':

    import sys

    nb = NeufBox()
    print "---- Paramètres ----"
    print "IP LAN : %s" % nb.get_box_lanipaddr()

    if not nb.isonlan():
        print "La NeufBox (%s) n'est pas accessible !" % nb.get_box_lanipaddr()
        sys.exit(1)

    if nb.open_HTTPConnection() and nb.isready():
        # partie de test des fonctions 
        print nb.get_status()
        nb.close_HTTPConnection()
    else:
        print "La NeufBox (%s) ne répond pas aux requêtes !" % nb.get_box_lanipaddr()

    sys.exit()
