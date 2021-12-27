#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Affichage des informations techniques d'une NeufBox en ligne de commande (Etats, paramétrage, ...)

Voir >ls9box --help pour le détail des options disponibles

L'adresse IP de la NeufBox est par défaut : 192.168.1.1
L'adresse ip, si différente, peut éventuellement être indiquée par l'option --ip <adresse>. 
Elle est stockée dans le fichier ~/.9box/9box.ip

----

This library is free software; you can redistribute it and/or modify 
it under the terms of the GNU Lesser General Public License as 
published by the Free Software Foundation; either version 2.1 of the 
License, or any later version.

This library is distributed in the hope that it will be useful, but 
WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public 
License along with this library; if not, write to the Free Software 
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 
USA

(C) 2013 Clement MILLET
"""

import getopt
import httplib
import imp
import locale
import os
import socket
import sys
import traceback
import urllib

# Import des bibliothèques privées
if (hasattr(sys, "frozen") or # new py2exe
    hasattr(sys, "importers") or # old py2exe
    imp.is_frozen("__main__")): # tools/freeze:
    scriptpath = os.path.dirname(sys.executable)
else:
    scriptpath = os.path.dirname(sys.argv[0])
absscriptpath = os.path.abspath(scriptpath)
sys.path.append(absscriptpath)
from NeufBox import NeufBox

__progname__ = u"ls9box"
__version__ = u"0.4.3212.1"
__author__ = u"Clement MILLET <contact@ls9box.fr>"
__copyright__ = u"Copyright(C) 2013 - Clement MILLET"
__license__ = u"GNU GPL 2"
__revision__ = u"$Revision: 5 $"
__date__ = u"$Date: 2013-01-20 12:20:31 +0100 (dim., 20 janv. 2013) $"
__lastchangedby__ = u"$Author: C. MILLET $"

_objet_ = u"Affichage des informations d'une Neuf Box"
_cmdline_options_ = u"""Options:

  -a, --all\tAffiche toutes les informations connues
  --adsl\tAffiche les informations de la ligne ADSL
  --box\t\tAffiche les informations concernant la NeufBox
  --dns\t\taffiche la liste des entrées DNS
  --dyndns\tAffiche les informations concernant la dyndns
  --firewall\tAffiche les informations de sécurisation du réseau
  --hotspot\tAffiche l'état du hotspot wifi
  --internet\tAffiche les informations de la connexion Internet
  --lan\t\tAffiche les éléments des attachments LAN et autres
  --services\tAffiche l'état des services réseau
  --startwifi\t|
  --status\tAffiche l'état des principaux indicateurs
  --stopwifi\t|
  --voip\tAffiche l'état de la téléphonie
  --wifi\tAffiche les informations lièes au réseau sans fil

  -i, --ip <adresse ip>\tSpécifie l'adresse ip de la NeufBox (192.168.1.1 par défaut)
  -h, --help\tAffiche cette page d'aide
  -v, --version\tAffiche la version de ce programme
"""

BOX_CONF_DIR = ".9box"
BOX_CONF_FILENAME = "9box.ip"
BOX_HASH_FILENAME = "9box.hash"
BOX_DEFAULT_IP = "192.168.1.1"
BOX_HASH = "default"

LIST_MAX_OCCUR = 16
EXCEPTION_LIMIT = 0


def getstreamencoding(stream):
    """Renvoie l'encodage pour le stream"""
    encoding = stream.encoding
    if encoding == None:
        encoding = locale.getpreferredencoding()
    return encoding


def printenc(unicodemsg, streamhdl = sys.stdout, encoding = None):
    """Affichage d'un message en unicode sur un stream encodé (par défaut, stdout)"""
    if encoding == None:
        encoding = getstreamencoding(streamhdl)
    if isinstance(unicodemsg, unicode):
        print >> streamhdl, unicodemsg.encode(encoding)
    else:
        print >> streamhdl, unicodemsg


def loadconffile():
    """Chargement ou création des fichiers de configuration"""

    #Obtenir chemin du fichier
    hashfilepath, conffilepath, confdirpath = getconffilepath()

    #Chargement du fichier existant ou création avec valeur par defaut
    global BOX_DEFAULT_IP, BOX_HASH
    if os.path.exists(conffilepath) and os.path.exists(hashfilepath):
        try:
            fhdl = open(conffilepath, 'r')
            BOX_DEFAULT_IP = fhdl.readline().strip()
            filehash = open(hashfilepath, 'r')
            BOX_HASH = filehash.readline().strip()
            fhdl.close()
            filehash.close()
        except IOError:
            printenc(u"Impossible de charger la configuration", sys.stderr)
            traceback.print_exc(limit = EXCEPTION_LIMIT, file = sys.stderr)
    else:
        saveconffile()
        savehashfile("")
        loadconffile()


def saveconffile():
    """Sauvegarde du fichier de configuration"""
    hashfilepath, conffilepath, confdirpath = getconffilepath()
    try:
        if not os.path.exists(confdirpath):
            os.makedirs(confdirpath)
        fhdl = open(conffilepath, 'w+')
        fhdl.write(BOX_DEFAULT_IP)
        fhdl.close()
    except IOError:
        printenc(u"Impossible d'enregistrer la configuration", sys.stderr)
        traceback.print_exc(limit = EXCEPTION_LIMIT, file = sys.stderr)

def savehashfile(hashfile):
    """Sauvegarde du hash"""
    hashfilepath, conffilepath, confdirpath = getconffilepath()
    try:
        if not os.path.exists(confdirpath):
            os.makedirs(confdirpath)
        fhdl = open(hashfilepath, 'w+')
        fhdl.write(hashfile)
        fhdl.close()
    except IOError:
        printenc(u"Impossible d'enregistrer la configuration", sys.stderr)
        traceback.print_exc(limit = EXCEPTION_LIMIT, file = sys.stderr)

def getconffilepath():
    """Obtenir le chemin absolu du fichier de configuration"""
    homepath = os.path.abspath(os.path.expanduser('~'))
    confdirpath = os.path.join(homepath, BOX_CONF_DIR)
    conffilepath = os.path.join(confdirpath, BOX_CONF_FILENAME)
    hashfilepath = os.path.join(confdirpath, BOX_HASH_FILENAME)
    return (hashfilepath, conffilepath, confdirpath)


def usage(printopts = False):
    """Affichage du mode d'emploi"""
    printenc("%s version %s\nCopyright(C) 2013 %s\n" \
            % (__progname__, __version__, __author__) + \
            "\nreleased under %s" % __license__)
    if printopts:
        printenc("\n%s" % _objet_)
        printenc("usage: %s [<options>]" % __progname__)
        printenc(_cmdline_options_)


if __name__ == '__main__':

    if __debug__:
        EXCEPTION_LIMIT = None

    # Chargement de la configuration
    loadconffile()

    # Parsing et contrôle des options
    validopts = ["adsl", "box", "dns", "dyndns", "firewall", "hotspot", "internet", "lan", "services", "status", "wifi", "voip"]
    try:
        opts, args = getopt.getopt (sys.argv[1:], "ahi:v", ["all", "boxrestart", "boxmode", "boxrefclient", "3gdatalink", "3gvoiplink", "3gpincode", "connect", "ddnsenable", "ddnsdisable", "ddnsconfig", "ddnsforceupdate", "help", "ip=", "starthotspot", "startwifi", "stophotspot", "stopwifi", "test", "version"] + validopts)
    except getopt.GetoptError:
        usage(True)
        sys.exit(9)

    querylist = list()
    for opt, a in opts:
        if opt in ('-a', '--all'):
            querylist = list(validopts)
            break
        elif opt in ('-h', '--help'):
            usage(True)
            sys.exit(0)
        elif opt in ('-i', '--ip'):
            BOX_DEFAULT_IP = unicode(a)
            saveconffile()
        elif opt in ('-v', '--version'):
            usage()
            sys.exit(0)
        else:
            querylist.append(opt.replace("--",""))

    if len(querylist) == 0:
        querylist = list(["status"])

    # Création de la Neuf Box
    nb4 = NeufBox(BOX_DEFAULT_IP, BOX_HASH)

    # IP joignable ?
    if not nb4.isonlan():
        printenc(u"Oups, rien ne répond à cette adresse (%s) !" % (BOX_DEFAULT_IP))
        sys.exit(1)

    # Est-ce une NeufBox ?
    if not nb4.open_HTTPConnection():
        printenc(u"Oups, est-ce une Neuf Box 4 ? (Impossible de s'y connecter)")
        sys.exit(2)

    if not nb4.isready():
        nb4.open_HTTPConnection()
        printenc(u"Oups, est-ce une Neuf Box 4 ? (Réponse incohérente)")
        sys.exit(3)

    # Etats
    if "status" in querylist:
        printenc(u"NeufBox -----")
        printenc(nb4.get_status())


    # Neuf Box
    if "box" in querylist:
        printenc("----- NeufBox -----")
        printenc(nb4.get_system_info())
        #printenc(u"- Adresse MAC : %s" % nb4.get_param("mac_addr"))


    # ligne ADSL
    if "adsl" in querylist:
        printenc(u"----- Ligne ADSL -----")
        printenc(nb4.get_dsl_info())


    # Connexion Internet
    if "internet" in querylist:
        printenc(u"----- Connexion Internet -----")
        printenc(nb4.get_wan_info())


    # Dynamic DNS
    if "dyndns" in querylist:
        printenc(u"----- DynDns -----")
        printenc(nb4.get_ddns_info())


    # Attachements Réseau
    if "lan" in querylist:
        printenc(u"----- LAN et service LAN -----")
        printenc(nb4.get_lan_info())
        printenc(u"----- Listes postes connectés -----")
        printenc(nb4.get_lan_hostlist())


    # Les DNS
    if "dns" in querylist:
        printenc(u"----- Liste DNS -----")
        printenc(nb4.get_lan_dnslist())


    # Services Réseau
    if "services" in querylist:
        printenc(u"----- Services réseau -----")
        printenc(u"-Partage de fichiers-")
        printenc(nb4.get_smb_info())
        printenc(u"-Partage d'imprimante-")
        printenc(nb4.get_print_info())


    # Wifi
    if "wifi" in querylist:
        printenc(u"----- Wifi -----")
        printenc(nb4.get_wlan_info())
        printenc(u"--- Appareils connectés---")
        printenc(nb4.get_wlan_client_list())


    # Hotspot
    if "hotspot" in querylist:
        printenc(u"----- HotSpot -----")
        printenc(nb4.get_hotspot_info())
        printenc(nb4.get_hotspot_client_list())


    # VOIP
    if "voip" in querylist:
        printenc(u"----- VOIP -----")
        printenc(nb4.get_voip_info())
        printenc(nb4.get_call_history_list())


    # Firewall
    if "firewall" in querylist:
        printenc(u"---- Firewall ----")
        printenc(nb4.get_firewall_info())


    # Connexion pour accéder au méthodes privées
    if "connect" in querylist:
        try:
            token = nb4.authentification()
            savehashfile(token['token'])
            printenc(u"Connection réussie.")
        except Exception:
            printenc(u"Erreur "+token['code']+": "+token['msg'])


    # Backup 3g
    if "3gdatalink" in querylist:
        printenc(nb4.set_backup3g_force_data_link())


    # Backup 3g
    if "3gvoiplink" in querylist:
        printenc(nb4.set_backup3g_force_voip_link())


    # Backup 3g Pin Code
    if "3gpincode" in querylist:
        printenc(nb4.set_backup3g_pin_code())


    # Active le service DynDns
    if "ddnsenable" in querylist:
        printenc(nb4.set_ddns_enable())


    # Désactive le service DynDns
    if "ddnsdisable" in querylist:
        printenc(nb4.set_ddns_disable())


    # ForceUpdate
    if "ddnsforceupdate" in querylist:
        printenc(nb4.set_ddns_forceUpdate())


    # Configurer le DynDns
    if "ddnsconfig" in querylist:
        printenc(nb4.set_ddns_service())


    # Active le filtrage SMTP
    if "enablesmtpfilter" in querylist:
        printenc(nb4.set_firewall_enable_smtp_filter())


    # Désactive le filtrage SMTP
    if "disablesmtpfilter" in querylist:
        printenc(nb4.set_firewall_disable_smtp_filter())


    # Active le hotspot
    if "starthotspot" in querylist:
        printenc(nb4.set_hotspot_enable())


    # Désactive le hotspot
    if "stophotspot" in querylist:
        printenc(nb4.set_hotspot_disable())


    # Redémare le hotspot
    if "restarthotspot" in querylist:
        printenc(nb4.set_hotspot_restart())


    # Définir le mode du hotspot
    if "hotspotmode" in querylist:
        printenc(nb4.set_hotspot_mode())


    # Ajoute une entrée dns
    if "landnsadd" in querylist:
        printenc(nb4.set_lan_add_dns())


    # Supprime une entrée dns
    if "landnsdel" in querylist:
        printenc(nb4.set_lan_delete_dns())


    # Set password Credential
    #if "pppcredential" in querylist:
    #


    # Redémarer la box
    if "boxrestart" in querylist:
        printenc(nb4.set_system_reboot())


    # Mode de la box
    if "boxmode" in querylist:
        printenc(nb4.set_system_netmode())


    # Référence Client
    if "boxrefclient" in querylist:
        printenc(nb4.set_system_refclient())


    # Start voip
    if "voipstop" in querylist:
        printenc(nb4.set_voip_start())


    # Stop voip
    if "voipstop" in querylist:
        printenc(nb4.set_voip_stop())


    # Démare le wifi
    if "startwifi" in querylist:
        printenc(nb4.set_wlan_enable())


    # Arrête le wifi
    if "stopwifi" in querylist:
        printenc(nb4.set_wlan_disable())


    # Set cannal wifi
    if "wificannal" in querylist:
        printenc(nb4.set_wlan_channel())

    # test
    if "test" in querylist:
        printenc(u"test")

    nb4.open_HTTPConnection()

    sys.exit(0)

