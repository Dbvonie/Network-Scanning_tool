from scapy.all import Ether, ARP, srp
import socket
import subprocess
import re

def get_local_network() -> str:
    """
    Détecte automatiquement le réseau local.
    Retourne ex: "192.168.1.0/24"
    """
    # ip route show donne les routes réseau
    result = subprocess.run(["ip", "route", "show"], capture_output=True, text=True)
    
    # On cherche une ligne comme "192.168.1.0/24 dev eth0"
    match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
    
    if match:
        return match.group(1)
    
    # Fallback si rien trouvé
    return "192.168.1.0/24"

def arp_scan(network: str) -> list[dict]:
    """
    Scanne le réseau avec ARP et retourne les hôtes actifs.
    
    network : ex "192.168.1.0/24"
    retourne : liste de { "ip": ..., "mac": ..., "hostname": ... }
    """

    # Couche Ethernet : destination = broadcast (tout le monde écoute)
    ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Couche ARP : "qui a ces IPs ?" pour tout le sous-réseau
    arp = ARP(pdst=network)

    # On assemble les deux couches avec /
    paquet = ethernet / arp

    # Envoi du paquet et réception des réponses
    # timeout=2 : on attend 2 secondes pour les réponses
    resultats = srp(paquet, timeout=2, verbose=0)[0]
    hotes_actifs = []
    for _, reponse in resultats:
        ip = reponse.psrc
        mac = reponse.hwsrc
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = None
        hotes_actifs.append({"ip": ip, "mac": mac, "hostname": hostname})
    return hotes_actifs