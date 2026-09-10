#!/usr/bin/env python3
"""
Controleur SDN avec detection DDoS IPv6 pilotee par MODELE (temps reel).
Le controleur calcule chaque seconde les caracteristiques par source
(au coeur OVS-1) et les envoie au service de detection (Flask + RF/LSTM).
Si le service juge une source "attaque", le controleur la bloque.

NOUVEAU : un petit serveur de controle (port 5001) permet au service de
demander le deblocage de toutes les sources (bouton "Reinitialiser" du
dashboard), sans redemarrer les machines.
"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6, udp, tcp, ipv4
from ryu.lib import hub
from collections import defaultdict
import time
import csv
import os
import json
import math
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


def _win_factory():
    """Structure d'accumulation d'une source sur une fenetre d'1 seconde."""
    return {"n": 0, "oct": 0, "oct2": 0, "dst": set(),
            "dport": set(), "tcp": 0, "udp": 0, "icmp": 0}


class DDoSPrevention(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    DPID_NOMS = {
        0x080027089179: "Routeur_TAYGA",
        0xea0ff7aae243: "OVS-1_Core",
        0xc66a172c1949: "OVS-2_Switch",
        0x9e7c59c0ec4f: "OVS-3_Switch",
    }
    DPID_TAYGA = 0x080027089179
    DPID_OVS1  = 0xea0ff7aae243
    DPID_OVS2  = 0xc66a172c1949
    DPID_OVS3  = 0x9e7c59c0ec4f

    CSV_FILE = "/home/controleur/Bureau/traficNormal.csv"

    # Adresse du site cible (le trafic TCP entrant vers cette adresse est capture)
    SITE_IP = "2001:4278:19:e9cd::30"

    # Service de detection (meme VM)
    SERVICE_URL = "http://127.0.0.1:5000/features"

    # Ordre EXACT des caracteristiques attendu par le modele
    FEATURES = ['n_paq', 'n_oct', 'taille_moy', 'taille_ect',
                'n_dst', 'n_dport', 'f_tcp', 'f_udp', 'f_icmp']

    def __init__(self, *args, **kwargs):
        super(DDoSPrevention, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.SEUIL_PPS = 100
        self.FENETRE_TEMPS = 5
        self.blocked_ips = set()
        # Adresses a NE JAMAIS bloquer (le site, le controleur, le NAT64...)
        self.protected_ips = {
            self.SITE_IP,
            "2001:4278:19:e9cd::10",   # controleur
            "2001:4278:19:e9cd::253",  # NAT64 (br-ext)
        }
        self.packet_count = defaultdict(int)
        # Accumulateur temps reel (par source, fenetre d'1 s, mesure au coeur OVS-1)
        self.win = defaultdict(_win_factory)
        self._svc_ok = True
        self._init_csv()
        self.logger.info("DDoS Prevention (IA) demarre - service: %s", self.SERVICE_URL)
        self.monitor_thread = hub.spawn(self._monitor)
        self.sender_thread = hub.spawn(self._envoyer_service)
        # Petit serveur HTTP pour recevoir l'ordre de deblocage depuis le service
        self.unblock_thread = hub.spawn(self._serveur_controle)

    def _init_csv(self):
        if not os.path.exists(self.CSV_FILE):
            with open(self.CSV_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'switch', 'dpid', 'in_port',
                    'src_mac', 'dst_mac', 'src_ip', 'dst_ip',
                    'protocole', 'icmpv6_type', 'src_port', 'dst_port',
                    'taille_paquet', 'label'
                ])
        self.logger.info("Fichier CSV: %s", self.CSV_FILE)

    def _save_to_csv(self, switch, dpid, in_port, src_mac, dst_mac,
                     src_ip, dst_ip, protocole, icmpv6_type,
                     src_port, dst_port, taille, label=0):
        try:
            with open(self.CSV_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    time.strftime('%Y-%m-%d %H:%M:%S'),
                    switch, dpid, in_port,
                    src_mac, dst_mac, src_ip, dst_ip,
                    protocole, icmpv6_type, src_port, dst_port,
                    taille, label
                ])
        except Exception as e:
            self.logger.error("Erreur CSV: %s", str(e))

    def _get_nom(self, dpid):
        return self.DPID_NOMS.get(dpid, "Switch_%s" % dpid)

    # ---------------------------------------------------------------
    #  ACCUMULATION + ENVOI AU SERVICE (temps reel)
    # ---------------------------------------------------------------
    def _accumuler(self, src_ip, dst_ip, dst_port, taille, protocole):
        """Ajoute un paquet a la fenetre courante de sa source."""
        w = self.win[src_ip]
        w["n"] += 1
        w["oct"] += taille
        w["oct2"] += taille * taille
        w["dst"].add(dst_ip)
        w["dport"].add(dst_port)
        if protocole.startswith("TCP"):
            w["tcp"] += 1
        elif protocole.startswith("UDP"):
            w["udp"] += 1
        elif protocole.startswith("PING") or protocole.startswith("ICMP"):
            w["icmp"] += 1

    def _caracteristiques(self, w):
        """Transforme un accumulateur en dictionnaire de caracteristiques."""
        n = w["n"]
        moy = w["oct"] / n
        # ecart-type d'echantillon (comme pandas .std(), ddof=1)
        if n > 1:
            var = (w["oct2"] - (w["oct"] * w["oct"]) / n) / (n - 1)
            ect = math.sqrt(var) if var > 0 else 0.0
        else:
            ect = 0.0
        return {
            "n_paq": n, "n_oct": w["oct"],
            "taille_moy": moy, "taille_ect": ect,
            "n_dst": len(w["dst"]), "n_dport": len(w["dport"]),
            "f_tcp": w["tcp"] / n, "f_udp": w["udp"] / n, "f_icmp": w["icmp"] / n,
        }

    def _envoyer_service(self):
        """Chaque seconde : envoie les caracteristiques au service et applique le verdict."""
        while True:
            hub.sleep(1)
            # bascule atomique de la fenetre
            snap = self.win
            self.win = defaultdict(_win_factory)
            if not snap:
                continue
            sources = {ip: self._caracteristiques(w) for ip, w in snap.items()}
            try:
                data = json.dumps({"sources": sources}).encode()
                req = urllib.request.Request(
                    self.SERVICE_URL, data=data,
                    headers={"Content-Type": "application/json"})
                resp = urllib.request.urlopen(req, timeout=2)
                verdicts = json.loads(resp.read().decode())
                if not self._svc_ok:
                    self.logger.info("Service de detection joignable a nouveau.")
                    self._svc_ok = True
                # application du verdict : blocage si "attaque"
                for ip, v in verdicts.items():
                    if (v.get("bloquer") and ip not in self.blocked_ips
                            and ip not in self.protected_ips):
                        self.logger.warning("MODELE -> ATTAQUE: %s", ip)
                        self.block_attacker(ip)
            except Exception as e:
                if self._svc_ok:
                    self.logger.error("Service de detection injoignable: %s", e)
                    self._svc_ok = False

    def _monitor(self):
        while True:
            hub.sleep(self.FENETRE_TEMPS)
            for src_ip, count in list(self.packet_count.items()):
                pps = count / self.FENETRE_TEMPS
                if (pps > self.SEUIL_PPS
                        and src_ip not in self.blocked_ips
                        and src_ip not in self.protected_ips):
                    self.logger.warning(
                        "ATTAQUE DETECTEE: %s (%d pps)", src_ip, pps
                    )
                    #self.block_attacker(src_ip)
            self.packet_count.clear()

    def block_attacker(self, src_ip):
        self.blocked_ips.add(src_ip)
        for dp in self.datapaths.values():
            self._install_block_rule(dp, src_ip)
        self.logger.info("BLOQUE: %s", src_ip)

    def _install_block_rule(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        nom = self._get_nom(datapath.id)
        match = parser.OFPMatch(eth_type=0x86DD, ipv6_src=src_ip)
        self._add_flow(datapath, 100, match, [])
        self.logger.info("Regle blocage sur %s", nom)

    # ---------------------------------------------------------------
    #  DEBLOCAGE (declenche par le bouton "Reinitialiser" du dashboard)
    # ---------------------------------------------------------------
    def unblock_all(self):
        """Retire toutes les regles de blocage et vide la liste des IP bloquees."""
        ips = list(self.blocked_ips)
        for dp in self.datapaths.values():
            for ip in ips:
                self._remove_block_rule(dp, ip)
        self.blocked_ips.clear()
        self.logger.info("DEBLOCAGE TOTAL : %d source(s) debloquee(s).", len(ips))
        return len(ips)

    def _remove_block_rule(self, datapath, src_ip):
        """Supprime la regle de blocage (priorite 100) d'une source."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=0x86DD, ipv6_src=src_ip)
        mod = parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            priority=100, match=match)
        datapath.send_msg(mod)

    def _serveur_controle(self):
        """Ecoute les ordres de controle du service (deblocage) sur le port 5001."""
        ctrl = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path == "/debloquer_tout":
                    n = ctrl.unblock_all()
                    body = json.dumps({"ok": True, "debloquees": n}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *a):
                pass  # silence les logs HTTP du serveur de controle

        try:
            srv = HTTPServer(("127.0.0.1", 5001), H)
            ctrl.logger.info("Serveur de controle pret (port 5001, /debloquer_tout).")
            srv.serve_forever()
        except Exception as e:
            ctrl.logger.error("Serveur de controle : %s", e)

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        nom = self._get_nom(datapath.id)

        if datapath.id == self.DPID_TAYGA:
            self.logger.info("Routeur_TAYGA connecte - DPID: %s", datapath.id)
            # Laisser passer IPv4 normalement sur TAYGA
            match_ipv4 = parser.OFPMatch(eth_type=0x0800)
            actions_normal = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self._add_flow(datapath, 20, match_ipv4, actions_normal)
            # Laisser passer ARP normalement sur TAYGA
            match_arp = parser.OFPMatch(eth_type=0x0806)
            self._add_flow(datapath, 20, match_arp, actions_normal)
        else:
            self.logger.info("%s connecte - DPID: %s", nom, datapath.id)

        # Laisser passer NDP (133=RS, 134=RA, 135=NS, 136=NA) en NORMAL
        actions_normal = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        for icmp_type in [133, 134, 135, 136]:
            match_ndp = parser.OFPMatch(
                eth_type=0x86DD,
                ip_proto=58,
                icmpv6_type=icmp_type
            )
            self._add_flow(datapath, 20, match_ndp, actions_normal)

        # Laisser passer tout le TCP IPv6 en NORMAL (protege le canal de controle)
        match_tcp = parser.OFPMatch(eth_type=0x86DD, ip_proto=6)
        self._add_flow(datapath, 10, match_tcp, actions_normal)

        # Capturer le TCP VERS le site (priorite 30 > 10), sens entrant.
        to_ctrl = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        match_site = parser.OFPMatch(eth_type=0x86DD, ip_proto=6,
                                     ipv6_dst=self.SITE_IP)
        self._add_flow(datapath, 30, match_site, to_ctrl)

        # Regle par defaut : tout le reste au controleur
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

        self.datapaths[datapath.id] = datapath

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        nom = self._get_nom(datapath.id)
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("%s enregistre | Total: %d", nom, len(self.datapaths))
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("%s deconnecte | Total: %d", nom, len(self.datapaths))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        nom = self._get_nom(datapath.id)
        au_coeur = (datapath.id == self.DPID_OVS1)   # point de mesure unique

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        src_mac = eth.src
        dst_mac = eth.dst
        taille = len(msg.data)
        src_ip = dst_ip = protocole = ""
        icmpv6_type = src_port = dst_port = 0
        label = 0

        # --- Traitement IPv4 (trafic Kali -> TAYGA) ---
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                protocole = "TCP_IPv4"
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                protocole = "UDP_IPv4"
                src_port = udp_pkt.src_port
                dst_port = udp_pkt.dst_port
            else:
                protocole = "IPv4"
            self.logger.info(
                "TRAFIC_IPv4 [%s] port%d: %s -> %s | %s | %d bytes",
                nom, in_port, src_ip, dst_ip, protocole, taille
            )
            self._save_to_csv(nom, datapath.id, in_port,
                              src_mac, dst_mac, src_ip, dst_ip,
                              protocole, 0, src_port, dst_port,
                              taille, label)
            if au_coeur:
                self._accumuler(src_ip, dst_ip, dst_port, taille, protocole)

        # --- Traitement IPv6 ---
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        if ipv6_pkt:
            src_ip = ipv6_pkt.src
            dst_ip = ipv6_pkt.dst

            if src_ip in self.blocked_ips:
                label = 1
                self._save_to_csv(nom, datapath.id, in_port,
                                  src_mac, dst_mac, src_ip, dst_ip,
                                  "BLOQUE", 0, 0, 0, taille, label)
                return

            self.packet_count[src_ip] += 1

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if tcp_pkt:
                protocole = "TCP"
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                protocole = "UDP"
                src_port = udp_pkt.src_port
                dst_port = udp_pkt.dst_port
            elif icmp_pkt:
                icmpv6_type = icmp_pkt.type_
                if icmpv6_type == 128:
                    protocole = "PING_REQUEST"
                elif icmpv6_type == 129:
                    protocole = "PING_REPLY"
                else:
                    protocole = "ICMPv6_%d" % icmpv6_type
            else:
                protocole = "IPv6"

            if self.packet_count[src_ip] > self.SEUIL_PPS:
                label = 1

            self.logger.info(
                "TRAFIC [%s] port%d: %s -> %s | %s | %d bytes | label=%d",
                nom, in_port, src_ip, dst_ip, protocole, taille, label
            )
            self._save_to_csv(nom, datapath.id, in_port,
                              src_mac, dst_mac, src_ip, dst_ip,
                              protocole, icmpv6_type,
                              src_port, dst_port, taille, label)
            if au_coeur:
                self._accumuler(src_ip, dst_ip, dst_port, taille, protocole)

        # --- Apprentissage MAC + reemission ---
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)