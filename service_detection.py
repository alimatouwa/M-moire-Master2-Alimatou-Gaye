#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=======================================================================
 Detection DDoS - SDN/IPv6 : service + dashboard 3 pages
=======================================================================
 Pages : "/" Temps reel | "/modeles" Modeles | "/rapport" Rapport
 - Decision de blocage : RANDOM FOREST (rapide). LSTM en arriere-plan.
 - Donnees PERMANENTES : historique ecrit sur disque, recharge au demarrage.
 - Telechargement CSV du journal, de la tracabilite et du rapport.
 - Temps d'inference mesure en direct (RF et LSTM).

 Fichiers requis : modele_rf.pkl, poids_lstm.weights.h5, scaler.pkl, features.pkl
 Lancement : python3 service_detection.py   |   http://127.0.0.1:5000/
=======================================================================
"""
import time, threading, json, csv, io, os
import urllib.request
from collections import deque
from flask import Flask, request, jsonify, Response
import numpy as np
import joblib


def demander_deblocage_controleur():
    """Demande au controleur Ryu de retirer toutes les regles de blocage.
    Sans effet si le controleur n'est pas joignable (on n'interrompt pas la reinit)."""
    try:
        req = urllib.request.Request(CONTROLEUR_URL, data=b"{}",
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        resp = urllib.request.urlopen(req, timeout=2)
        d = json.loads(resp.read().decode())
        print(f"Deblocage demande au controleur : {d.get('debloquees', 0)} source(s).")
        return d.get("debloquees", 0)
    except Exception as e:
        print("Deblocage controleur impossible (non bloquant) :", e)
        return None

# ===================== CONFIG A RENSEIGNER ============================
# Valeurs de VOTRE evaluation Colab (page Modeles) :
METRIQUES = {
    "Random Forest": {"Accuracy": 0.979, "Precision": 0.958, "Rappel": 0.962, "F1-score": 0.960},
    "LSTM":          {"Accuracy": 0.978, "Precision": 0.951, "Rappel": 0.966, "F1-score": 0.958},
}
CONFUSION = {                       # [[VN, FP], [FN, VP]]
    "Random Forest": [[722, 11], [10, 253]],
    "LSTM":          [[720, 13], [9, 254]],
}
# ---------------------------------------------------------------------
LSTM_ACTIF   = True
PORT         = 5000
L            = 10
SUSPECT_PPS  = 40
CALME_PPS    = 15
PROTEGEES = {"2001:4278:19:e9cd::30", "2001:4278:19:e9cd::10", "2001:4278:19:e9cd::253"}
# NOUVELLE SESSION AU DEMARRAGE :
#   True  = le dashboard repart a ZERO a chaque lancement (l'ancien historique
#           n'est pas perdu : il est archive dans le sous-dossier "archives/").
#   False = le dashboard recharge l'historique precedent (mode permanent).
NOUVELLE_SESSION_AU_DEMARRAGE = False
# Les fichiers permanents sont TOUJOURS ecrits a cote de ce script,
# quel que soit le dossier depuis lequel on lance la commande.
DOSSIER   = os.path.dirname(os.path.abspath(__file__))
F_JOURNAL = os.path.join(DOSSIER, "historique_detections.csv")   # permanent (append)
F_ETAT    = os.path.join(DOSSIER, "etat_sauvegarde.json")        # permanent (snapshot)
# Adresse du serveur de controle du controleur Ryu (pour lever les blocages).
CONTROLEUR_URL = "http://127.0.0.1:5001/debloquer_tout"
# =====================================================================

print("Chargement des modeles...")
rf       = joblib.load(os.path.join(DOSSIER, "modele_rf.pkl"))
scaler   = joblib.load(os.path.join(DOSSIER, "scaler.pkl"))
FEATURES = joblib.load(os.path.join(DOSSIER, "features.pkl"))
lstm = None
if LSTM_ACTIF:
    from tensorflow.keras import layers, models
    lstm = models.Sequential([
        layers.Input((L, len(FEATURES))), layers.LSTM(64), layers.Dropout(0.3),
        layers.Dense(32, activation="relu"), layers.Dense(1, activation="sigmoid"),
    ])
    lstm.load_weights(os.path.join(DOSSIER, "poids_lstm.weights.h5"))
    print("LSTM charge (poids).")
print("Modeles prets.")

app = Flask(__name__)
verrou = threading.Lock()
etat = {}
journal = deque(maxlen=200)
attaques_timing = deque(maxlen=25)
glob = {"total": 0, "accord": 0}
inf = {"rf_sum": 0.0, "rf_n": 0, "lstm_sum": 0.0, "lstm_n": 0}
compteur = {"attaques": 0}


# ---------------------- PERSISTANCE (permanence) ----------------------
def nouvelle_session():
    """Archive l'historique precedent, leve les blocages, puis repart a zero."""
    # 1) Demander au controleur de retirer les regles de blocage des commutateurs.
    demander_deblocage_controleur()
    # 2) Archiver les fichiers permanents.
    arch = os.path.join(DOSSIER, "archives")
    horo = time.strftime("%Y%m%d_%H%M%S")
    deplaces = 0
    try:
        os.makedirs(arch, exist_ok=True)
        for f in (F_JOURNAL, F_ETAT):
            if os.path.exists(f):
                base = os.path.basename(f)
                nom, ext = os.path.splitext(base)
                os.rename(f, os.path.join(arch, f"{nom}_{horo}{ext}"))
                deplaces += 1
    except Exception as e:
        print("archive:", e)
    with verrou:
        etat.clear(); journal.clear(); attaques_timing.clear()
        glob["total"] = 0; glob["accord"] = 0
        inf["rf_sum"] = 0.0; inf["rf_n"] = 0
        inf["lstm_sum"] = 0.0; inf["lstm_n"] = 0
        compteur["attaques"] = 0
    return deplaces


def charger_permanent():
    if os.path.exists(F_JOURNAL):
        try:
            with open(F_JOURNAL, newline="") as f:
                for row in csv.DictReader(f):
                    journal.appendleft({"ip": row["source"], "t": row["heure"],
                                        "rf": int(row["rf"]), "lstm": (None if row["lstm"] == "" else int(row["lstm"])),
                                        "reaction": float(row["reaction_s"]), "proto": row["protocole"]})
                    compteur_inc(row.get("protocole", "--"))
        except Exception as e:
            print("journal:", e)
        # remet dans l'ordre chronologique inverse
        items = list(journal); journal.clear()
        for it in reversed(items): journal.appendleft(it)
    if os.path.exists(F_ETAT):
        try:
            with open(F_ETAT) as f:
                d = json.load(f)
            for ip, s in d.get("sources", {}).items():
                etat[ip] = {"hist": deque(maxlen=L), "rf": s.get("rf", 0), "lstm": s.get("lstm"),
                            "feats": s.get("feats", {}), "vu": 0.0, "bloque": s.get("bloque", False),
                            "debut": time.time(), "t_suspect": None, "total": s.get("total", 0.0),
                            "max": s.get("max", 0.0), "proto": s.get("proto", "--"),
                            "r_lstm": None, "timing_ref": None}
            attaques_timing.extend(d.get("timing", []))
            glob.update(d.get("glob", glob))
        except Exception as e:
            print("etat:", e)
    # Le journal CSV fait foi : il est ecrit a chaque detection.
    compteur["attaques"] = len(journal)
    print(f"Historique recharge : {len(journal)} detection(s), "
          f"{sum(1 for e in etat.values() if e['bloque'])} source(s) bloquee(s).")
    print(f"Fichiers permanents : {F_JOURNAL}")


def compteur_inc(proto):
    pass  # place-holder si besoin d'agregats par proto au chargement


def sauver_etat():
    with verrou:
        sources = {ip: {"rf": e["rf"], "lstm": e["lstm"], "feats": e["feats"],
                        "bloque": e["bloque"], "total": e["total"], "max": e["max"],
                        "proto": proto_dominant(e["feats"])} for ip, e in etat.items()}
        data = {"sources": sources, "timing": list(attaques_timing),
                "glob": glob, "attaques": compteur["attaques"]}
    try:
        with open(F_ETAT, "w") as f:
            json.dump(data, f)
    except Exception as e:
        print("save:", e)


def ajouter_journal(entry):
    """Ajoute une detection en memoire ET sur disque (permanent)."""
    journal.appendleft(entry)
    besoin_sauver["v"] = True        # declenche une sauvegarde immediate de l'etat
    nouveau = not os.path.exists(F_JOURNAL)
    try:
        with open(F_JOURNAL, "a", newline="") as f:
            w = csv.writer(f)
            if nouveau:
                w.writerow(["heure", "source", "protocole", "rf", "lstm", "reaction_s"])
            w.writerow([entry["t"], entry["ip"], entry.get("proto", "--"), entry["rf"],
                        "" if entry["lstm"] is None else entry["lstm"], entry["reaction"]])
    except Exception as e:
        print("append:", e)


besoin_sauver = {"v": False}


def _sauver_periodique():
    """Sauvegarde toutes les 10 s, et tout de suite apres une detection."""
    ecoule = 0
    while True:
        time.sleep(2)
        ecoule += 2
        if besoin_sauver["v"] or ecoule >= 10:
            besoin_sauver["v"] = False
            ecoule = 0
            sauver_etat()


# ---------------------------- MODELES ---------------------------------
def _lstm_worker():
    while True:
        time.sleep(1)
        with verrou:
            items = [(ip, list(e["hist"]), e["rf"]) for ip, e in etat.items() if len(e["hist"]) == L]
        for ip, hist, rf_v in items:
            try:
                t0 = time.perf_counter()
                seq = scaler.transform(np.array(hist, dtype=float)).reshape(1, L, len(FEATURES))
                pred = int(lstm.predict(seq, verbose=0).ravel()[0] >= 0.5)
                dt = (time.perf_counter() - t0) * 1000
            except Exception:
                continue
            with verrou:
                if ip not in etat: continue
                e = etat[ip]; e["lstm"] = pred
                inf["lstm_sum"] += dt; inf["lstm_n"] += 1
                glob["total"] += 1
                if pred == rf_v: glob["accord"] += 1
                if pred == 1 and e["t_suspect"] and e["r_lstm"] is None:
                    e["r_lstm"] = round(time.time() - e["t_suspect"], 1)
                    if e["timing_ref"] is not None and e["timing_ref"].get("lstm") is None:
                        e["timing_ref"]["lstm"] = e["r_lstm"]


def predire_rf(h):
    t0 = time.perf_counter()
    r = int(rf.predict(np.array(h, dtype=float).reshape(1, -1))[0])
    inf["rf_sum"] += (time.perf_counter() - t0) * 1000; inf["rf_n"] += 1
    return r


def proto_dominant(f):
    p = [("TCP", float(f.get("f_tcp", 0))), ("UDP", float(f.get("f_udp", 0))), ("ICMPv6", float(f.get("f_icmp", 0)))]
    n, v = max(p, key=lambda x: x[1]); return n if v > 0 else "--"


# ---------------------------- ENDPOINTS -------------------------------
@app.route("/features", methods=["POST"])
def recevoir_features():
    data = request.get_json(force=True); sources = data.get("sources", {})
    rep = {}; now = time.time()
    with verrou:
        for ip, f in sources.items():
            vec = [float(f.get(k, 0)) for k in FEATURES]
            e = etat.setdefault(ip, {"hist": deque(maxlen=L), "rf": 0, "lstm": None, "feats": {},
                                     "vu": 0.0, "bloque": False, "debut": now, "t_suspect": None,
                                     "total": 0.0, "max": 0.0, "proto": "--", "r_lstm": None, "timing_ref": None})
            e["hist"].append(vec); e["feats"] = f; e["vu"] = now
            npaq = float(f.get("n_paq", 0)); e["total"] += npaq
            if npaq > e["max"]: e["max"] = npaq
            if npaq >= SUSPECT_PPS and e["t_suspect"] is None: e["t_suspect"] = now
            elif npaq < CALME_PPS: e["t_suspect"] = None; e["r_lstm"] = None
            protege = ip in PROTEGEES
            if len(e["hist"]) == L:
                e["rf"] = predire_rf(e["hist"])
                if e["rf"] == 1 and not e["bloque"] and not protege:
                    e["bloque"] = True
                    base = e["t_suspect"] or e["debut"]
                    entry = {"ip": ip, "t": time.strftime("%H:%M:%S"), "rf": 1,
                             "lstm": e["lstm"], "reaction": round(now - base, 1),
                             "proto": proto_dominant(f)}
                    e["timing_ref"] = {"ip": ip, "t": entry["t"], "rf": entry["reaction"], "lstm": e["r_lstm"]}
                    attaques_timing.appendleft(e["timing_ref"])
                    compteur["attaques"] += 1
                    ajouter_journal(entry)
            rep[ip] = {"rf": e["rf"], "lstm": e["lstm"], "bloquer": (e["rf"] == 1 and not protege)}
    return jsonify(rep)


@app.route("/state")
def etat_courant():
    now = time.time()
    with verrou:
        srcs = []
        for ip, e in etat.items():
            actif = (now - e["vu"] < 5)
            srcs.append({"ip": ip, "rf": e["rf"], "protege": ip in PROTEGEES,
                         "proto": proto_dominant(e["feats"]),
                         "n_paq": (e["feats"].get("n_paq", 0) if actif else 0),
                         "max": int(e["max"]), "total": int(e["total"]),
                         "bloque": e["bloque"], "actif": actif})
        srcs.sort(key=lambda s: (0 if s["bloque"] else 1, 0 if s["actif"] else 1, -s["total"]))
        acc = round(100 * glob["accord"] / glob["total"]) if glob["total"] else None
        der = journal[0]["reaction"] if journal else None
        return jsonify({"sources": srcs, "journal": list(journal)[:12],
                        "accord_global": acc, "derniere_reaction": der})


@app.route("/modeles_data")
def modeles_data():
    with verrou:
        rf_ms = round(inf["rf_sum"] / inf["rf_n"], 2) if inf["rf_n"] else None
        ls_ms = round(inf["lstm_sum"] / inf["lstm_n"], 1) if inf["lstm_n"] else None
        timing = list(attaques_timing)[:8]
    return jsonify({"metriques": METRIQUES, "confusion": CONFUSION,
                    "inference": {"Random Forest": rf_ms, "LSTM": ls_ms}, "timing": timing})


@app.route("/rapport_data")
def rapport_data():
    with verrou:
        j = list(journal)
        par_proto = {}
        for x in j:
            par_proto[x.get("proto", "--")] = par_proto.get(x.get("proto", "--"), 0) + 1
        reacs = [x["reaction"] for x in j if x.get("reaction") is not None]
        rmoy = round(sum(reacs) / len(reacs), 1) if reacs else None
        bloquees = [{"ip": ip, "proto": proto_dominant(e["feats"]), "max": int(e["max"]),
                     "total": int(e["total"])} for ip, e in etat.items() if e["bloque"]]
        bloquees.sort(key=lambda s: -s["max"])
        return jsonify({"total_attaques": compteur["attaques"], "nb_bloquees": len(bloquees),
                        "reaction_moy": rmoy, "par_proto": par_proto, "bloquees": bloquees})


def _csv_response(entetes, lignes, nom):
    buf = io.StringIO(); w = csv.writer(buf); w.writerow(entetes)
    for l in lignes: w.writerow(l)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={nom}"})


@app.route("/telecharger/journal")
def dl_journal():
    with verrou:
        lignes = [[x["t"], x["ip"], x.get("proto", "--"), x["rf"],
                   "" if x["lstm"] is None else x["lstm"], x["reaction"]] for x in list(journal)]
    return _csv_response(["heure", "source", "protocole", "rf", "lstm", "reaction_s"], lignes, "journal_detections.csv")


@app.route("/telecharger/sources")
def dl_sources():
    with verrou:
        lignes = [[ip, proto_dominant(e["feats"]), int(e["max"]), int(e["total"]),
                   ("attaque" if e["rf"] == 1 else "normal"), ("oui" if e["bloque"] else "non")]
                  for ip, e in etat.items()]
    return _csv_response(["source", "protocole", "pic_pps", "total_paquets", "verdict_rf", "bloquee"], lignes, "tracabilite_sources.csv")


@app.route("/telecharger/rapport")
def dl_rapport():
    with verrou:
        lignes = [["Total attaques detectees", compteur["attaques"]],
                  ["Sources bloquees", sum(1 for e in etat.values() if e["bloque"])]]
        reacs = [x["reaction"] for x in journal if x.get("reaction") is not None]
        if reacs: lignes.append(["Reaction moyenne (s)", round(sum(reacs) / len(reacs), 1)])
        lignes.append([])
        lignes.append(["Sources bloquees", "protocole", "pic_pps", "total_paquets"])
        for ip, e in etat.items():
            if e["bloque"]:
                lignes.append([ip, proto_dominant(e["feats"]), int(e["max"]), int(e["total"])])
    return _csv_response(["Rapport de session", ""], lignes, "rapport_session.csv")


# ---- pages (definies dans la partie 2) ----
# --- pages HTML (integrees) ---
STYLE = """
 *{box-sizing:border-box;margin:0;padding:0}
 :root{--bg:#f4f6f8;--surface:#fff;--ink:#0f1720;--mut:#5f6b78;--line:#e6eaef;
  --em:#2563eb;--em-s:#eff4ff;--em-d:#1d4ed8;--red:#e11d48;--red-s:#fdeaee;
  --amber:#d97706;--amber-s:#fdf1e3;--blue:#0284c7;--blue-s:#e6f4fb;--or:#ea7317}
 body{font-family:Ubuntu,system-ui,sans-serif;background:var(--bg);color:var(--ink);display:flex;min-height:100vh}
 .mono{font-family:'Ubuntu Mono','DejaVu Sans Mono',monospace;font-feature-settings:"tnum"}
 .rail{width:228px;flex:none;background:var(--surface);border-right:1px solid var(--line);padding:22px 15px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
 .mark{display:flex;align-items:center;gap:11px;padding:2px 8px 20px;border-bottom:1px solid var(--line);margin-bottom:16px}
 .mark .g{width:38px;height:38px;border-radius:11px;background:var(--em-s);border:1px solid #c7d7fe;display:flex;align-items:center;justify-content:center;flex:none}
 .mark h1{font-size:.94rem;font-weight:700;line-height:1.15}.mark .s{font-size:.65rem;color:var(--mut);letter-spacing:.04em}
 .nav{display:flex;flex-direction:column;gap:3px}
 .nav a{display:flex;align-items:center;gap:11px;padding:11px 12px;border-radius:10px;text-decoration:none;color:var(--mut);font-size:.85rem;font-weight:600}
 .nav a:hover{background:#f2f5f9}.nav a.on{background:var(--em-s);color:var(--em-d)}
 .rail .end{margin-top:auto;padding-top:14px;border-top:1px solid var(--line)}
 .save{background:var(--em-s);border:1px solid #c7d7fe;border-radius:11px;padding:12px}
 .save .t{display:flex;align-items:center;gap:8px;font-size:.73rem;font-weight:700;color:var(--em-d)}
 .save .t i{width:8px;height:8px;border-radius:50%;background:var(--em)}
 .save .d{font-size:.65rem;color:var(--mut);margin-top:4px;line-height:1.4}
 .main{flex:1;min-width:0;padding:22px 30px}
 .head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:18px}
 .head h2{font-size:1.2rem;font-weight:700}.head .sub{font-size:.76rem;color:var(--mut);margin-top:3px}
 .head .right{display:flex;align-items:center;gap:14px}
 .live{display:inline-flex;align-items:center;gap:7px;font-size:.7rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--em)}
 .live i{width:7px;height:7px;border-radius:50%;background:var(--em);animation:b 2s infinite}
 @keyframes b{0%,100%{opacity:1}50%{opacity:.35}}
 .clock{font-size:.92rem;font-weight:600}
 .posture{display:flex;align-items:center;justify-content:space-between;gap:20px;background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--em);border-radius:16px;padding:18px 22px;margin-bottom:16px}
 .posture.alert{border-left-color:var(--red)}
 .posture .l{display:flex;align-items:center;gap:16px}
 .posture .badge{width:48px;height:48px;border-radius:13px;background:var(--em-s);display:flex;align-items:center;justify-content:center;flex:none}
 .posture.alert .badge{background:var(--red-s)}
 .posture .st{font-size:1.12rem;font-weight:700}.posture .ds{font-size:.78rem;color:var(--mut);margin-top:3px}
 .posture .r{display:flex;align-items:center;gap:18px}
 .posture .spark{width:150px;height:52px;display:block}
 .posture .pps{font-size:1.5rem;font-weight:700;text-align:right}
 .posture .pps small{display:block;font-size:.62rem;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-top:2px}
 .cols{display:grid;grid-template-columns:1.6fr 1fr;gap:16px}
 @media(max-width:1040px){.cols{grid-template-columns:1fr}}
 .two{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:900px){.two{grid-template-columns:1fr}}
 .card{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:16px 18px;margin-bottom:16px}
 .ct{display:flex;justify-content:space-between;align-items:center;margin-bottom:13px}
 .ct h3{font-size:.82rem;font-weight:700}.ct .d{font-size:.7rem;color:var(--mut)}
 .dl{font-size:.72rem;font-weight:600;color:var(--em-d);text-decoration:none;display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border-radius:7px;border:1px solid #c7d7fe;background:var(--em-s)}
 .dl:hover{background:#dbe6ff}
 .raz{font-family:inherit;font-size:.72rem;font-weight:600;color:#be123c;background:#fdeaee;border:1px solid #f0c9d2;border-radius:7px;padding:6px 10px;cursor:pointer}
 .raz:hover{background:#fbd9e0}
 canvas.big{width:100%;height:150px;display:block}
 .stat{display:flex;justify-content:space-between;align-items:center;padding:12px 2px;border-bottom:1px solid #eef2f6}
 .stat:last-child{border-bottom:0}
 .stat .k{font-size:.78rem;color:var(--mut);font-weight:600}
 .stat .v{font-size:1.35rem;font-weight:700}.stat .v small{font-size:.82rem;color:var(--mut)}
 table{width:100%;border-collapse:collapse;font-size:.82rem}
 thead th{text-align:left;padding:0 8px 9px;font-size:.62rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);border-bottom:1px solid var(--line)}
 tbody td{padding:11px 8px;border-bottom:1px solid #f1f4f8}tbody tr:last-child td{border-bottom:0}
 .ipc{font-family:'Ubuntu Mono','DejaVu Sans Mono',monospace;font-size:.77rem;color:#22303c}
 .proto{font-size:.64rem;font-weight:700;color:#556;background:#eef2f6;padding:2px 7px;border-radius:5px}
 .tag{font-size:.64rem;font-weight:700;padding:3px 9px;border-radius:6px}
 .t-att{background:var(--red-s);color:#be123c}.t-norm{background:var(--em-s);color:var(--em-d)}.t-prot{background:var(--blue-s);color:#0369a1}
 .state{display:inline-flex;align-items:center;gap:7px;font-size:.74rem;color:#3a4652}.state i{width:7px;height:7px;border-radius:50%}
 .s-b i{background:var(--red)}.s-p i{background:var(--blue)}.s-a i{background:var(--em)}.s-i i{background:#aab4bf}
 tr.row-b td{background:#fdf5f6}
 .ev{display:flex;justify-content:space-between;gap:10px;padding:11px 2px;border-bottom:1px solid #f1f4f8}.ev:last-child{border-bottom:0}
 .ev .ip{font-family:'Ubuntu Mono','DejaVu Sans Mono',monospace;font-size:.77rem;color:#be123c;font-weight:600}
 .ev .meta{font-size:.66rem;color:var(--mut);margin-top:3px}
 .ev .tm{font-family:'Ubuntu Mono','DejaVu Sans Mono',monospace;font-size:.74rem;color:var(--mut)}
 .vide{color:var(--mut);font-size:.8rem;padding:14px 4px;text-align:center}
 .lg{display:flex;gap:18px;margin-top:10px;font-size:.76rem;color:#48545f}
 .lg span span{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:5px;vertical-align:middle}
 .hl{background:var(--em-s);border:1px solid #c7d7fe;border-radius:10px;padding:11px 13px;font-size:.78rem;color:var(--em-d);margin-top:10px}
 .cm{display:grid;grid-template-columns:auto auto auto;gap:4px;font-size:.8rem}
 .cm div{padding:13px;text-align:center;border-radius:6px}
 .cm .h{background:transparent;color:var(--mut);font-size:.64rem;font-weight:600;display:flex;align-items:center;justify-content:center}
 @media (prefers-reduced-motion: reduce){*{animation:none!important}}
"""

RAIL = """<aside class="rail">
 <div class="mark"><div class="g"><svg width="21" height="21" viewBox="0 0 32 32" fill="none"><path d="M16 3l11 4v7c0 7-4.7 12.2-11 15C9.7 26.2 5 21 5 14V7l11-4z" stroke="#2563eb" stroke-width="1.7"/><path d="M11 15l3.5 3.5L21 12" stroke="#2563eb" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
  <div><h1>Detection DDoS</h1><div class="s">SDN &middot; IPv6</div></div></div>
 <nav class="nav">
  <a href="/" class="__TR__"><svg width="17" height="17" viewBox="0 0 24 24" fill="none"><path d="M3 12h4l2 6 4-14 2 8h6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg> Temps reel</a>
  <a href="/modeles" class="__MD__"><svg width="17" height="17" viewBox="0 0 24 24" fill="none"><path d="M4 20V10M10 20V4M16 20v-7M20 20H3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg> Modeles</a>
  <a href="/rapport" class="__RP__"><svg width="17" height="17" viewBox="0 0 24 24" fill="none"><path d="M8 3h8l4 4v14H4V3z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M8 12h8M8 16h5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg> Rapport</a>
 </nav>
 <div class="end"><div class="save"><div class="t"><i></i> Donnees permanentes</div><div class="d">Historique ecrit sur disque, conserve au redemarrage.</div></div></div>
</aside>"""

CHARTS = """
function area(id,pts,col,fill){var c=document.getElementById(id);if(!c)return;var x=c.getContext('2d'),W=c.width,H=c.height,m=Math.max(20,...pts);
 var P=pts.map(function(v,i){return [i/(pts.length-1)*W,H-(v/m)*(H-14)-7];});var g=x.createLinearGradient(0,0,0,H);g.addColorStop(0,fill);g.addColorStop(1,'rgba(0,0,0,0)');
 x.clearRect(0,0,W,H);x.strokeStyle='rgba(16,24,40,.05)';x.lineWidth=1;for(var i=1;i<4;i++){var y=H/4*i;x.beginPath();x.moveTo(0,y);x.lineTo(W,y);x.stroke();}
 x.beginPath();P.forEach(function(p,i){i?x.lineTo(p[0],p[1]):x.moveTo(p[0],p[1]);});x.lineTo(W,H);x.lineTo(0,H);x.closePath();x.fillStyle=g;x.fill();
 x.beginPath();P.forEach(function(p,i){i?x.lineTo(p[0],p[1]):x.moveTo(p[0],p[1]);});x.strokeStyle=col;x.lineWidth=2.1;x.stroke();
 x.fillStyle='#9aa7b2';x.font='11px monospace';x.fillText('max '+m,8,15);}
function bars(id,labels,A,B,y0,y1,cA,cB,fmt){var c=document.getElementById(id);if(!c)return;var x=c.getContext('2d'),W=c.width,H=c.height,pad=44;
 x.clearRect(0,0,W,H);if(!labels.length){x.fillStyle='#9aa7b2';x.font='12px sans-serif';x.fillText('En attente de donnees...',pad,H/2);return;}
 var gw=(W-pad*2)/labels.length,bw=B?gw*0.28:gw*0.42;
 x.strokeStyle='rgba(16,24,40,.07)';x.fillStyle='#9aa7b2';x.font='10px sans-serif';x.textAlign='left';
 for(var s=0;s<=4;s++){var v=y0+(y1-y0)*s/4,y=H-26-((v-y0)/(y1-y0))*(H-46);x.beginPath();x.moveTo(pad,y);x.lineTo(W-8,y);x.stroke();x.fillText(fmt(v),4,y+3);}
 labels.forEach(function(lb,i){var cx=pad+gw*i+gw/2,ya=H-26-((A[i]-y0)/(y1-y0))*(H-46);
  if(B){var yb=H-26-((B[i]-y0)/(y1-y0))*(H-46);x.fillStyle=cA;x.fillRect(cx-bw-2,ya,bw,H-26-ya);x.fillStyle=cB;x.fillRect(cx+2,yb,bw,H-26-yb);
   x.fillStyle='#0f1720';x.font='bold 9px sans-serif';x.textAlign='center';x.fillText(fmt(A[i]),cx-bw/2-2,ya-3);x.fillText(fmt(B[i]),cx+bw/2+2,yb-3);}
  else{x.fillStyle=cA;x.fillRect(cx-bw/2,ya,bw,H-26-ya);x.fillStyle='#0f1720';x.font='bold 10px sans-serif';x.textAlign='center';x.fillText(fmt(A[i]),cx,ya-4);}
  x.fillStyle='#48545f';x.font='11px sans-serif';x.fillText(lb,cx,H-9);x.textAlign='left';});}
function clk(){var e=document.getElementById('clk');if(e)e.textContent=new Date().toLocaleTimeString('fr-FR');}setInterval(clk,1000);clk();
"""


def shell(active, titre, sous, live, contenu, script):
    rail = (RAIL.replace("__TR__", "on" if active == "tr" else "")
                .replace("__MD__", "on" if active == "md" else "")
                .replace("__RP__", "on" if active == "rp" else ""))
    liveh = ('<span class="live"><i></i> En direct</span><span class="clock mono" id="clk">--:--:--</span>'
             if live else '<span class="clock mono" id="clk">--:--:--</span>')
    return ("<!DOCTYPE html><html lang=\"fr\"><head><meta charset=\"UTF-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>" + titre + " - Detection DDoS</title><style>" + STYLE + "</style></head><body>"
            + rail +
            "<main class=\"main\"><div class=\"head\"><div><h2>" + titre + "</h2>"
            "<div class=\"sub\">" + sous + "</div></div><div class=\"right\">" + liveh + "</div></div>"
            + contenu + "</main><script>" + CHARTS + script + "</script></body></html>")


# ============================ PAGE TEMPS REEL =========================
_TR_CONTENU = """
<section class="posture" id="posture">
 <div class="l"><div class="badge" id="p-badge"></div><div><div class="st" id="p-st">Reseau sous surveillance</div><div class="ds" id="p-ds">Aucune attaque en cours.</div></div></div>
 <div class="r"><canvas class="spark" id="spark" width="150" height="52"></canvas><div class="pps"><span class="mono" id="p-pps">0</span><small>paquets/s</small></div></div>
</section>
<div class="cols">
 <div>
  <div class="card"><div class="ct"><h3>Trafic reseau (paquets/s)</h3></div><canvas class="big" id="chart" width="820" height="150"></canvas></div>
  <div class="card"><div class="ct"><h3>Tracabilite des sources</h3><a class="dl" href="/telecharger/sources"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg> Telecharger CSV</a></div>
   <table><thead><tr><th>Source</th><th>Proto</th><th>Paq/s</th><th>Max</th><th>Total</th><th>Random Forest</th><th>Etat</th></tr></thead><tbody id="tb"><tr><td colspan="7" class="vide">En attente de trafic...</td></tr></tbody></table>
  </div>
 </div>
 <div>
  <div class="card"><div class="ct"><h3>Indicateurs</h3></div>
   <div class="stat"><span class="k">Sources actives</span><span class="v mono" id="c-act">0</span></div>
   <div class="stat"><span class="k">Attaques detectees</span><span class="v mono" id="c-att" style="color:var(--red)">0</span></div>
   <div class="stat"><span class="k">Sources bloquees</span><span class="v mono" id="c-blo" style="color:var(--amber)">0</span></div>
   <div class="stat"><span class="k">Accord RF - LSTM</span><span class="v mono" id="c-acc" style="color:var(--em)">--</span></div>
   <div class="stat"><span class="k">Temps de reaction</span><span class="v mono" id="c-rea">--</span></div>
  </div>
  <div class="card"><div class="ct"><h3>Journal des detections</h3><a class="dl" href="/telecharger/journal"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg> CSV</a><a class="dl" href="#" id="btn-raz" style="border-color:#f0c9d2;background:#fdeaee;color:#be123c;margin-left:6px"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M4 5v6h6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 11a8 8 0 113 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg> Reinitialiser</a></div><div id="jr"><div class="vide">Aucune detection.</div></div></div>
 </div>
</div>
"""
_TR_SCRIPT = """
var hist=[];
function tagRF(v,p){return p?'<span class="tag t-prot">PROTEGEE</span>':(v===1?'<span class="tag t-att">ATTAQUE</span>':'<span class="tag t-norm">NORMAL</span>');}
function etatC(s){if(s.protege)return '<span class="state s-p"><i></i>Protegee</span>';if(s.bloque)return '<span class="state s-b"><i></i>Bloquee</span>';if(s.actif)return '<span class="state s-a"><i></i>Active</span>';return '<span class="state s-i"><i></i>Inactive</span>';}
async function tick(){try{
 var d=await(await fetch('/state')).json();var S=d.sources,att=0,blo=0,tot=0,act=0,rows='';
 S.forEach(function(s){if(!s.protege&&s.rf===1)att++;if(s.bloque)blo++;if(s.actif)act++;tot+=(+s.n_paq||0);
  rows+='<tr class="'+(s.bloque?'row-b':'')+'"><td class="ipc">'+s.ip+'</td><td><span class="proto">'+s.proto+'</span></td><td class="mono">'+s.n_paq+'</td><td class="mono">'+s.max+'</td><td class="mono">'+s.total+'</td><td>'+tagRF(s.rf,s.protege)+'</td><td>'+etatC(s)+'</td></tr>';});
 document.getElementById('tb').innerHTML=rows||'<tr><td colspan="7" class="vide">En attente de trafic...</td></tr>';
 document.getElementById('c-act').textContent=act;document.getElementById('c-att').textContent=att;document.getElementById('c-blo').textContent=blo;
 document.getElementById('c-acc').textContent=(d.accord_global===null?'--':d.accord_global+'%');
 document.getElementById('c-rea').textContent=(d.derniere_reaction===null?'--':d.derniere_reaction+'s');
 document.getElementById('p-pps').textContent=tot;
 var pos=document.getElementById('posture');
 if(blo>0){pos.classList.add('alert');document.getElementById('p-badge').innerHTML='<svg width=24 height=24 viewBox="0 0 24 24" fill=none><path d="M12 3l9 16H3L12 3z" stroke="#e11d48" stroke-width="1.9" stroke-linejoin="round"/><path d="M12 10v4M12 17v.5" stroke="#e11d48" stroke-width="2" stroke-linecap="round"/></svg>';
  document.getElementById('p-st').textContent='Attaque en cours - '+blo+' source(s) neutralisee(s)';document.getElementById('p-ds').textContent='Le trafic malveillant est bloque ; le serveur reste accessible.';}
 else{pos.classList.remove('alert');document.getElementById('p-badge').innerHTML='<svg width=24 height=24 viewBox="0 0 24 24" fill=none><path d="M12 3l9 4v6c0 5-3.5 8.5-9 10-5.5-1.5-9-5-9-10V7l9-4z" stroke="#2563eb" stroke-width="1.8"/><path d="M9 12l2 2 4-4" stroke="#2563eb" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  document.getElementById('p-st').textContent='Reseau protege';document.getElementById('p-ds').textContent='Aucune attaque en cours.';}
 var jr=d.journal;document.getElementById('jr').innerHTML=jr.length?jr.map(function(j){return '<div class="ev"><div><div class="ip">'+j.ip+'</div><div class="meta">RF '+(j.rf===1?'attaque':'normal')+' &middot; LSTM '+(j.lstm===1?'attaque':(j.lstm===0?'normal':'--'))+' &middot; '+j.reaction+'s</div></div><div class="tm">'+j.t+'</div></div>';}).join(''):'<div class="vide">Aucune detection.</div>';
 hist.push(tot);if(hist.length>64)hist.shift();area('chart',hist,'#2563eb','rgba(37,99,235,.14)');area('spark',hist.slice(-24),(blo>0?'#e11d48':'#2563eb'),(blo>0?'rgba(225,29,72,.16)':'rgba(37,99,235,.16)'));
}catch(e){}}
setInterval(tick,1000);tick();
document.getElementById('btn-raz').addEventListener('click',async function(e){e.preventDefault();
 if(!confirm("Vider le dashboard et lever tous les blocages ? L'historique sera archive dans le dossier archives/."))return;
 try{await fetch('/reinitialiser',{method:'POST'});hist=[];tick();}catch(err){}});
"""
PAGE_TR = shell("tr", "Temps reel", "Surveillance et mitigation - decision par Random Forest", True, _TR_CONTENU, _TR_SCRIPT)


# ============================ PAGE MODELES ============================
_MD_CONTENU = """
<div class="card"><div class="ct"><div><h3>Comparaison des performances</h3><div class="d">Evaluation hors ligne sur le jeu de test</div></div></div>
 <canvas class="big" id="bar" width="900" height="240" style="height:240px"></canvas>
 <div class="lg"><span><span style="background:#2563eb"></span>Random Forest</span><span><span style="background:#ea7317"></span>LSTM</span></div></div>
<div class="two">
 <div class="card"><div class="ct"><div><h3>Temps d'inference (ms)</h3><div class="d">Vitesse de calcul mesuree en direct</div></div><button id="btn-raz" class="raz">Reinitialiser</button></div>
  <canvas id="inf" width="440" height="200" style="width:100%;height:200px"></canvas>
  <div class="hl" id="inf-note">Mesure en cours...</div></div>
 <div class="card"><div class="ct"><div><h3>Temps de detection par attaque (s)</h3><div class="d">Delai entre debut de l'attaque et detection</div></div></div>
  <canvas id="det" width="440" height="200" style="width:100%;height:200px"></canvas>
  <div class="lg"><span><span style="background:#2563eb"></span>Random Forest</span><span><span style="background:#ea7317"></span>LSTM</span></div></div>
</div>
<div class="two">
 <div class="card"><div class="ct"><h3>Matrice de confusion - Random Forest</h3></div><div id="cmrf" class="cm"></div></div>
 <div class="card"><div class="ct"><h3>Matrice de confusion - LSTM</h3></div><div id="cmls" class="cm"></div></div>
</div>
"""
_MD_SCRIPT = """
function cm(id,M){var mx=Math.max(M[0][0],M[0][1],M[1][0],M[1][1]);function cc(v,d){var a=.12+.6*(v/mx);return d?'background:rgba(37,99,235,'+a+')':'background:rgba(225,29,72,'+a+')';}
 document.getElementById(id).innerHTML='<div class="h"></div><div class="h">Pred. Normal</div><div class="h">Pred. Attaque</div>'+
 '<div class="h">Vrai Normal</div><div style="'+cc(M[0][0],1)+'"><b>'+M[0][0]+'</b></div><div style="'+cc(M[0][1],0)+'">'+M[0][1]+'</div>'+
 '<div class="h">Vrai Attaque</div><div style="'+cc(M[1][0],0)+'">'+M[1][0]+'</div><div style="'+cc(M[1][1],1)+'"><b>'+M[1][1]+'</b></div>';}
async function load(){var d=await(await fetch('/modeles_data')).json();
 var mk=Object.keys(d.metriques['Random Forest']);
 bars('bar',mk,mk.map(function(k){return d.metriques['Random Forest'][k];}),mk.map(function(k){return d.metriques['LSTM'][k];}),.80,1.0,'#2563eb','#ea7317',function(v){return v.toFixed(3);});
 var rf=d.inference['Random Forest'],ls=d.inference['LSTM'];
 bars('inf',['Random Forest','LSTM'],[rf||0,ls||0],null,0,Math.max(20,(ls||10)*1.15),'#2563eb',null,function(v){return v.toFixed(1);});
 if(rf&&ls){document.getElementById('inf-note').textContent='Le Random Forest est environ '+Math.round(ls/rf)+'x plus rapide - d\\'ou son choix pour le temps reel.';}
 var T=d.timing;if(T&&T.length){var labs=T.map(function(_,i){return 'Att. '+(T.length-i);}).reverse();var Ar=T.map(function(t){return t.rf||0;}).reverse();var Bl=T.map(function(t){return t.lstm||0;}).reverse();
  bars('det',labs,Ar,Bl,0,Math.max(14,...Ar,...Bl)*1.1,'#2563eb','#ea7317',function(v){return v.toFixed(1);});}
 else{bars('det',[],[],[],0,14,'#2563eb','#ea7317',function(v){return v;});}
 cm('cmrf',d.confusion['Random Forest']);cm('cmls',d.confusion['LSTM']);}
load();setInterval(load,4000);
document.getElementById('btn-raz').addEventListener('click',async function(e){e.preventDefault();
 if(!confirm("Reinitialiser l'historique ?\\n\\nLes blocages seront leves et les donnees archivees dans 'archives/', puis le dashboard repartira a zero.")) return;
 try{await fetch('/reinitialiser',{method:'POST'});load();}catch(err){}});
"""
PAGE_MD = shell("md", "Modeles", "Performances et temps de reaction - Random Forest vs LSTM", False, _MD_CONTENU, _MD_SCRIPT)


# ============================ PAGE RAPPORT ============================
_RP_CONTENU = """
<div class="two">
 <div class="card"><div class="ct"><h3>Bilan de la session</h3><a class="dl" href="/telecharger/rapport"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg> Telecharger le rapport</a></div>
  <div class="stat"><span class="k">Total d'attaques detectees</span><span class="v mono" id="r-tot" style="color:var(--red)">0</span></div>
  <div class="stat"><span class="k">Sources bloquees (uniques)</span><span class="v mono" id="r-blo" style="color:var(--amber)">0</span></div>
  <div class="stat"><span class="k">Temps de reaction moyen</span><span class="v mono" id="r-rea">--</span></div>
 </div>
 <div class="card"><div class="ct"><div><h3>Attaques par protocole</h3><div class="d">Repartition des detections</div></div></div>
  <canvas id="proto" width="440" height="200" style="width:100%;height:200px"></canvas></div>
</div>
<div class="card"><div class="ct"><h3>Sources bloquees</h3></div>
 <table><thead><tr><th>Source</th><th>Protocole</th><th>Pic (paq/s)</th><th>Total paquets</th></tr></thead><tbody id="rtb"><tr><td colspan="4" class="vide">Aucune source bloquee pour l'instant.</td></tr></tbody></table>
</div>
<div class="card"><div class="ct"><div><h3>Gestion de l'historique</h3><div class="d">Efface le journal, la tracabilite et les fichiers permanents</div></div>
 <button id="btn-raz" class="raz">Reinitialiser l'historique</button></div>
 <div class="d" id="raz-msg" style="font-size:.74rem;color:var(--mut)">Cette action leve aussi les blocages en cours sur les commutateurs.</div>
</div>
"""
_RP_SCRIPT = """
async function load(){var d=await(await fetch('/rapport_data')).json();
 document.getElementById('r-tot').textContent=d.total_attaques;
 document.getElementById('r-blo').textContent=d.nb_bloquees;
 document.getElementById('r-rea').textContent=(d.reaction_moy===null?'--':d.reaction_moy+'s');
 var P=d.par_proto,labs=Object.keys(P),vals=labs.map(function(k){return P[k];});
 bars('proto',labs,vals,null,0,Math.max(5,...vals)*1.2,'#2563eb',null,function(v){return v.toFixed(0);});
 var B=d.bloquees;document.getElementById('rtb').innerHTML=B.length?B.map(function(s){return '<tr><td class="ipc">'+s.ip+'</td><td><span class="proto">'+s.proto+'</span></td><td class="mono">'+s.max+'</td><td class="mono">'+s.total+'</td></tr>';}).join(''):'<tr><td colspan="4" class="vide">Aucune source bloquee pour l\\'instant.</td></tr>';}
load();setInterval(load,4000);
document.getElementById('btn-raz').addEventListener('click',async function(e){e.preventDefault();
 if(!confirm("Reinitialiser l'historique ?\\n\\nLes blocages seront leves et les donnees archivees dans 'archives/', puis le dashboard repartira a zero.")) return;
 try{await fetch('/reinitialiser',{method:'POST'});load();}catch(err){}});
"""
PAGE_RP = shell("rp", "Rapport", "Bilan de session - synthese de l'activite", False, _RP_CONTENU, _RP_SCRIPT)


@app.route("/")
def index():      return Response(PAGE_TR, mimetype="text/html")
@app.route("/modeles")
def p_modeles():  return Response(PAGE_MD, mimetype="text/html")
@app.route("/rapport")
def p_rapport():  return Response(PAGE_RP, mimetype="text/html")


@app.route("/reinitialiser", methods=["POST"])
def reinitialiser():
    n = nouvelle_session()
    print(f"Dashboard reinitialise ({n} fichier(s) archive(s)).")
    return jsonify({"ok": True, "archives": n})


if __name__ == "__main__":
    if NOUVELLE_SESSION_AU_DEMARRAGE:
        n = nouvelle_session()
        print(f"Nouvelle session : dashboard vide ({n} fichier(s) archive(s) dans 'archives/').")
    else:
        charger_permanent()
    import atexit
    atexit.register(sauver_etat)          # sauvegarde propre a l'arret (Ctrl+C)
    threading.Thread(target=_sauver_periodique, daemon=True).start()
    if lstm is not None:
        threading.Thread(target=_lstm_worker, daemon=True).start()
        print("Worker LSTM (arriere-plan) demarre.")
    print(f"Dashboard : http://127.0.0.1:{PORT}/  (Temps reel | Modeles | Rapport)")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
