<div align="center">

# 🛡️ Détection et mitigation automatisées des attaques DDoS sur réseaux IPv6

### par apprentissage automatique dans une architecture SDN-OpenFlow

![IPv6](https://img.shields.io/badge/IPv6-2C2C2C?style=for-the-badge)
![SDN](https://img.shields.io/badge/SDN-Ryu-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3-yellow?style=for-the-badge&logo=python&logoColor=white)
![Machine Learning](https://img.shields.io/badge/ML-RandomForest%20%7C%20LSTM-green?style=for-the-badge)

**Mémoire de Master 2**

👩‍🎓 **Autrice :** Alimatou Gaye  •  👨‍🏫 **Encadrant :** Docteur Sada Anne
🏛️ **Université Alioune Diop de Bambey — UFR SATIC**

</div>

---

## 📖 Présentation

Ce projet propose un système capable de **détecter** et de **bloquer automatiquement** les attaques par déni de service distribué (**DDoS**) dans un réseau **IPv6**, au sein d'une architecture **SDN** (Software Defined Networking).

Le principe est le suivant : le contrôleur SDN capture le trafic, calcule des caractéristiques par source, puis interroge un modèle d'apprentissage automatique qui décide si une source est malveillante. Le cas échéant, le contrôleur installe automatiquement une règle de blocage sur les commutateurs, tout en préservant la disponibilité du service.

Deux modèles ont été entraînés et comparés :
- 🌳 un **Random Forest** (modèle classique), retenu pour la détection en temps réel grâce à sa rapidité ;
- 🧠 un **LSTM** (modèle temporel), utilisé à des fins de comparaison.

---

## 📂 Contenu du dépôt

| Fichier | Description |
|---|---|
| `code_controleur_ryu.py` | Contrôleur SDN (Ryu) : capture du trafic, calcul des caractéristiques et application des blocages. |
| `service_detection.py` | Service de détection (Flask) : héberge les modèles et le tableau de bord de supervision. |
| `pretraitement_et_entrainement_des_modeles.ipynb` | Notebook de prétraitement, d'entraînement et d'évaluation des modèles. |
| `traficNormal.csv` | Jeu de données — trafic normal. |
| `TAnormal.csv` | Jeu de données — trafic d'attaque. |

---

## ⚙️ Environnement technique

| Composant | Outil |
|---|---|
| Simulation réseau | GNS3 + VirtualBox |
| Contrôleur SDN | Ryu (OpenFlow 1.3) |
| Commutateurs | Open vSwitch |
| Traduction IPv4 ↔ IPv6 | NAT64 (Tayga) |
| Apprentissage automatique | scikit-learn (Random Forest), TensorFlow/Keras (LSTM) |
| Langage | Python 3 |

---

## 🚀 Utilisation

**1. Lancer le contrôleur SDN**
```bash
ryu-manager code_controleur_ryu.py --ofp-tcp-listen-port 6633 --ofp-listen-host ::
```

**2. Lancer le service de détection et le tableau de bord**
```bash
python3 service_detection.py
```
> Le tableau de bord est ensuite accessible à l'adresse : `http://127.0.0.1:5000/`

**3. Générer une attaque de test** (depuis la machine attaquante)
```bash
sudo python3 generateur_trafic_attaque.py
```

---

## 📊 Le jeu de données

Constitué spécialement pour ce travail, faute de corpus public adapté aux attaques DDoS en IPv6 :

- **160 180 paquets** capturés au niveau du commutateur cœur ;
- agrégés en **3 517 fenêtres** d'une seconde (2 624 normales · 893 d'attaque) ;
- puis en **3 317 séquences** de dix fenêtres pour l'entraînement.

---

## 🎯 Résultats

| Mesure | 🌳 Random Forest | 🧠 LSTM |
|---|:---:|:---:|
| Exactitude | **0,979** | 0,978 |
| Précision | **0,958** | 0,951 |
| Rappel | 0,962 | **0,966** |
| F1-score | **0,960** | 0,958 |
| Temps d'inférence | **~64 ms** | ~149 ms |

> Les deux modèles offrent des performances proches. Le **Random Forest** a été retenu pour le déploiement en temps réel en raison de son temps d'inférence nettement plus faible.

---

<div align="center">

*Mémoire de Master 2 — Université Alioune Diop de Bambey — 2025/2026*

</div>
