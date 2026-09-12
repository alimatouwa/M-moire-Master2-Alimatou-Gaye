# 🛡️ Détection et mitigation des attaques DDoS sur réseaux IPv6

> Mémoire de Master 2 — Université Alioune Diop de Bambey (UFR SATIC)
> **Autrice :** Alimatou Gaye — **Encadrant :** Docteur Sada Anne

Détection et mitigation automatisées des attaques DDoS sur réseaux **IPv6** par **apprentissage automatique**, dans une architecture **SDN-OpenFlow**.

---

## 💡 Le principe

Le contrôleur SDN capture le trafic et calcule des caractéristiques pour chaque source. Un modèle d'apprentissage automatique analyse ces caractéristiques et décide si la source est en train d'attaquer. Si c'est le cas, le contrôleur installe une règle qui bloque la source directement sur les commutateurs, sans couper le service pour les utilisateurs légitimes.

Deux modèles ont été entraînés et comparés : un **Random Forest** et un **LSTM**. Le Random Forest a été retenu pour le temps réel car il est plus rapide.

## 📂 Contenu du dépôt

| Fichier | Rôle |
|---------|------|
| `code_controleur_ryu.py` | Contrôleur SDN (Ryu) : capture, calcul des caractéristiques, blocage |
| `service_detection.py` | Service de détection + tableau de bord |
| `pretraitement_et_entrainement_des_modeles.ipynb` | Préparation des données et entraînement des modèles |
| `traficNormal.csv` | Données de trafic normal |
| `TAnormal.csv` | Données de trafic d'attaque |

## ▶️ Lancer le système

**Le contrôleur :**
```bash
ryu-manager code_controleur_ryu.py --ofp-tcp-listen-port 6633 --ofp-listen-host ::
```

**Le service et le tableau de bord :**
```bash
python3 service_detection.py
```
Tableau de bord accessible sur `http://127.0.0.1:5000/`

## 🧰 Environnement

GNS3 · VirtualBox · Ryu (OpenFlow 1.3) · Open vSwitch · NAT64 (Tayga) · Python 3 (scikit-learn, TensorFlow/Keras)

## 📊 Résultats

Jeu de données : **160 180 paquets** capturés, agrégés en **3 517 fenêtres** puis **3 317 séquences**.

| Mesure | Random Forest | LSTM |
|--------|:-------------:|:----:|
| Exactitude | 0,979 | 0,978 |
| Précision | 0,958 | 0,951 |
| Rappel | 0,962 | 0,966 |
| F1-score | 0,960 | 0,958 |
| Temps d'inférence | ~64 ms | ~149 ms |

Les deux modèles se valent en performance. Le **Random Forest**, plus rapide, a été choisi pour la détection en temps réel.
