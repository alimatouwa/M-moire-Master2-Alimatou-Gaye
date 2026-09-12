# Mémoire Master 2 — Détection et mitigation des attaques DDoS sur réseaux IPv6

Ce dépôt contient le code et les données de mon mémoire de Master 2, réalisé à l'Université Alioune Diop de Bambey (UFR SATIC).

**Sujet :** Détection et mitigation automatisées des attaques DDoS sur réseaux IPv6 par apprentissage automatique dans une architecture SDN-OpenFlow.

**Autrice :** Alimatou Gaye
**Encadrant :** Docteur Sada Anne

## De quoi il s'agit

L'objectif de ce travail est de détecter et de bloquer automatiquement les attaques DDoS dans un réseau IPv6, à l'aide de l'apprentissage automatique et d'une architecture SDN.

Le contrôleur SDN capture le trafic et calcule des caractéristiques pour chaque source. Ces caractéristiques sont envoyées à un modèle qui décide si la source est en train d'attaquer. Si c'est le cas, le contrôleur installe une règle qui bloque cette source directement sur les commutateurs, sans couper le service pour les autres utilisateurs.

Deux modèles ont été entraînés et comparés : un Random Forest et un LSTM. Le Random Forest a finalement été choisi pour le temps réel car il est plus rapide.

## Les fichiers

- `code_controleur_ryu.py` : le contrôleur SDN (Ryu). Il capture le trafic, calcule les caractéristiques et applique les blocages.
- `service_detection.py` : le service qui contient les modèles et le tableau de bord.
- `pretraitement_et_entrainement_des_modeles.ipynb` : le notebook où les données sont préparées et où les modèles sont entraînés et évalués.
- `traficNormal.csv` : les données de trafic normal.
- `TAnormal.csv` : les données de trafic d'attaque.

## Comment lancer le système

Lancer le contrôleur :
```
ryu-manager code_controleur_ryu.py --ofp-tcp-listen-port 6633 --ofp-listen-host ::
```

Lancer le service et le tableau de bord :
```
python3 service_detection.py
```
Le tableau de bord est ensuite accessible sur http://127.0.0.1:5000/

## Environnement utilisé

Le projet a été réalisé sous GNS3 et VirtualBox, avec le contrôleur Ryu (OpenFlow 1.3), des commutateurs Open vSwitch et une passerelle NAT64 (Tayga). Les modèles ont été développés en Python avec scikit-learn pour le Random Forest et TensorFlow/Keras pour le LSTM.

## Quelques résultats

Le jeu de données a été constitué à partir de 160 180 paquets capturés, regroupés en 3 517 fenêtres puis en 3 317 séquences.

Les deux modèles atteignent une exactitude d'environ 98 %. Leurs performances sont proches, mais le Random Forest est nettement plus rapide (environ 64 ms contre 149 ms pour le LSTM), ce qui explique son choix pour la détection en temps réel.
