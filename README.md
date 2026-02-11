# Système de Chiffrement de Données - TP3
## Présentation du Projet
Ce projet est une simulation de ransomware pédagogique réalisée dans le cadre du TP3. Il démontre les étapes critiques d'une cyberattaque : la génération de clés sécurisées, l'exfiltration de données vers un serveur distant (Kali Linux) et le chiffrement récursif de fichiers "in-place".

## Fonctionnalités
Le script main.py est divisé en plusieurs modules correspondant aux exigences du sujet :

**Vérification du Système (Partie A) :** Contrôle de la version de Python (3.8+) et installation automatique des dépendances (cryptography, paramiko).

**Menu Principal (Partie B) :** Mise en place d'un menu textuel interactif permettant de piloter les différentes fonctionnalités du programme.

**Gestion des Clés (Partie C) :** Génération de clés AES/PBKDF2 de 128, 192 ou 256 bits, stockées localement dans /var/keys/ avec des permissions restreintes (0o700 pour le dossier, 0o600 pour le fichier).

**Exfiltration SFTP (Partie D) :** Transfert sécurisé de la clé vers un serveur distant via SSH/SFTP.

**Chiffrement (Partie E/F) :** Chiffrement irréversible de fichiers uniques ou de dossiers complets avec parcours récursif et affichage d'une barre de progression.

## Installation et Lancement

### 1. Prérequis
Assurez-vous d'avoir Python 3.8 ou supérieur.

### 2. Installation des dépendances
Vous pouvez installer les modules manuellement ou laisser le script le faire au premier lancement :

`pip install -r requirements.txt`

### 3. Exécution
Important : Le script nécessite des privilèges d'administrateur pour créer le répertoire de clés dans /var/keys/.

`sudo python3 main.py`

**⚠️ Précautions d'Usage**

Ce script effectue un chiffrement in-place, ce qui signifie qu'il écrase les fichiers originaux.


Conservez toujours une copie de vos clés générées pour pouvoir déchiffrer vos fichiers de test ultérieurement.

# 📂 Structure du Répertoire

main.py : Script principal contenant toute la logique.

requirements.txt : Liste des bibliothèques Python nécessaires.

README.md : Documentation du projet.
