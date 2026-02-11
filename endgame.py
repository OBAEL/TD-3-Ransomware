import sys  # Importe les fonctions système (version, sortie du script)
import subprocess  # Permet d'exécuter des commandes système (comme pip install)
import importlib.util  # Utilisé pour vérifier si un module est installé sans l'importer
import os  # Pour interagir avec le système de fichiers (dossiers, chemins, droits)
import secrets  # Générateur de nombres aléatoires sécurisés pour la cryptographie
import datetime  # Pour obtenir la date et l'heure actuelle (horodatage)
import json  # Pour lire et écrire des fichiers au format JSON structuré
import paramiko  # Bibliothèque pour gérer les connexions SSH et le transfert SFTP
import base64  # Pour convertir les octets en texte Base64 (requis par Fernet)
from cryptography.fernet import Fernet  # Module de chiffrement symétrique sécurisé


# ==========================================================
# PARTIE A : Vérification des Dépendances (2 points)
# ==========================================================
def check_dependencies():
    """
    Vérifie si Python 3.8+ est installé et si les bibliothèques
    cryptography et paramiko sont présentes.
    """
    print("\n=== [Partie A] Vérification du Système ===")

    # 1. Vérification de la version de Python 3.8+
    if sys.version_info < (3, 8):  # Vérifie si la version est plus petite que 3.8
        print(f"[-] Erreur : Python 3.8+ est requis (actuel : {sys.version_info.major}.{sys.version_info.minor})")
        sys.exit(1)  # Arrête le script avec un code d'erreur

    # 2. Bibliothèques obligatoires
    dependencies = ["cryptography", "paramiko"]  # Liste des paquets nécessaires
    # On crée une liste 'missing' contenant les paquets non détectés sur la machine
    missing = [pkg for pkg in dependencies if importlib.util.find_spec(pkg) is None]

    if missing:  # Si la liste n'est pas vide
        print(f"[-] Bibliothèques manquantes : {missing}")
        # Demande à l'utilisateur s'il veut tenter l'installation
        rep = input("Voulez-vous les installer automatiquement ? (O/N) : ").strip().lower()
        if rep == 'o':
            try:
                for pkg in missing:  # Boucle sur chaque paquet manquant
                    print(f"[*] Installation de {pkg}...")
                    # Exécute la commande 'pip install' via le terminal
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                print("[+] Installation terminée avec succès.")
            except Exception as e:  # Si l'installation échoue (ex: pas d'internet)
                print(f"[-] Erreur lors de l'installation : {e}")
                sys.exit(1)
        else:  # Si l'utilisateur refuse
            print("[-] Le programme ne peut pas continuer sans ces dépendances.")
            sys.exit(1)
    else:
        print("[+] Environnement Python OK.")


# ==========================================================
# PARTIE C : Fonctions de Clés (4 points)
# ==========================================================
def save_key(key_hex, algo, length):
    """
    Stocke les clés dans /var/keys/ avec des permissions restreintes.
    """
    folder = "/var/keys/"  # Chemin de stockage imposé par le sujet

    # Création du dossier si inexistant (nécessite sudo sur Linux)
    if not os.path.exists(folder):  # Vérifie si le dossier existe déjà
        try:
            # Crée le dossier avec les droits rwx------ (700) pour la sécurité
            os.makedirs(folder, mode=0o700)
        except PermissionError:  # Si l'utilisateur n'a pas lancé avec sudo
            print(f"[-] Erreur : Droits insuffisants pour créer {folder}. Utilisez 'sudo'.")
            return None

    # Format du nom de fichier : key_algo_longueur_date.json
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")  # Génère l'heure précise
    filename = f"key_{algo.lower()}_{length}_{timestamp}.json"  # Construit le nom du fichier
    filepath = os.path.join(folder, filename)  # Combine le dossier et le nom proprement

    try:
        # Prépare le dictionnaire de données à enregistrer
        data = {
            "algorithm": algo,
            "length": length,
            "key": key_hex,
            "date": timestamp
        }
        with open(filepath, "w") as f:  # Ouvre le fichier en mode écriture ('w')
            json.dump(data, f, indent=4)  # Écrit le dictionnaire au format JSON propre

        # Restriction des droits : 0o600 signifie lecture/écriture par le propriétaire SEUL
        os.chmod(filepath, 0o600)
        return filepath  # Renvoie le chemin complet du fichier créé
    except Exception as e:
        print(f"[-] Erreur de sauvegarde : {e}")
        return None


def generate_key():
    """
    Gère la demande utilisateur et génère la clé (AES/PBKDF2).
    """
    print("\n--- [Partie C] Génération de Clé ---")

    # Demande de l'algorithme
    algo = input("Algorithme (AES/PBKDF2) : ").strip().upper()  # Nettoie et met en majuscules
    if algo not in ["AES", "PBKDF2"]:  # Vérifie si le choix est valide
        print("[-] Erreur : Algorithme non supporté.")
        return

    # Demande de la longueur
    try:
        length = int(input("Longueur de clé (128/192/256) : "))  # Convertit la saisie en nombre entier
        if length not in [128, 192, 256]:  # Vérifie si la taille est acceptée
            print("[-] Erreur : Longueur invalide.")
            return
    except ValueError:  # Si l'utilisateur tape des lettres au lieu de chiffres
        print("[-] Erreur : Saisie numérique requise.")
        return

    # Génération sécurisée : on divise par 8 car 1 octet = 8 bits
    byte_length = length // 8
    key_bytes = secrets.token_bytes(byte_length)  # Génère des octets aléatoires cryptographiques
    key_hex = key_bytes.hex()  # Convertit les octets en texte hexadécimal lisible

    # Appelle la fonction de sauvegarde définie plus haut
    path = save_key(key_hex, algo, length)
    if path:
        print(f"[+] ✓ Clé générée : {path}")


# ==========================================================
# PARTIE D : Transfert SFTP (4 points)
# ==========================================================
def send_sftp():
    """
    Partie D: Transfert SFTP (3 points)
    Demande les paramètres, connecte et transfère la clé.
    """
    print("\n--- [Partie D] Transfert SFTP de la Clé ---")

    # 1. Demander les paramètres de connexion
    host = input("Adresse IP du serveur distant : ").strip()
    user = input("Nom d'utilisateur SSH : ").strip()
    password = input("Mot de passe SSH : ").strip()
    local_path = input("Chemin local de la clé (ex: /var/keys/...) : ").strip()
    remote_path = os.path.basename(local_path)  # Récupère juste le nom du fichier pour la destination

    # Vérifie si le fichier à envoyer existe localement avant de lancer la connexion
    if not os.path.exists(local_path):
        print("[-] Erreur : Le fichier local n'existe pas.")
        return

    # 2. Initialisation du client SSH
    ssh = paramiko.SSHClient()  # Crée l'objet client SSH
    # Politique pour accepter les nouvelles clés de serveurs inconnus (AutoAdd)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"[*] Connexion à {host}...")
        # Tente de se connecter au serveur distant
        ssh.connect(hostname=host, username=user, password=password, timeout=10)

        # 3. Ouverture du canal SFTP pour le transfert
        sftp = ssh.open_sftp()  # Ouvre une session SFTP sur la connexion SSH
        sftp.put(local_path, remote_path)  # Copie le fichier local vers le serveur
        sftp.close()  # Ferme la session SFTP

        # 4. Vérification du succès
        print(f"[+] ✓ Transfert réussi : {remote_path} est sur le serveur.")

    except Exception as e:
        # 5. Gestion des erreurs (IP fausse, mot de passe erroné, etc.)
        print(f"[-] Erreur SFTP : {e}")
    finally:
        ssh.close()  # On ferme toujours la connexion SSH, même s'il y a eu une erreur


# ==========================================================
# PARTIE E & F : Chiffrement In-Place et Fonctions Avancées
# ==========================================================

def encrypt_file(filepath, key_hex):
    """
    Partie E: Chiffre un fichier et remplace l'original (In-place).
    """
    try:
        # 1. Préparation de la clé pour Fernet :
        # Fernet nécessite 32 octets. On complète avec 'ljust' (espaces à droite) si besoin.
        key_bytes = bytes.fromhex(key_hex)  # Transforme le texte HEX en octets réels
        fernet_key = base64.urlsafe_b64encode(key_bytes.ljust(32)[:32])  # Encode en Base64 valide
        f = Fernet(fernet_key)  # Initialise l'outil de chiffrement avec cette clé

        # 2. Lecture : Ouvre le fichier cible en mode binaire ('rb') pour ne pas corrompre les données
        with open(filepath, 'rb') as file:
            original_data = file.read()  # Lit tout le contenu du fichier en mémoire

        # 3. Chiffrement effectif
        encrypted_data = f.encrypt(original_data)  # Chiffre les données lues

        # 4. Écriture "In-Place" : On réouvre en mode 'wb' (écriture binaire), ce qui vide le fichier
        # On y écrit ensuite les données chiffrées. Le fichier original est écrasé.
        with open(filepath, 'wb') as file:
            file.write(encrypted_data)

        return True  # Succès
    except Exception as e:
        print(f"[-] Erreur sur {filepath}: {e}")
        return False


def select_and_encrypt():
    """
    Partie E & F: Sélection interactive et chiffrement récursif.
    """
    print("\n--- [Partie E/F] Chiffrement des données ---")
    print("[1] Fichier unique")  #
    print("[2] Dossier complet (Récursif)")  #

    choix = input("Sélection: ").strip()  # Récupère le choix de l'utilisateur

    # Demande l'entrée (clé brute ou chemin vers le JSON)
    entree_utilisateur = input("Entrez la clé HEX OU le chemin du fichier .json: ").strip()

    # LOGIQUE DE DÉTECTION (Amélioration) : On vérifie si l'entrée est un fichier JSON existant
    if entree_utilisateur.endswith(".json") and os.path.exists(entree_utilisateur):
        try:
            with open(entree_utilisateur, 'r') as f:  # Ouvre le fichier de clé
                data = json.load(f)  # Charge le contenu JSON
                key_hex = data['key']  # Extrait uniquement la valeur de la clé
                print(f"[+] Clé extraite du fichier JSON avec succès.")
        except Exception as e:
            print(f"[-] Erreur lors de la lecture du fichier JSON : {e}")
            return
    else:
        key_hex = entree_utilisateur  # Sinon, on prend le texte tapé tel quel

    # OPTION 1 : Un seul fichier à chiffrer
    if choix == '1':
        path = input("Chemin du fichier à chiffrer: ").strip()
        if os.path.isfile(path):  # Vérifie que c'est bien un fichier et non un dossier
            if encrypt_file(path, key_hex):
                print(f"[+] ✓ Fichier chiffré avec succès")

    # OPTION 2 : Un dossier complet (Récursif - Partie F)
    elif choix == '2':
        folder = input("Chemin du dossier à chiffrer: ").strip()  #
        if os.path.isdir(folder):  # Vérifie que le dossier existe
            files_to_encrypt = []
            # os.walk parcourt récursivement tous les sous-dossiers
            for root, dirs, files in os.walk(folder):
                for name in files:
                    # On construit le chemin complet de chaque fichier trouvé
                    files_to_encrypt.append(os.path.join(root, name))

            total = len(files_to_encrypt)  # Nombre total de fichiers à traiter
            if total == 0:
                print("[-] Aucun fichier trouvé dans ce dossier.")
                return

            print(f"[*] Chiffrement de {total} fichiers...")

            # Boucle de chiffrement avec index 'i' pour la barre de progression
            for i, filepath in enumerate(files_to_encrypt):
                encrypt_file(filepath, key_hex)  # Appelle la fonction de chiffrement in-place

                # Calcul du pourcentage de progression
                percent = int(((i + 1) / total) * 100)
                # '\r' permet de réécrire sur la même ligne dans la console
                print(f"\rProgression : {percent}%", end="", flush=True)

            print(f"\n[+] ✓ Dossier chiffré avec succès")
        else:
            print("[-] Erreur: Dossier introuvable.")


# ==========================================================
# PARTIE B : Menu Principal (3 points)
# ==========================================================
def main_menu():
    """
    Menu textuel interactif avec validation des saisies .
    """
    # On lance la vérification des dépendances dès le démarrage
    check_dependencies()

    while True:  # Boucle infinie pour garder le menu ouvert
        print("\n==============================")
        print(" Système de Chiffrement - TP3")
        print("==============================")
        print("1. Générer une nouvelle clé")  #
        print("2. Envoyer une clé via SFTP")  #
        print("3. Chiffrer des fichiers/dossiers")  #
        print("4. Vérifier les dépendances")  #
        print("5. Quitter")  #

        choix = input("\nChoix : ").strip()

        if choix == '1':
            generate_key()  # Appelle la création de clé
        elif choix == '2':
            send_sftp()  # Appelle l'exfiltration SFTP
        elif choix == '3':
            select_and_encrypt()  # Appelle le chiffrement
        elif choix == '4':
            check_dependencies()  # Permet de revérifier l'environnement
        elif choix == '5':
            print("[*] Fermeture du programme.")
            break  # Sort de la boucle 'while', ce qui ferme le script
        else:
            print("[!] Erreur : Choix invalide.")  # Si l'utilisateur tape n'importe quoi


# --- Point d'entrée principal ---
if __name__ == "__main__":
    try:
        main_menu()  # Démarre le programme
    except KeyboardInterrupt:
        # Gère proprement le fait de quitter avec CTRL+C
        print("\n\n[!] Interruption par l'utilisateur. Quitter...")
        sys.exit(0)