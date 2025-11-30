# Plateforme Professionnelle de Cryptographie

Application Django de démonstration de chiffrement et signature de documents avec des algorithmes cryptographiques de niveau professionnel.

## 🔐 Fonctionnalités

- **Chiffrement de Documents** : Upload et chiffrement de fichiers (PDF, TXT, DJVU)
- **Algorithmes** : 
  - AES-256-GCM (chiffrement symétrique)
  - RSA-OAEP (chiffrement asymétrique)
  - RSA-PSS + SHA-256 (signature numérique)
  - Certificats X.509 pour l'authentification
- **Déchiffrement avec Visualisation** : Processus de déchiffrement étape par étape
- **Interface Professionnelle** : Design moderne avec Bootstrap 5 et Bootstrap Icons

## 🚀 Installation Locale

1. Créer un environnement virtuel :
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/Mac
   ```

2. Installer les dépendances :
   ```bash
   pip install -r requirements.txt
   pip install cryptography
   ```

3. Créer les utilisateurs de démonstration :
   ```bash
   python manage.py migrate
   python manage.py init_users
   ```

4. Lancer le serveur :
   ```bash
   python manage.py runserver
   ```

5. Accéder à l'application : http://127.0.0.1:8000/crypto/

## 📦 Déploiement

### ⚠️ Important : Django et Vercel

**Vercel n'est PAS recommandé pour Django** car :
- Django nécessite un serveur persistant (WSGI/ASGI)
- Vercel utilise des fonctions serverless (courte durée)
- La base de données SQLite ne persiste pas
- Les fichiers uploadés sont perdus entre les requêtes

### Plateformes Recommandées :

1. **Railway** (Recommandé) : https://railway.app
2. **Render** : https://render.com
3. **PythonAnywhere** : https://www.pythonanywhere.com
4. **Heroku** : https://www.heroku.com

## 🏗️ Structure du Projet

```
.
 crypto_demo/           # Application principale
   ├── models.py         # CryptoUser, EncryptedDocument
   ├── views.py          # Logique de chiffrement/déchiffrement
   ├── templates/        # Templates HTML
   └── management/       # Commandes personnalisées
 messenger/            # Configuration Django
   ├── settings.py       # Configuration
   └── urls.py           # Routes
 manage.py             # CLI Django
 requirements.txt      # Dépendances Python
```

## 🔑 Technologies

- **Backend** : Django 5.2.7
- **Cryptographie** : Python Cryptography Library
- **Frontend** : Bootstrap 5, Bootstrap Icons
- **Base de données** : SQLite (dev)

## 📚 Standards de Sécurité

- OAEP (Optimal Asymmetric Encryption Padding)
- PSS (Probabilistic Signature Scheme)
- GCM (Galois/Counter Mode)
- X.509 v3 Certificates

## 👥 Utilisateurs de Démonstration

Après `python manage.py init_users` :
- **Alice** : alice@example.com
- **Bob** : bob@example.com

## 📄 Licence

MIT
