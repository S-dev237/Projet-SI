# Guide de Déploiement - Plateforme Cryptographie

## ✅ Problèmes Résolus

### 1. Problème Git (RÉSOLU)
**Erreur** : `error: cannot lock ref 'refs/remotes/origin/HEAD': unable to resolve reference`

**Solution appliquée** :
```bash
# Réinitialisé le dépôt Git local
git init
git branch -m main
git remote add origin https://github.com/S-dev237/Projet-SI.git
git fetch origin
git pull origin main --allow-unrelated-histories --no-rebase
git push -u origin main
```

✅ **Statut** : Le code est maintenant sur GitHub : https://github.com/S-dev237/Projet-SI

---

## ⚠️ Problème Vercel

### Pourquoi l'erreur 404 sur Vercel ?

**Vercel n'est PAS compatible avec Django** pour les raisons suivantes :

1. **Architecture incompatible** :
   - Vercel = Fonctions serverless (sans état, courte durée)
   - Django = Serveur WSGI persistant (avec état, long terme)

2. **Base de données** :
   - SQLite ne persiste pas sur Vercel
   - Les fichiers uploadés disparaissent entre les requêtes

3. **Problèmes techniques** :
   - Les migrations ne fonctionnent pas
   - Les sessions utilisateur sont perdues
   - Les fichiers statiques ne sont pas servis correctement

---

## ✅ Solutions Recommandées

### Option 1 : Railway (RECOMMANDÉ) ⭐

**Pourquoi Railway ?**
- ✅ Support natif Django
- ✅ Base de données PostgreSQL incluse
- ✅ Déploiement en 1 clic depuis GitHub
- ✅ Plan gratuit disponible

**Étapes** :

1. Aller sur https://railway.app
2. Se connecter avec GitHub
3. Cliquer sur "New Project"
4. Sélectionner "Deploy from GitHub repo"
5. Choisir `S-dev237/Projet-SI`
6. Railway détectera automatiquement Django

**Configuration nécessaire** :

Ajouter ces variables d'environnement dans Railway :
```
SECRET_KEY=votre-clé-secrète-aléatoire
DEBUG=False
ALLOWED_HOSTS=*.railway.app
DATABASE_URL=(auto-généré par Railway)
```

---

### Option 2 : Render

**Étapes** :

1. Aller sur https://render.com
2. Créer un compte
3. "New" → "Web Service"
4. Connecter le repo GitHub `S-dev237/Projet-SI`
5. Configuration :
   - **Build Command** : `pip install -r requirements.txt`
   - **Start Command** : `gunicorn messenger.wsgi:application`

**Fichiers à ajouter** :

`requirements.txt` (ajouter) :
```
gunicorn==20.1.0
psycopg2-binary==2.9.9
```

---

### Option 3 : PythonAnywhere

**Étapes** :

1. Créer un compte sur https://www.pythonanywhere.com
2. Ouvrir un "Bash Console"
3. Cloner le repo :
   ```bash
   git clone https://github.com/S-dev237/Projet-SI.git
   ```
4. Créer une "Web App" Django
5. Pointer vers le projet cloné

---

### Option 4 : Heroku

**Étapes** :

1. Installer Heroku CLI : https://devcenter.heroku.com/articles/heroku-cli
2. Dans le terminal :
   ```bash
   heroku login
   heroku create projet-crypto-si
   git push heroku main
   ```

**Fichiers nécessaires** :

`Procfile` :
```
web: gunicorn messenger.wsgi
```

`runtime.txt` :
```
python-3.11.0
```

---

## 🔧 Configuration pour la Production

### 1. Modifier `settings.py`

```python
import os
import dj_database_url

# Sécurité
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-key')
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

# Base de données PostgreSQL
DATABASES = {
    'default': dj_database_url.config(
        default='sqlite:///db.sqlite3',
        conn_max_age=600
    )
}

# Fichiers statiques
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Middleware WhiteNoise (pour les fichiers statiques)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Ajouter ici
    # ... autres middleware
]
```

### 2. Ajouter à `requirements.txt`

```
Django==5.2.7
cryptography==46.0.3
gunicorn==20.1.0
psycopg2-binary==2.9.9
dj-database-url==2.1.0
whitenoise==6.6.0
```

### 3. Créer `Procfile` (Heroku/Render)

```
web: gunicorn messenger.wsgi:application
```

---

## 📊 Comparaison des Plateformes

| Plateforme | Gratuit | Django Support | PostgreSQL | Complexité |
|------------|---------|----------------|------------|------------|
| **Railway** | ✅ | ⭐⭐⭐⭐⭐ | ✅ Inclus | Facile |
| **Render** | ✅ | ⭐⭐⭐⭐⭐ | ✅ Inclus | Facile |
| **PythonAnywhere** | ✅ | ⭐⭐⭐⭐ | ❌ Payant | Moyen |
| **Heroku** | ❌ (Plus gratuit) | ⭐⭐⭐⭐⭐ | ✅ Payant | Moyen |
| **Vercel** | ✅ | ⭐ (Non recommandé) | ❌ | Difficile |

---

## 🎯 Recommandation Finale

**Utilisez Railway** : https://railway.app

C'est la solution la plus simple et la plus adaptée pour votre projet Django de cryptographie.

---

## 📞 Support

Si vous rencontrez des problèmes :

1. Vérifiez les logs de la plateforme
2. Assurez-vous que toutes les dépendances sont installées
3. Vérifiez les variables d'environnement
4. Testez localement d'abord avec `python manage.py runserver`

---

## ✅ Checklist de Déploiement

- [ ] Code pushé sur GitHub
- [ ] requirements.txt à jour
- [ ] Variables d'environnement configurées
- [ ] Base de données PostgreSQL configurée
- [ ] Migrations exécutées (`python manage.py migrate`)
- [ ] Fichiers statiques collectés (`python manage.py collectstatic`)
- [ ] Utilisateurs créés (`python manage.py init_users`)
- [ ] DEBUG=False en production
- [ ] SECRET_KEY sécurisée (générée aléatoirement)

---

Date : 30 Novembre 2025
