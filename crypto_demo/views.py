from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from .models import Game, Player, Message, Veto, Vote, CryptoUser, EncryptedDocument
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
import random
import hashlib
import time
import json
import os
from datetime import datetime

# Helper function to broadcast game updates (channels disabled for now)
def broadcast_game_update(game_id):
    # Placeholder - WebSocket support not enabled
    pass

# Helper functions
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private.decode('utf-8'), pem_public.decode('utf-8')

def sign_message_func(private_key_pem, message):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        return None

def verify_signature_func(public_key_pem, message, signature_b64):
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

# --- Game Logic Views ---

def login_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        role = request.POST.get('role')
        
        # Get or create active game
        game = Game.objects.filter(is_active=True).first()
        if not game:
            game = Game.objects.create(is_active=True)
        
        # Admin password check
        if role == 'Admin':
            admin_password = request.POST.get('admin_password')
            if admin_password != game.admin_password:
                return render(request, 'crypto_demo/game/login.html', {'error': 'Mot de passe incorrect'})
            
        # Create player
        player = Player.objects.create(name=name, role=role, game=game)
        request.session['player_id'] = player.id
        return redirect('crypto_demo:lobby')
        
    return render(request, 'crypto_demo/game/login.html')

def lobby_view(request):
    player_id = request.session.get('player_id')
    if not player_id:
        return redirect('crypto_demo:login')
        
    player = Player.objects.get(id=player_id)
    game = player.game
    
    if game.current_phase != 'waiting':
        return redirect('crypto_demo:game_interface')
        
    players = game.players.all()
    
    # Admin start logic (simplified: anyone can start for now, or check if user is 'Admin')
    if request.method == 'POST' and request.POST.get('action') == 'start':
        # Assign traitors
        alice_players = list(game.players.filter(role='Alice'))
        bob_players = list(game.players.filter(role='Bob'))
        
        if alice_players:
            traitor_a = random.choice(alice_players)
            traitor_a.is_traitor = True
            traitor_a.save()
            
        if bob_players:
            traitor_b = random.choice(bob_players)
            traitor_b.is_traitor = True
            traitor_b.save()
            
        game.start_round()
        return redirect('crypto_demo:game_interface')
        
    return render(request, 'crypto_demo/game/lobby.html', {'players': players, 'player': player})

def game_interface(request):
    player_id = request.session.get('player_id')
    if not player_id:
        return redirect('crypto_demo:login')
        
    player = Player.objects.get(id=player_id)
    game = player.game
    
    # Refresh game state
    game.refresh_from_db()
    
    context = {
        'player': player,
        'game': game,
        'messages': game.messages.order_by('timestamp'),
    }
    
    # Logic based on phase
    if game.current_phase == 'drafting':
        if request.method == 'POST':
            message_index = request.POST.get('message_index')
            if message_index:
                content = Message.PREDEFINED_MESSAGES[int(message_index)]
                # Create message draft
                msg = Message.objects.create(
                    game=game,
                    round=game.round,
                    sender_role=game.current_turn,
                    content=content,
                    traitor_content=content + " [MODIFIÉ PAR LE TRAÎTRE]" # Simple modification logic
                )
                game.current_phase = 'veto'
                game.save()
                broadcast_game_update(game.id)
                return redirect('crypto_demo:game_interface')
        
        # Pass predefined messages to template
        context['predefined_messages'] = Message.PREDEFINED_MESSAGES
            
    elif game.current_phase == 'veto':
        current_message = game.messages.filter(round=game.round).last()
        context['current_message'] = current_message
        
        # Check if player already vetoed
        has_vetoed = Veto.objects.filter(player=player, message=current_message).exists()
        context['has_vetoed'] = has_vetoed
        
        if request.method == 'POST' and not has_vetoed:
            approved = request.POST.get('decision') == 'approve'
            Veto.objects.create(player=player, message=current_message, approved=approved)
            
            # Check if all team members voted
            team_members = game.players.filter(role=game.current_turn, is_eliminated=False).count()
            votes = Veto.objects.filter(message=current_message).count()
            
            if votes >= team_members:
                # Check if traitor approved the modified message
                # Logic: If traitor is in the team and approved, message is compromised
                traitor_in_team = game.players.filter(role=game.current_turn, is_traitor=True).first()
                if traitor_in_team:
                    traitor_vote = Veto.objects.filter(player=traitor_in_team, message=current_message).first()
                    if traitor_vote and traitor_vote.approved:
                        current_message.is_compromised = True
                        current_message.save()
                
                game.current_phase = 'transmission'
                game.save()
                broadcast_game_update(game.id)
                return redirect('crypto_demo:game_interface')

    elif game.current_phase == 'transmission':
        # Oscar can view/attack here
        current_message = game.messages.filter(round=game.round).last()
        context['current_message'] = current_message
        
        if request.method == 'POST' and player.role == 'Oscar':
            attack_type = request.POST.get('attack_type')
            if attack_type:
                current_message.attack_type = attack_type
                current_message.save()
            
            # Move to elimination
            game.current_phase = 'elimination'
            game.save()
            broadcast_game_update(game.id)
            return redirect('crypto_demo:game_interface')
            
        # Auto-advance if no Oscar or timeout (simplified)
        if not game.players.filter(role='Oscar').exists():
             game.current_phase = 'elimination'
             game.save()
             broadcast_game_update(game.id)

    elif game.current_phase == 'elimination':
        if request.method == 'POST':
            target_id = request.POST.get('target_id')
            if target_id:
                target = Player.objects.get(id=target_id)
                Vote.objects.create(voter=player, target=target, round=game.round, game=game)
                
                # Check if voting done (simplified: just check count)
                total_players = game.players.filter(is_eliminated=False).exclude(role='Oscar').count()
                votes_cast = Vote.objects.filter(game=game, round=game.round).count()
                
                if votes_cast >= total_players:
                    # Process elimination
                    # Find most voted
                    # ... (Simplified for brevity)
                    
                    # Next round
                    game.round += 1
                    game.current_turn = 'Bob' if game.current_turn == 'Alice' else 'Alice'
                    game.current_phase = 'drafting'
                    game.save()
                    broadcast_game_update(game.id)
                    return redirect('crypto_demo:game_interface')

    return render(request, 'crypto_demo/game/interface.html', context)

# --- Keep existing views for reference or remove them ---
# For now, I will comment out the old views to avoid confusion, 
# or keep them if the user wants to access the old demos via a different URL.
# But the user asked to "Modify the way it works", so the root URL should point to login.

def index(request):
    return render(request, 'crypto_demo/index.html')

def under_development(request):
    """Page pour les fonctionnalités en développement"""
    return render(request, 'crypto_demo/under_development.html')

# --- Document Encryption Views ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os
import json

def encrypt_document(request):
    """Interface professionnelle pour chiffrer et envoyer un document (upload fichier)"""
    users = CryptoUser.objects.all()
    context = {
        'users': users,
        'recipients': users,
    }
    
    # Get sender from session
    sender_id = request.session.get('crypto_user_id')
    if sender_id:
        context['current_user'] = CryptoUser.objects.filter(id=sender_id).first()
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'login':
            # User selects their identity
            user_id = request.POST.get('user_id')
            if user_id:
                request.session['crypto_user_id'] = int(user_id)
                return redirect('crypto_demo:encrypt_document')
        
        elif action == 'send':
            sender_id = request.session.get('crypto_user_id')
            recipient_id = request.POST.get('recipient_id')
            uploaded_file = request.FILES.get('document_file')
            
            if not sender_id or not recipient_id or not uploaded_file:
                context['error'] = "Veuillez sélectionner un destinataire et un fichier."
                context['current_user'] = CryptoUser.objects.filter(id=sender_id).first()
                return render(request, 'crypto_demo/encrypt_document.html', context)
            
            sender = get_object_or_404(CryptoUser, id=sender_id)
            recipient = get_object_or_404(CryptoUser, id=recipient_id)
            
            try:
                # Read file content
                document_bytes = uploaded_file.read()
                original_filename = uploaded_file.name
                file_size = len(document_bytes)
                mime_type = uploaded_file.content_type or 'application/octet-stream'
                
                # Protocole de chiffrement complet
                
                # Étape 1: Signer le document (hash SHA-256) avec clé privée de l'expéditeur (RSA-PSS)
                sender_private = serialization.load_pem_private_key(
                    sender.private_key.encode(), password=None
                )
                
                # Calculer le hash du document
                doc_hash = hashlib.sha256(document_bytes).digest()
                
                # Signer le hash
                signature = sender_private.sign(
                    doc_hash,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                # Étape 2: Générer une clé symétrique AES-256-GCM
                aes_key = AESGCM.generate_key(bit_length=256)
                nonce = os.urandom(12)  # 96-bit nonce pour GCM
                
                # Étape 3: Chiffrer le document avec AES-256-GCM
                aesgcm = AESGCM(aes_key)
                ciphertext = aesgcm.encrypt(nonce, document_bytes, None)
                
                # Étape 4: Chiffrer la clé AES avec la clé publique du destinataire (RSA-OAEP)
                recipient_public = serialization.load_pem_public_key(
                    recipient.public_key.encode()
                )
                encrypted_key = recipient_public.encrypt(
                    aes_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Étape 5: Créer le paquet chiffré avec tous les composants
                encrypted_package = {
                    'ciphertext': base64.b64encode(ciphertext).decode(),
                    'nonce': base64.b64encode(nonce).decode(),
                    'encrypted_key': base64.b64encode(encrypted_key).decode(),
                    'signature': base64.b64encode(signature).decode(),
                    'certificate': sender.certificate,
                    'sender_name': sender.name,
                    'doc_hash': base64.b64encode(doc_hash).decode(),
                    'timestamp': datetime.now().isoformat()
                }
                
                # Sauvegarder dans la base de données
                EncryptedDocument.objects.create(
                    sender=sender,
                    recipient=recipient,
                    encrypted_package=json.dumps(encrypted_package),
                    original_filename=original_filename,
                    file_size=file_size,
                    mime_type=mime_type
                )
                
                context['success'] = True
                context['recipient_name'] = recipient.name
                context['filename'] = original_filename
                context['file_size'] = file_size
                context['current_user'] = sender
                
            except Exception as e:
                context['error'] = f"Erreur lors du chiffrement: {str(e)}"
                context['current_user'] = sender
    
    return render(request, 'crypto_demo/encrypt_document.html', context)

def decrypt_document(request):
    """Interface pour déchiffrer les documents reçus"""
    context = {}
    
    # Get current user from session
    user_id = request.session.get('crypto_user_id')
    if not user_id:
        context['users'] = CryptoUser.objects.all()
        
        if request.method == 'POST' and request.POST.get('action') == 'login':
            user_id = request.POST.get('user_id')
            if user_id:
                request.session['crypto_user_id'] = int(user_id)
                return redirect('crypto_demo:decrypt_document')
        
        return render(request, 'crypto_demo/decrypt_document.html', context)
    
    current_user = get_object_or_404(CryptoUser, id=user_id)
    context['current_user'] = current_user
    
    # Get received documents
    received_documents = EncryptedDocument.objects.filter(recipient=current_user)
    context['received_documents'] = received_documents
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'decrypt':
            doc_id = request.POST.get('document_id')
            document = get_object_or_404(EncryptedDocument, id=doc_id, recipient=current_user)
            
            try:
                package = json.loads(document.encrypted_package)
                
                # Extract components
                ciphertext = base64.b64decode(package['ciphertext'])
                nonce = base64.b64decode(package['nonce'])
                encrypted_key = base64.b64decode(package['encrypted_key'])
                signature = base64.b64decode(package['signature'])
                sender_cert_pem = package['certificate']
                doc_hash_b64 = package.get('doc_hash', '')
                
                # Étape 1: Vérifier le certificat X.509 de l'expéditeur
                sender_cert = x509.load_pem_x509_certificate(sender_cert_pem.encode())
                cert_subject = sender_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                cert_valid_from = sender_cert.not_valid_before_utc
                cert_valid_to = sender_cert.not_valid_after_utc
                cert_is_valid = cert_valid_from <= datetime.now(cert_valid_from.tzinfo) <= cert_valid_to
                
                # Étape 2: Déchiffrer la clé AES avec la clé privée RSA (RSA-OAEP)
                recipient_private = serialization.load_pem_private_key(
                    current_user.private_key.encode(), password=None
                )
                aes_key = recipient_private.decrypt(
                    encrypted_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Étape 3: Déchiffrer le document avec AES-256-GCM
                aesgcm = AESGCM(aes_key)
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                
                # Étape 4: Vérifier la signature RSA-PSS avec la clé publique de l'expéditeur
                sender_public = sender_cert.public_key()
                doc_hash = base64.b64decode(doc_hash_b64) if doc_hash_b64 else hashlib.sha256(decrypted_bytes).digest()
                
                try:
                    sender_public.verify(
                        signature,
                        doc_hash,
                        asym_padding.PSS(
                            mgf=asym_padding.MGF1(hashes.SHA256()),
                            salt_length=asym_padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    signature_valid = True
                except InvalidSignature:
                    signature_valid = False
                
                # Marquer comme lu
                document.is_read = True
                document.save()
                
                # Préparer le résultat du déchiffrement pour affichage
                context['decryption_result'] = {
                    'document': document,
                    'sender_name': package.get('sender_name', 'Inconnu'),
                    'cert_subject': cert_subject,
                    'cert_valid_from': cert_valid_from,
                    'cert_valid_to': cert_valid_to,
                    'cert_is_valid': cert_is_valid,
                    'signature_valid': signature_valid,
                    'aes_key_length': len(aes_key) * 8,  # en bits
                    'ciphertext_size': len(ciphertext),
                    'decrypted_size': len(decrypted_bytes),
                    'timestamp': package.get('timestamp', 'Inconnu'),
                }
                
            except Exception as e:
                context['error'] = f"Erreur lors du déchiffrement: {str(e)}"
        
        elif action == 'download_encrypted':
            # Télécharger le fichier CHIFFRÉ (sans déchiffrement)
            doc_id = request.POST.get('document_id')
            document = get_object_or_404(EncryptedDocument, id=doc_id, recipient=current_user)
            
            try:
                package = json.loads(document.encrypted_package)
                ciphertext = base64.b64decode(package['ciphertext'])
                
                # Retourner le fichier chiffré
                response = HttpResponse(ciphertext, content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename="{document.original_filename}.encrypted"'
                return response
                
            except Exception as e:
                context['error'] = f"Erreur lors du téléchargement: {str(e)}"
        
        elif action == 'download_decrypted':
            # Télécharger le fichier DÉCHIFFRÉ
            doc_id = request.POST.get('document_id')
            document = get_object_or_404(EncryptedDocument, id=doc_id, recipient=current_user)
            
            try:
                package = json.loads(document.encrypted_package)
                
                ciphertext = base64.b64decode(package['ciphertext'])
                nonce = base64.b64decode(package['nonce'])
                encrypted_key = base64.b64decode(package['encrypted_key'])
                
                # Déchiffrer la clé AES
                recipient_private = serialization.load_pem_private_key(
                    current_user.private_key.encode(), password=None
                )
                aes_key = recipient_private.decrypt(
                    encrypted_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Déchiffrer le document
                aesgcm = AESGCM(aes_key)
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                
                # Retourner le fichier déchiffré
                response = HttpResponse(decrypted_bytes, content_type=document.mime_type)
                response['Content-Disposition'] = f'attachment; filename="{document.original_filename}"'
                return response
                
            except Exception as e:
                context['error'] = f"Erreur lors du déchiffrement: {str(e)}"
        
        elif action == 'logout':
            del request.session['crypto_user_id']
            return redirect('crypto_demo:decrypt_document')
    
    return render(request, 'crypto_demo/decrypt_document.html', context)

def logout_crypto(request):
    """Déconnexion de l'utilisateur crypto"""
    if 'crypto_user_id' in request.session:
        del request.session['crypto_user_id']
    return redirect('crypto_demo:index')


def logout_crypto(request):
    """Déconnexion de l'utilisateur crypto"""
    if 'crypto_user_id' in request.session:
        del request.session['crypto_user_id']
    return redirect('crypto_demo:index')


def hashing(request):
    context = {}
    if request.method == 'POST':
        message = request.POST.get('message', '')
        hash_object = hashlib.sha256(message.encode())
        hex_dig = hash_object.hexdigest()
        context = {
            'message': message,
            'hash': hex_dig
        }
    return render(request, 'crypto_demo/hashing.html', context)

def signing(request):
    context = {}
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'generate_keys':
            priv, pub = generate_keys()
            context['private_key'] = priv
            context['public_key'] = pub
            
        elif action == 'sign':
            message = request.POST.get('message')
            private_key = request.POST.get('private_key')
            public_key = request.POST.get('public_key')
            signature = sign_message_func(private_key, message)
            context = {
                'message': message,
                'private_key': private_key,
                'public_key': public_key,
                'signature': signature
            }
            
        elif action == 'verify':
            message = request.POST.get('message')
            public_key = request.POST.get('public_key')
            signature = request.POST.get('signature')
            # For demo purposes, we might want to pass private key back if user wants to keep signing
            private_key = request.POST.get('private_key') 
            
            is_valid = verify_signature_func(public_key, message, signature)
            context = {
                'message': message,
                'private_key': private_key,
                'public_key': public_key,
                'signature': signature,
                'is_valid': is_valid,
                'verification_done': True
            }
            
    return render(request, 'crypto_demo/signing.html', context)

# Attacks

def attack_modification(request):
    # Similar to signing but with a focus on modifying the message after signing
    context = {}
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'generate_keys':
            priv, pub = generate_keys()
            context['private_key'] = priv
            context['public_key'] = pub
            
        elif action == 'sign':
            message = request.POST.get('message')
            private_key = request.POST.get('private_key')
            public_key = request.POST.get('public_key')
            signature = sign_message_func(private_key, message)
            context = {
                'message': message,
                'private_key': private_key,
                'public_key': public_key,
                'signature': signature
            }
            
        elif action == 'verify':
            # original_message = request.POST.get('original_message') # Hidden field maybe?
            message_to_verify = request.POST.get('message_to_verify')
            public_key = request.POST.get('public_key')
            signature = request.POST.get('signature')
            private_key = request.POST.get('private_key')
            
            is_valid = verify_signature_func(public_key, message_to_verify, signature)
            context = {
                'message': message_to_verify, # Show the modified message
                'private_key': private_key,
                'public_key': public_key,
                'signature': signature,
                'is_valid': is_valid,
                'verification_done': True
            }
    return render(request, 'crypto_demo/attack_modification.html', context)

def attack_forgery(request):
    context = {}
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'forge':
            context['error'] = "Impossible : il faut la clé privée pour signer. Une signature générée au hasard sera rejetée par la vérification."
    return render(request, 'crypto_demo/attack_forgery.html', context)

def attack_mitm(request):
    context = {}
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'step1':
            # Alice generates keys
            priv_a, pub_a = generate_keys()
            context['step'] = 1
            context['priv_a'] = priv_a
            context['pub_a'] = pub_a
            context['message'] = "Message secret pour Bob"
        elif action == 'step2':
            # Mallory intercepts and replaces key
            priv_m, pub_m = generate_keys()
            context['step'] = 2
            context['priv_a'] = request.POST.get('priv_a')
            context['pub_a'] = request.POST.get('pub_a') # Original key
            context['priv_m'] = priv_m
            context['pub_m'] = pub_m # Mallory's key
            context['message'] = request.POST.get('message')
        elif action == 'step3':
            # Bob receives Mallory's key thinking it's Alice's
            # Bob encrypts message? Or verifies signature?
            # The prompt says: "Bob vérifie avec la clé de Mallory -> ça passe"
            # This implies Alice signed with HER key, but Mallory replaced the key?
            # If Alice signs with Priv_A, and Bob verifies with Pub_M, it will FAIL.
            # MITM on signature usually means Mallory replaces the signature AND the key?
            # Or Mallory intercepts the message, signs it with Priv_M, and sends Pub_M to Bob.
            
            # Scenario:
            # 1. Alice sends Pub_A. Mallory intercepts, sends Pub_M to Bob.
            # 2. Alice signs M with Priv_A. Sends (M, Sig_A).
            # 3. Mallory intercepts. Modifies M to M'. Signs M' with Priv_M. Sends (M', Sig_M) to Bob.
            # 4. Bob verifies (M', Sig_M) with Pub_M (thinking it's Alice's). -> Valid.
            
            priv_m = request.POST.get('priv_m')
            pub_m = request.POST.get('pub_m')
            message = "Message MODIFIÉ par Mallory"
            
            # Mallory signs the modified message with her key
            signature = sign_message_func(priv_m, message)
            
            context['step'] = 3
            context['priv_a'] = request.POST.get('priv_a')
            context['pub_a'] = request.POST.get('pub_a')
            context['priv_m'] = priv_m
            context['pub_m'] = pub_m
            context['message'] = message
            context['signature'] = signature
            
        elif action == 'step4':
            # Bob verifies
            message = request.POST.get('message')
            signature = request.POST.get('signature')
            pub_m = request.POST.get('pub_m') # Bob thinks this is Alice's key
            
            is_valid = verify_signature_func(pub_m, message, signature)
            
            context['step'] = 4
            context['is_valid'] = is_valid
            context['message'] = message
            
    return render(request, 'crypto_demo/attack_mitm.html', context)

def attack_replay(request):
    context = {}
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'send':
            message = request.POST.get('message')
            # Simulate sending
            context['sent_message'] = message
            context['timestamp'] = time.time()
            context['status'] = "Message sent and accepted."
        elif action == 'replay':
            message = request.POST.get('message')
            # Simulate replay
            context['sent_message'] = message
            context['status'] = "Replay Attack Successful! System accepted the duplicate message."
            
    return render(request, 'crypto_demo/attack_replay.html', context)

def attack_key_theft(request):
    context = {}
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'generate':
            priv, pub = generate_keys()
            context['private_key'] = priv
            context['public_key'] = pub
        elif action == 'steal':
            # Just show the private key prominently
            context['private_key'] = request.POST.get('private_key')
            context['public_key'] = request.POST.get('public_key')
            context['stolen'] = True
    return render(request, 'crypto_demo/attack_key_theft.html', context)

def attack_collision(request):
    context = {}
    if request.method == 'POST':
        # Simulation
        msg1 = "Hello World"
        msg2 = "Hello World!"
        hash1 = hashlib.sha256(msg1.encode()).hexdigest()
        hash2 = hashlib.sha256(msg2.encode()).hexdigest()
        context = {
            'msg1': msg1, 'hash1': hash1,
            'msg2': msg2, 'hash2': hash2,
            'collision_found': False
        }
    return render(request, 'crypto_demo/attack_collision.html', context)