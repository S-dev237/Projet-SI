from django.db import models
from django.contrib.auth.models import User
import random

# === Document Encryption Models ===

class CryptoUser(models.Model):
    """Utilisateur avec ses clés cryptographiques"""
    name = models.CharField(max_length=100, unique=True)
    email = models.EmailField(unique=True)
    
    # RSA Key Pair (4096 bits)
    private_key = models.TextField()
    public_key = models.TextField()
    
    # X.509 Certificate
    certificate = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name

class EncryptedDocument(models.Model):
    """Document chiffré envoyé entre utilisateurs"""
    sender = models.ForeignKey(CryptoUser, on_delete=models.CASCADE, related_name='sent_documents')
    recipient = models.ForeignKey(CryptoUser, on_delete=models.CASCADE, related_name='received_documents')
    
    # Original document info
    original_filename = models.CharField(max_length=255, default='document.txt')
    file_size = models.IntegerField(default=0)  # Taille en octets
    mime_type = models.CharField(max_length=100, default='text/plain')
    
    # Encrypted components (stored as base64 in JSON)
    encrypted_package = models.TextField()  # JSON contenant: ciphertext, enc_key, signature, nonce, tag, cert
    
    # Status
    is_read = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.sender.name} → {self.recipient.name} - {self.original_filename} ({self.created_at.strftime('%d/%m/%Y %H:%M')})"


# === Game Models ===

class Game(models.Model):
    PHASES = [
        ('waiting', 'En attente'),
        ('drafting', 'Rédaction'),
        ('veto', 'Veto/Signature'),
        ('transmission', 'Transmission'), # Oscar can act here
        ('elimination', 'Élimination'),
        ('finished', 'Terminé')
    ]
    
    is_active = models.BooleanField(default=False)
    round = models.IntegerField(default=1)
    max_rounds = models.IntegerField(default=10)
    
    # Admin password (set when creating the game)
    admin_password = models.CharField(max_length=100, default='admin123')
    
    # Scores
    alice_score = models.IntegerField(default=0)
    bob_score = models.IntegerField(default=0)
    oscar_score = models.IntegerField(default=0)
    
    current_phase = models.CharField(max_length=20, choices=PHASES, default='waiting')
    current_turn = models.CharField(max_length=10, default='Alice') # Who is sending? Alice or Bob
    
    created_at = models.DateTimeField(auto_now_add=True)

    def start_round(self):
        self.current_phase = 'drafting'
        self.save()

class Player(models.Model):
    ROLES = [('Alice', 'Alice'), ('Bob', 'Bob'), ('Oscar', 'Oscar'), ('Admin', 'Admin')]
    
    name = models.CharField(max_length=100)
    role = models.CharField(choices=ROLES, max_length=10)
    game = models.ForeignKey(Game, on_delete=models.CASCADE, related_name='players')
    
    # Secret status
    is_traitor = models.BooleanField(default=False)
    is_eliminated = models.BooleanField(default=False)
    
    # Session management
    session_key = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.role})"

class Message(models.Model):
    PREDEFINED_MESSAGES = [
        "Coordination pour l'attaque à 14h00",
        "Retraite immédiate, position compromise",
        "Renforts en route, tenir la position",
        "Mission accomplie, retour à la base",
        "Changement de plan, nouvelle cible identifiée",
        "Besoin de support médical urgent",
        "Position ennemie repérée aux coordonnées X",
        "Communication brouillée, passage au plan B",
        "Objectif sécurisé, zone sous contrôle",
        "Alerte: infiltration détectée dans le secteur"
    ]
    
    game = models.ForeignKey(Game, on_delete=models.CASCADE, related_name='messages')
    round = models.IntegerField()
    sender_role = models.CharField(max_length=10) # Alice or Bob
    
    content = models.TextField()
    traitor_content = models.TextField(null=True, blank=True) # Modified version for traitor
    
    # Security metadata
    signature = models.TextField(null=True, blank=True)
    hash_val = models.CharField(max_length=64, null=True, blank=True)
    
    # Attack status
    is_compromised = models.BooleanField(default=False) # Visible to Oscar?
    attack_type = models.CharField(max_length=50, null=True, blank=True) # MITM, etc.
    
    timestamp = models.DateTimeField(auto_now_add=True)

class Veto(models.Model):
    player = models.ForeignKey(Player, on_delete=models.CASCADE)
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='vetos')
    approved = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

class Vote(models.Model):
    voter = models.ForeignKey(Player, on_delete=models.CASCADE, related_name='votes_cast')
    target = models.ForeignKey(Player, on_delete=models.CASCADE, related_name='votes_received')
    round = models.IntegerField()
    game = models.ForeignKey(Game, on_delete=models.CASCADE)
