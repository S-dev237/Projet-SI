from django.core.management.base import BaseCommand
from crypto_demo.models import CryptoUser
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


class Command(BaseCommand):
    help = 'Crée les utilisateurs Alice et Bob avec leurs clés cryptographiques'

    def generate_user_keys(self, name, email):
        """Génère une paire de clés RSA-4096 et un certificat X.509"""
        # Generate RSA-4096 key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        public_key = private_key.public_key()
        
        # Create X.509 certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ile-de-France"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Crypto Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, email),
        ])
        
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )
        
        # Serialize to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        
        return private_pem, public_pem, cert_pem

    def handle(self, *args, **options):
        users_data = [
            {'name': 'Alice', 'email': 'alice@crypto-demo.fr'},
            {'name': 'Bob', 'email': 'bob@crypto-demo.fr'},
        ]
        
        for user_data in users_data:
            if CryptoUser.objects.filter(name=user_data['name']).exists():
                self.stdout.write(
                    self.style.WARNING(f"L'utilisateur {user_data['name']} existe déjà.")
                )
                continue
            
            self.stdout.write(f"Génération des clés pour {user_data['name']}...")
            private_key, public_key, certificate = self.generate_user_keys(
                user_data['name'], 
                user_data['email']
            )
            
            CryptoUser.objects.create(
                name=user_data['name'],
                email=user_data['email'],
                private_key=private_key,
                public_key=public_key,
                certificate=certificate,
            )
            
            self.stdout.write(
                self.style.SUCCESS(f"✓ Utilisateur {user_data['name']} créé avec succès!")
            )
        
        self.stdout.write(self.style.SUCCESS('\n✓ Initialisation terminée!'))
