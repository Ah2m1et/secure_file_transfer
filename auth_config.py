# auth_config.py
import hashlib
import secrets
import time
import json
import os

class AuthManager:
    def __init__(self, config_file='auth_config.json'):
        self.config_file = config_file
        self.valid_tokens = {}
        self.token_expiry = {}
        self.max_attempts = 3
        self.attempt_counter = {}
        self.blocked_ips = {}
        self.load_config()
    
    def load_config(self):
        """Konfigürasyon dosyasını yükle"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.valid_tokens = config.get('valid_tokens', {})
                    self.token_expiry = config.get('token_expiry', {})
                    self.max_attempts = config.get('max_attempts', 3)
                print(f"[*] Kimlik doğrulama konfigürasyonu yüklendi: {len(self.valid_tokens)} token")
            except Exception as e:
                print(f"[!] Konfigürasyon yüklenirken hata: {e}")
                self.create_default_config()
        else:
            self.create_default_config()
    
    def save_config(self):
        """Konfigürasyonu dosyaya kaydet"""
        config = {
            'valid_tokens': self.valid_tokens,
            'token_expiry': self.token_expiry,
            'max_attempts': self.max_attempts
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"[*] Konfigürasyon kaydedildi: {self.config_file}")
        except Exception as e:
            print(f"[!] Konfigürasyon kaydedilirken hata: {e}")
    
    def create_default_config(self):
        """Varsayılan konfigürasyon oluştur"""
        print("[*] Varsayılan kimlik doğrulama konfigürasyonu oluşturuluyor...")
        
        # Varsayılan token'lar
        default_tokens = [
            "secure_client_2024",
            "backup_token_2024",
            "admin_access_2024"
        ]
        
        for token in default_tokens:
            token_hash = self.hash_token(token)
            self.valid_tokens[token_hash] = {
                'name': token,
                'created': time.time(),
                'last_used': None,
                'usage_count': 0
            }
        
        self.save_config()
        print(f"[*] {len(default_tokens)} varsayılan token oluşturuldu.")
    
    def hash_token(self, token):
        """Token'ı güvenli şekilde hash'le"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def generate_token(self, name="generated_token"):
        """Yeni token oluştur"""
        token = secrets.token_urlsafe(32)
        token_hash = self.hash_token(token)
        
        self.valid_tokens[token_hash] = {
            'name': name,
            'created': time.time(),
            'last_used': None,
            'usage_count': 0
        }
        
        self.save_config()
        print(f"[*] Yeni token oluşturuldu: {name}")
        return token
    
    def authenticate(self, token, client_ip):
        """Token'ı doğrula"""
        # IP bloklama kontrolü
        if self.is_ip_blocked(client_ip):
            print(f"[!] Bloklu IP'den bağlantı: {client_ip}")
            return False, "IP adresi bloklu"
        
        token_hash = self.hash_token(token)
        
        if token_hash in self.valid_tokens:
            # Token geçerli
            self.valid_tokens[token_hash]['last_used'] = time.time()
            self.valid_tokens[token_hash]['usage_count'] += 1
            self.reset_attempts(client_ip)
            self.save_config()
            
            token_name = self.valid_tokens[token_hash]['name']
            print(f"[*] Başarılı kimlik doğrulama: {token_name} ({client_ip})")
            return True, "Kimlik doğrulama başarılı"
        else:
            # Token geçersiz
            self.increment_attempts(client_ip)
            print(f"[!] Geçersiz token: {client_ip}")
            return False, "Geçersiz token"
    
    def increment_attempts(self, ip):
        """Başarısız deneme sayısını artır"""
        if ip not in self.attempt_counter:
            self.attempt_counter[ip] = 0
        
        self.attempt_counter[ip] += 1
        
        if self.attempt_counter[ip] >= self.max_attempts:
            self.block_ip(ip)
    
    def reset_attempts(self, ip):
        """Başarısız deneme sayısını sıfırla"""
        if ip in self.attempt_counter:
            del self.attempt_counter[ip]
    
    def block_ip(self, ip):
        """IP'yi blokla"""
        self.blocked_ips[ip] = time.time()
        print(f"[!] IP bloklandı: {ip}")
    
    def is_ip_blocked(self, ip):
        """IP'nin bloklu olup olmadığını kontrol et"""
        if ip in self.blocked_ips:
            # 1 saat blok süresi
            if time.time() - self.blocked_ips[ip] > 3600:
                del self.blocked_ips[ip]
                return False
            return True
        return False
    
    def revoke_token(self, token):
        """Token'ı iptal et"""
        token_hash = self.hash_token(token)
        if token_hash in self.valid_tokens:
            token_name = self.valid_tokens[token_hash]['name']
            del self.valid_tokens[token_hash]
            self.save_config()
            print(f"[*] Token iptal edildi: {token_name}")
            return True
        return False
    
    def list_tokens(self):
        """Aktif token'ları listele"""
        print("\n[*] Aktif Token'lar:")
        print("-" * 60)
        for token_hash, info in self.valid_tokens.items():
            created = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['created']))
            last_used = "Hiç kullanılmadı"
            if info['last_used']:
                last_used = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['last_used']))
            
            print(f"İsim: {info['name']}")
            print(f"Oluşturulma: {created}")
            print(f"Son Kullanım: {last_used}")
            print(f"Kullanım Sayısı: {info['usage_count']}")
            print("-" * 60)

# Komut satırı araçları
if __name__ == "__main__":
    import sys
    
    auth_manager = AuthManager()
    
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  python auth_config.py list                 - Token'ları listele")
        print("  python auth_config.py generate <name>      - Yeni token oluştur")
        print("  python auth_config.py revoke <token>       - Token'ı iptal et")
        print("  python auth_config.py test <token>         - Token'ı test et")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "list":
        auth_manager.list_tokens()
    
    elif command == "generate":
        name = sys.argv[2] if len(sys.argv) > 2 else "generated_token"
        token = auth_manager.generate_token(name)
        print(f"\nYeni Token: {token}")
        print("Bu token'ı güvenli bir yerde saklayın!")
    
    elif command == "revoke":
        if len(sys.argv) < 3:
            print("Token belirtiniz!")
            sys.exit(1)
        token = sys.argv[2]
        if auth_manager.revoke_token(token):
            print("Token başarıyla iptal edildi.")
        else:
            print("Token bulunamadı.")
    
    elif command == "test":
        if len(sys.argv) < 3:
            print("Token belirtiniz!")
            sys.exit(1)
        token = sys.argv[2]
        success, message = auth_manager.authenticate(token, "127.0.0.1")
        print(f"Test Sonucu: {message}")
    
    else:
        print(f"Bilinmeyen komut: {command}")