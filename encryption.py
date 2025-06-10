# encryption.py
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

# AES şifreleme ve çözme
class AESCipher:
    def __init__(self, key):
        self.key = key  # 32 byte = 256 bit

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return {
            'cipher_text': ciphertext,
            'nonce': cipher.nonce,
            'tag': tag
        }

    def decrypt(self, cipher_text, nonce, tag):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(cipher_text, tag)
        return plaintext

# RSA anahtar yönetimi
class RSACipher:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """Yeni RSA anahtar çifti oluşturur"""
        key = RSA.generate(2048)  # 2048 bit RSA anahtarı
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()

    def encrypt(self, data, public_key=None):
        """Veriyi RSA ile şifreler"""
        if public_key is None:
            if self.public_key is None:
                raise ValueError("Genel anahtar mevcut değil!")
            rsa_key = RSA.import_key(self.public_key)
        else:
            rsa_key = RSA.import_key(public_key)
        
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(data)

    def decrypt(self, data):
        """Veriyi RSA ile çözer"""
        if self.private_key is None:
            raise ValueError("Özel anahtar mevcut değil!")
        
        rsa_key = RSA.import_key(self.private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(data)

    def get_public_key_dict(self):
        """Genel anahtarı dictionary formatında döndürür"""
        if self.public_key is None:
            raise ValueError("Genel anahtar mevcut değil!")
        
        rsa_key = RSA.import_key(self.public_key)
        return {
            'n': rsa_key.n,
            'e': rsa_key.e
        }

    def load_public_key_from_dict(self, key_dict):
        """Dictionary'den genel anahtarı yükler"""
        rsa_key = RSA.construct((key_dict['n'], key_dict['e']))
        self.public_key = rsa_key.export_key()

    def save_key_to_file(self, filename):
        """Özel anahtarı dosyaya kaydeder"""
        if self.private_key is None:
            raise ValueError("Özel anahtar mevcut değil!")
        
        with open(filename, 'wb') as f:
            f.write(self.private_key)

    def load_key_from_file(self, filename):
        """Özel anahtarı dosyadan yükler"""
        with open(filename, 'rb') as f:
            self.private_key = f.read()
        
        # Özel anahtardan genel anahtarı türet
        rsa_key = RSA.import_key(self.private_key)
        self.public_key = rsa_key.publickey().export_key()

    def get_public_key_pem(self):
        """Genel anahtarı PEM formatında döndürür"""
        return self.public_key

    def get_private_key_pem(self):
        """Özel anahtarı PEM formatında döndürür"""
        return self.private_key

# Yardımcı fonksiyonlar
def generate_aes_key():
    return get_random_bytes(32)  # 256 bitlik AES anahtarı üretir

def save_key_to_file(filename, key_data):
    with open(filename, 'wb') as f:
        f.write(key_data)

def load_key_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

# Test amaçlı çalıştırma
if __name__ == "__main__":
    # AES örneği
    print("[*] AES Testi Başlıyor...")
    aes_key = generate_aes_key()
    aes_cipher = AESCipher(aes_key)
    data = b"Bu bir test verisidir."
    encrypted = aes_cipher.encrypt(data)
    decrypted = aes_cipher.decrypt(encrypted['cipher_text'], encrypted['nonce'], encrypted['tag'])
    print("Şifrelenmiş Veri:", base64.b64encode(encrypted['cipher_text']))
    print("Çözülen Veri:", decrypted)

    # RSA örneği
    print("\n[*] RSA Testi Başlıyor...")
    rsa_cipher = RSACipher()
    rsa_cipher.generate_keys()
    
    # Dictionary yöntemi ile test
    public_key_dict = rsa_cipher.get_public_key_dict()
    print("Genel Anahtar Dict:", public_key_dict)
    
    # Yeni RSA cipher ile genel anahtarı yükle
    rsa_cipher2 = RSACipher()
    rsa_cipher2.load_public_key_from_dict(public_key_dict)
    
    # Şifreleme/çözme testi
    encrypted_rsa = rsa_cipher2.encrypt(data)
    decrypted_rsa = rsa_cipher.decrypt(encrypted_rsa)
    print("RSA ile Çözülen Veri:", decrypted_rsa)
    
    # Dosyaya kaydetme/yükleme testi
    print("\n[*] Dosya Kaydetme/Yükleme Testi...")
    rsa_cipher.save_key_to_file("test_rsa_key.pem")
    
    rsa_cipher3 = RSACipher()
    rsa_cipher3.load_key_from_file("test_rsa_key.pem")
    
    encrypted_rsa2 = rsa_cipher3.encrypt(data)
    decrypted_rsa2 = rsa_cipher3.decrypt(encrypted_rsa2)
    print("Dosyadan Yüklenen Anahtar ile Çözülen Veri:", decrypted_rsa2)