# sender.py
import socket
import json
from encryption import AESCipher, RSACipher, generate_aes_key
from fragmentation import Fragmenter
import base64
import hashlib  # <-- eklendi

SERVER_IP = '127.0.0.1'  # Alıcı (receiver) IP adresi
SERVER_PORT = 5001       # Alıcı port numarası
MAX_FRAGMENT_SIZE = 1024 # 1 KB parçalar

def send_file(file_path, auth_token="secure_client_2024"):  # Token'ı parametre olarak alalım
    # 1. Dosyayı oku
    with open(file_path, 'rb') as f:
        file_data = f.read()
        print("[*] Dosya okundu:", file_path)
    
    # Dosya hash'i hesapla
    file_hash = hashlib.sha256(file_data).hexdigest()
    
    # 2. Socket aç ve sunucuya bağlan
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))
    print("[*] Alıcıya bağlanıldı.")
    
    try:
        # --- YENİ EKLENEN KİMLİK DOĞRULAMA ADIMI ---
        # 1. Kimlik doğrulama isteği gönder
        auth_message = {
            'type': 'AUTH_REQUEST',
            'token': auth_token
        }
        sock.sendall(json.dumps(auth_message).encode() + b'\n')
        print("[*] Kimlik doğrulama isteği gönderildi.")
        
        # 2. Sunucudan kimlik doğrulama yanıtını bekle
        auth_response_raw = sock.recv(1024)
        auth_response = json.loads(auth_response_raw.decode())
        
        if auth_response.get('status') != 'AUTH_SUCCESS':
            raise Exception(f"Kimlik doğrulama başarısız: {auth_response.get('message')}")
        
        print("[✓] Kimlik doğrulama başarılı.")
        # --- KİMLİK DOĞRULAMA ADIMI BİTTİ ---

        # 3. Artık genel anahtarı isteyebilirsin
        sock.sendall(b'REQUEST_PUBLIC_KEY\n')
        print("[*] RSA genel anahtarı istendi.")
        
        # 4. Sunucudan gelen genel anahtarı al
        response = sock.recv(4096)
        public_key_data = json.loads(response.decode())
        print("[*] RSA genel anahtarı alındı.")
        
        # 5. RSA cipher oluştur (genel anahtar ile)
        rsa_cipher = RSACipher()
        rsa_cipher.load_public_key_from_dict(public_key_data)
        
        # 6. AES anahtarı oluştur
        aes_key = generate_aes_key()
        print("[*] AES anahtarı oluşturuldu.")
        
        # 7. AES anahtarını RSA ile şifrele
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        print("[*] AES anahtarı RSA ile şifrelendi.")
        
        # 8. Şifrelenmiş AES anahtarını gönder
        key_message = {
            'type': 'AES_KEY',
            'data': base64.b64encode(encrypted_aes_key).decode()
        }
        sock.sendall(json.dumps(key_message).encode() + b'\n')
        print("[*] Şifrelenmiş AES anahtarı gönderildi.")
        
        # 9. Sunucudan onay al
        ack = sock.recv(1024)
        if b'KEY_RECEIVED' not in ack:
            raise Exception("Anahtar gönderimi başarısız!")
        print("[*] Anahtar gönderimi onaylandı.")

        # Dosya hash'ini gönder
        hash_message = {
            'type': 'FILE_HASH',
            'hash': file_hash
        }
        sock.sendall(json.dumps(hash_message).encode() + b'\n')
        print(f"[*] Dosya hash'i gönderildi: {file_hash}")
        
        # 10. Veriyi AES ile şifrele
        aes_cipher = AESCipher(aes_key)
        encrypted_data = aes_cipher.encrypt(file_data)
        
        # Şifrelenmiş veriyi birleştir
        full_data = encrypted_data['nonce'] + encrypted_data['tag'] + encrypted_data['cipher_text']
        
        # 11. Veriyi parçalara ayır
        fragmenter = Fragmenter(max_fragment_size=MAX_FRAGMENT_SIZE)
        fragments = fragmenter.fragment(full_data)
        print(f"[*] Veri {len(fragments)} parçaya bölündü.")
        
        # 12. Her parçayı gönder
        for fragment in fragments:
            fragment_data = {
                'type': 'FRAGMENT',
                'fragment_id': fragment['fragment_id'],
                'total_fragments': fragment['total_fragments'],
                'data': base64.b64encode(fragment['data']).decode()
            }
            message = json.dumps(fragment_data).encode() + b'\n'
            sock.sendall(message)
        
        # 13. Gönderim tamamlandı sinyali
        end_message = {'type': 'EOF'}
        sock.sendall(json.dumps(end_message).encode() + b'\n')
        print("[*] Dosya gönderimi tamamlandı.")
        
    except Exception as e:
        print(f"[!] Hata: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    file_path = input("Gönderilecek dosyanın yolu: ")
    send_file(file_path)