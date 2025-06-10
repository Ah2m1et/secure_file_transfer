# sender_logic.py
import socket
import json
from encryption import AESCipher, RSACipher, generate_aes_key
from fragmentation import Fragmenter
import base64
import hashlib

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5001
MAX_FRAGMENT_SIZE = 1024

def send_file_logic(file_path, status_callback, auth_token="secure_client_2024"):
    def update_status(message):
        print(message)
        if status_callback:
            status_callback(message)

    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        update_status(f"[*] Dosya okundu: {file_path}")
        
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        update_status("[*] Alıcıya bağlanıldı.")

        auth_message = {'type': 'AUTH_REQUEST', 'token': auth_token}
        sock.sendall(json.dumps(auth_message).encode() + b'\n')
        update_status("[*] Kimlik doğrulama isteği gönderildi.")
        
        auth_response = json.loads(sock.recv(1024).decode())
        if auth_response.get('status') != 'AUTH_SUCCESS':
            raise Exception(f"Kimlik doğrulama başarısız: {auth_response.get('message')}")
        update_status("[✓] Kimlik doğrulama başarılı.")

        sock.sendall(b'REQUEST_PUBLIC_KEY\n')
        update_status("[*] RSA genel anahtarı istendi.")
        
        public_key_data = json.loads(sock.recv(4096).decode())
        update_status("[*] RSA genel anahtarı alındı.")

        rsa_cipher = RSACipher()
        rsa_cipher.load_public_key_from_dict(public_key_data)
        
        aes_key = generate_aes_key()
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        
        key_message = {'type': 'AES_KEY', 'data': base64.b64encode(encrypted_aes_key).decode()}
        sock.sendall(json.dumps(key_message).encode() + b'\n')
        update_status("[*] Şifrelenmiş AES anahtarı gönderildi.")
        
        if b'KEY_RECEIVED' not in sock.recv(1024):
            raise Exception("Anahtar gönderimi başarısız!")
        update_status("[*] Anahtar gönderimi onaylandı.")

        hash_message = {'type': 'FILE_HASH', 'hash': file_hash}
        sock.sendall(json.dumps(hash_message).encode() + b'\n')
        update_status(f"[*] Dosya hash'i gönderildi.")

        aes_cipher = AESCipher(aes_key)
        encrypted_data = aes_cipher.encrypt(file_data)
        full_data = encrypted_data['nonce'] + encrypted_data['tag'] + encrypted_data['cipher_text']
        #full_data = file_data # şifreleme olmadan gönderim için

        fragmenter = Fragmenter(max_fragment_size=MAX_FRAGMENT_SIZE)
        fragments = fragmenter.fragment(full_data)
        update_status(f"[*] Veri {len(fragments)} parçaya bölündü.")
        
        for i, fragment in enumerate(fragments):
            fragment_data = {
                'type': 'FRAGMENT',
                'fragment_id': fragment['fragment_number'],
                'total_fragments': fragment['total_fragments'],
                'data': base64.b64encode(fragment['data']).decode()
            }
            message = json.dumps(fragment_data).encode() + b'\n'
            sock.sendall(message)
            update_status(f"[*] Parça {i+1}/{len(fragments)} gönderiliyor...")

        end_message = {'type': 'EOF'}
        sock.sendall(json.dumps(end_message).encode() + b'\n')
        update_status("[✓] Dosya gönderimi tamamlandı.")
        
    except Exception as e:
        update_status(f"[!] Hata: {e}")
    finally:
        try:
            sock.close()
        except:
            pass