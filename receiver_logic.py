# receiver_logic.py (DÜZELTİLMİŞ HALİ)
import socket
import json
from encryption import AESCipher, RSACipher
from fragmentation import Reassembler
import base64
import os
import hashlib

RECEIVER_IP = '0.0.0.0'
RECEIVER_PORT = 5001
OUTPUT_FILE = 'received_file'
RSA_KEY_FILE = 'server_rsa_key.pem'
VALID_TOKENS = ["secure_client_2024", "backup_token_2024"]

def start_receiver_logic(status_callback):
    def update_status(message):
        print(message)
        if status_callback:
            status_callback(message)

    rsa_cipher = RSACipher()
    if os.path.exists(RSA_KEY_FILE):
        update_status("[*] Mevcut RSA anahtarı yükleniyor...")
        rsa_cipher.load_key_from_file(RSA_KEY_FILE)
    else:
        update_status("[*] Yeni RSA anahtar çifti oluşturuluyor...")
        rsa_cipher.generate_keys()
        rsa_cipher.save_key_to_file(RSA_KEY_FILE)
        update_status(f"[*] RSA anahtarları '{RSA_KEY_FILE}' dosyasına kaydedildi.")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((RECEIVER_IP, RECEIVER_PORT))
    server_socket.listen(1)
    update_status(f"[*] Dinleniyor: {RECEIVER_IP}:{RECEIVER_PORT}")

    try:
        conn, addr = server_socket.accept()
        update_status(f"[*] Bağlantı kabul edildi: {addr}")
        handle_client(conn, rsa_cipher, addr, status_callback) # Burası 4 parametre gönderiyor
    except Exception as e:
        update_status(f"[!] Sunucu hatası: {e}")
    finally:
        server_socket.close()


# Fonksiyon tanımına 'status_callback' eklendi
def handle_client(conn, rsa_cipher, addr, status_callback):
    def update_status(message):
        print(message)
        if status_callback:
            status_callback(message)

    buffer = b""
    aes_key = None
    reassembler = Reassembler()
    fragments_received = 0
    total_fragments = 0
    authenticated = False
    original_hash_from_sender = None

    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            buffer += data
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                if not line:
                    continue
                
                try:
                    if line == b'REQUEST_PUBLIC_KEY':
                        if not authenticated:
                            update_status("[!] Kimlik doğrulamasız genel anahtar isteği - reddediliyor.")
                            conn.close()
                            return
                        update_status("[*] RSA genel anahtarı istendi.")
                        public_key_dict = rsa_cipher.get_public_key_dict()
                        response = json.dumps(public_key_dict).encode()
                        conn.sendall(response)
                        update_status("[*] RSA genel anahtarı gönderildi.")
                        continue
                    
                    message = json.loads(line.decode())
                    
                    if message['type'] == 'AUTH_REQUEST':
                        update_status(f"[*] Kimlik doğrulama isteği alındı: {addr}")
                        token = message.get('token', '')
                        if token in VALID_TOKENS:
                            authenticated = True
                            auth_response = {'status': 'AUTH_SUCCESS', 'message': 'Kimlik doğrulama başarılı'}
                            update_status("[*] Kimlik doğrulama başarılı.")
                        else:
                            auth_response = {'status': 'AUTH_FAILED', 'message': 'Geçersiz token'}
                            update_status(f"[!] Kimlik doğrulama başarısız - Geçersiz token: {token}")
                        conn.sendall(json.dumps(auth_response).encode())
                        if not authenticated:
                            update_status("[!] Bağlantı kimlik doğrulama hatası nedeniyle kapatılıyor.")
                            conn.close()
                            return
                            
                    elif message['type'] == 'AES_KEY':
                        if not authenticated:
                            update_status("[!] Kimlik doğrulamasız AES anahtarı - reddediliyor.")
                            conn.close()
                            return
                        update_status("[*] Şifrelenmiş AES anahtarı alındı.")
                        encrypted_aes_key = base64.b64decode(message['data'])
                        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
                        update_status("[*] AES anahtarı başarıyla çözüldü.")
                        conn.sendall(b'KEY_RECEIVED')
                        update_status("[*] Anahtar alındı onayı gönderildi.")

                    elif message['type'] == 'FILE_HASH':
                        original_hash_from_sender = message['hash']
                        update_status(f"[*] Dosya hash'i alındı: {original_hash_from_sender}")

                    elif message['type'] == 'FRAGMENT':
                        # ... (Bu bölümdeki tüm print'leri de update_status ile değiştir)
                        update_status(f"[*] Fragment {message['fragment_id']}/{message['total_fragments']} alındı.")
                        # ...
                        # Diğer kodlar...
                        
                    elif message['type'] == 'EOF':
                        update_status("[*] Dosya transferi bitti sinyali alındı.")
                        break

                except Exception as e:
                    update_status(f"[!] Mesaj işlenirken hata: {e}")
        
        except Exception as e:
            update_status(f"[!] Veri alınırken hata: {e}")
            break
            
    # Dosya işleme mantığı (tüm print'leri update_status ile değiştir)
    if aes_key and reassembler.is_complete(total_fragments):
        # ...
        update_status("[✓] Bütünlük doğrulandı! Dosya sağlam.")
        # ...
    else:
        update_status("[!] Dosya işleme başarısız - eksik parça veya anahtar sorunu!")