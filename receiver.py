# receiver.py
import socket
import json
from encryption import AESCipher, RSACipher
from fragmentation import Reassembler
import base64
import os
import hashlib  # <-- eklendi

RECEIVER_IP = '0.0.0.0'  # Tüm IP'lerden bağlantı kabul et
RECEIVER_PORT = 5001
OUTPUT_FILE = 'received_file'  # Çıkış dosyası ismi
RSA_KEY_FILE = 'server_rsa_key.pem'  # RSA anahtar dosyası
VALID_TOKENS = ["secure_client_2024", "backup_token_2024"]  # Geçerli kimlik doğrulama token'ları

def start_receiver():
    # 1. RSA anahtar çifti oluştur veya yükle
    rsa_cipher = RSACipher()
    
    if os.path.exists(RSA_KEY_FILE):
        print("[*] Mevcut RSA anahtarı yükleniyor...")
        rsa_cipher.load_key_from_file(RSA_KEY_FILE)
    else:
        print("[*] Yeni RSA anahtar çifti oluşturuluyor...")
        rsa_cipher.generate_keys()
        rsa_cipher.save_key_to_file(RSA_KEY_FILE)
        print(f"[*] RSA anahtarları '{RSA_KEY_FILE}' dosyasına kaydedildi.")
    
    # 2. Socket oluştur
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Port yeniden kullanılabilir
    server_socket.bind((RECEIVER_IP, RECEIVER_PORT))
    server_socket.listen(1)
    print(f"[*] Dinleniyor: {RECEIVER_IP}:{RECEIVER_PORT}")
    
    while True:
        try:
            conn, addr = server_socket.accept()
            print(f"[*] Bağlantı kabul edildi: {addr}")
            
            handle_client(conn, rsa_cipher, addr)  # addr parametresi eklendi
            
        except Exception as e:
            print(f"[!] İstemci işlenirken hata: {e}")
        finally:
            try:
                conn.close()
            except:
                pass

def handle_client(conn, rsa_cipher, addr):  # addr parametresi eklendi
    buffer = b""
    aes_key = None
    reassembler = Reassembler()
    fragments_received = 0
    total_fragments = 0
    authenticated = False  # Kimlik doğrulama durumu
    original_hash_from_sender = None  # <-- eklendi

    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
                
            buffer += data
            
            # Gelen verileri satırlara böl
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                if not line:
                    continue
                
                try:
                    # İlk olarak ham mesajı kontrol et
                    if line == b'REQUEST_PUBLIC_KEY':
                        if not authenticated:
                            print("[!] Kimlik doğrulamasız genel anahtar isteği - reddediliyor.")
                            conn.close()
                            return
                        
                        print("[*] RSA genel anahtarı istendi.")
                        # Genel anahtarı gönder
                        public_key_dict = rsa_cipher.get_public_key_dict()
                        response = json.dumps(public_key_dict).encode()
                        conn.sendall(response)
                        print("[*] RSA genel anahtarı gönderildi.")
                        continue
                    
                    # JSON mesajları işle
                    message = json.loads(line.decode())
                    
                    if message['type'] == 'AUTH_REQUEST':
                        print(f"[*] Kimlik doğrulama isteği alındı: {addr}")
                        token = message.get('token', '')
                        
                        if token in VALID_TOKENS:
                            authenticated = True
                            auth_response = {
                                'status': 'AUTH_SUCCESS',
                                'message': 'Kimlik doğrulama başarılı'
                            }
                            print("[*] Kimlik doğrulama başarılı.")
                        else:
                            auth_response = {
                                'status': 'AUTH_FAILED',
                                'message': 'Geçersiz token'
                            }
                            print(f"[!] Kimlik doğrulama başarısız - Geçersiz token: {token}")
                        
                        conn.sendall(json.dumps(auth_response).encode())
                        
                        if not authenticated:
                            print("[!] Bağlantı kimlik doğrulama hatası nedeniyle kapatılıyor.")
                            conn.close()
                            return
                        
                    elif message['type'] == 'AES_KEY':
                        if not authenticated:
                            print("[!] Kimlik doğrulamasız AES anahtarı - reddediliyor.")
                            conn.close()
                            return
                        
                        print("[*] Şifrelenmiş AES anahtarı alındı.")
                        # RSA ile şifrelenmiş AES anahtarını çöz
                        encrypted_aes_key = base64.b64decode(message['data'])
                        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
                        print("[*] AES anahtarı başarıyla çözüldü.")
                        
                        # Onay gönder
                        conn.sendall(b'KEY_RECEIVED')
                        print("[*] Anahtar alındı onayı gönderildi.")

                    elif message['type'] == 'FILE_HASH':
                        original_hash_from_sender = message['hash']
                        print(f"[*] Dosya hash'i alındı: {original_hash_from_sender}")

                    elif message['type'] == 'FRAGMENT':
                        if not authenticated:
                            print("[!] Kimlik doğrulamasız fragment - reddediliyor.")
                            conn.close()
                            return
                        
                        if aes_key is None:
                            print("[!] AES anahtarı alınmadan fragment geldi!")
                            continue
                            
                        # Fragment işle
                        fragment = {
                            'fragment_id': message['fragment_id'],
                            'total_fragments': message['total_fragments'],
                            'data': base64.b64decode(message['data'])
                        }
                        
                        reassembler.add_fragment(fragment)
                        fragments_received += 1
                        total_fragments = fragment['total_fragments']
                        
                        print(f"[*] Fragment {fragment['fragment_id']}/{total_fragments} alındı.")
                        
                    elif message['type'] == 'EOF':
                        if not authenticated:
                            print("[!] Kimlik doğrulamasız EOF - reddediliyor.")
                            conn.close()
                            return
                        
                        print("[*] Dosya transferi bitti sinyali alındı.")
                        break
                        
                except json.JSONDecodeError:
                    print(f"[!] JSON çözülürken hata: {line}")
                except Exception as e:
                    print(f"[!] Mesaj işlenirken hata: {e}")
        
        except Exception as e:
            print(f"[!] Veri alınırken hata: {e}")
            break
    
    # Tüm fragmentler alındıysa dosyayı birleştir ve çöz
    if aes_key and fragments_received > 0 and reassembler.is_complete(total_fragments):
        try:
            print("[*] Tüm parçalar alındı, birleştiriliyor...")
            combined_data = reassembler.reassemble()
            print("[*] Tüm parçalar birleştirildi.")
            
            # Şifre çözümü için ilk 16 + 16 baytı ayır (nonce + tag)
            nonce = combined_data[:16]
            tag = combined_data[16:32]
            cipher_text = combined_data[32:]
            
            # AES ile şifre çöz
            aes_cipher = AESCipher(aes_key)
            original_data = aes_cipher.decrypt(cipher_text, nonce, tag)

            # --- Bütünlük kontrolü ---
            received_file_hash = hashlib.sha256(original_data).hexdigest()
            print(f"[*] Alınan dosyanın hash'i: {received_file_hash}")
            print(f"[*] Göndericiden gelen hash: {original_hash_from_sender}")

            if original_hash_from_sender and received_file_hash == original_hash_from_sender:
                print("[✓] Bütünlük doğrulandı! Dosya sağlam.")
                # Dosyayı kaydetme işlemi burada yapılabilir
                with open(OUTPUT_FILE, 'wb') as f:
                    f.write(original_data)
                print(f"[*] Dosya başarıyla kaydedildi: {OUTPUT_FILE}")
            else:
                print("[X] BÜTÜNLÜK HATASI! Dosya bozulmuş veya değiştirilmiş olabilir.")

        except Exception as e:
            print(f"[!] Dosya işlenirken hata: {e}")
    else:
        print("[!] Dosya işleme başarısız - eksik parça veya anahtar sorunu!")

if __name__ == "__main__":
    start_receiver()