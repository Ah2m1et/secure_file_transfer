# Düşük Seviyeli IP İşleme ve Ağ Performansı Analizi ile Gelişmiş Güvenli Dosya Transfer Sistemi

Bu proje, ağ üzerinde güvenli dosya transferi gerçekleştiren, düşük seviyeli IP paket işleme ve ağ performans analizi yeteneklerine sahip bütünsel bir sistemdir. Sistem, AES-256 ve RSA tabanlı hibrit şifreleme, SHA-256 ile bütünlük doğrulama, Scapy ile IP başlık manipülasyonu ve performans ölçümü gibi gelişmiş özellikler sunar.

## Özellikler

- AES-256 ile dosya şifreleme ve çözme
- RSA ile güvenli anahtar değişimi
- SHA-256 ile veri bütünlüğü kontrolü
- TCP üzerinden güvenli ve sıralı dosya transferi
- Büyük dosyalar için paket parçalama ve birleştirme
- Scapy ile IP başlık (TTL, checksum) manipülasyonu
- Wireshark ve iPerf ile ağ performans analizi
- MITM ve paket enjeksiyonu saldırılarına karşı koruma
- Tkinter tabanlı basit grafik kullanıcı arayüzü

## Sistem Mimarisi

Sistem, istemci-sunucu mimarisi ile çalışır. Bağlantı kurulduğunda RSA ile anahtar değişimi yapılır, dosya parçalanıp AES-256 ile şifrelenir ve TCP üzerinden transfer edilir. Alıcı, parçaları birleştirip deşifre eder ve SHA-256 ile bütünlüğü doğrular.

## Kurulum

```bash
git clone https://github.com/ah2m1et/secure_file_transfer.git
cd secure_file_transfer
```

## Kullanım

Grafik arayüz ile:

```bash
python gui.py
```

## Teknik Detaylar

- **Şifreleme:** AES-256 (EAX modu), anahtar dağıtımı için RSA
- **Bütünlük:** SHA-256 hash kontrolü
- **Ağ:** TCP tabanlı iletişim, Scapy ile IP başlık düzenleme
- **Performans:** iPerf ve ping ile gecikme/bant genişliği ölçümü
- **Saldırı Simülasyonu:** MITM ve paket manipülasyonu testleri
- **GUI:** Tkinter ile temel arayüz

## Karşılaşılan Zorluklar ve Limitler

- Scapy ile checksum yönetimi ve IP başlık düzenleme
- Güvenli anahtar paylaşımı için hibrit şifreleme entegrasyonu
- Ağ koşullarının (gecikme, paket kaybı) simülasyonu
- Sistem tek istemci-sunucu için optimize edilmiştir, çoklu istemci desteği yoktur

## Gelecek Geliştirmeler

- Gelişmiş GUI (ilerleme çubuğu, hız göstergesi)
- Dinamik TCP/UDP protokol seçimi
- Gerçek zamanlı saldırı tespiti (IDS) entegrasyonu

## Sonuç

Bu proje, bilgisayar ağları ve siber güvenlik alanındaki teorik bilgilerin pratik bir uygulamaya dönüştürülmesini amaçlar. Hibrit şifreleme, düşük seviyeli IP işleme ve kapsamlı performans analizi ile güvenli dosya transferi sağlar.

## Proje Tanıtım Videosu

[YouTube - Proje Tanıtım Videosu](https://youtu.be/aRP4iPs8mjo)


Katkılarınızı bekliyoruz! Lütfen bir pull request gönderin.
