# fragmentation.py

import math

class Fragmenter:
    def __init__(self, max_fragment_size=1024):
        self.max_fragment_size = max_fragment_size  # Parça başına maksimum bayt sayısı

    def fragment(self, data):
        """
        Verilen veriyi küçük parçalara ayırır.
        Her parça:
        * Parça numarası
        * Toplam parça sayısı
        * Verinin kendisini içerir.
        """
        fragments = []
        total_fragments = math.ceil(len(data) / self.max_fragment_size)

        for i in range(total_fragments):
            start = i * self.max_fragment_size
            end = start + self.max_fragment_size
            fragment_data = data[start:end]
            fragment_info = {
                'fragment_number': i,
                'total_fragments': total_fragments,
                'data': fragment_data
            }
            fragments.append(fragment_info)

        return fragments

class Reassembler:
    def __init__(self):
        self.fragments = {}

    def add_fragment(self, fragment):
        """
        Gelen parçayı saklar.
        """
        number = fragment['fragment_number']
        self.fragments[number] = fragment['data']

    def is_complete(self, total_fragments):
        """
        Tüm parçalar geldi mi kontrol eder.
        """
        return len(self.fragments) == total_fragments

    def reassemble(self):
        """
        Bütün parçaları sıraya koyup veriyi birleştirir.
        """
        ordered_fragments = [self.fragments[i] for i in sorted(self.fragments.keys())]
        return b''.join(ordered_fragments)

# Test amaçlı çalıştırma
if __name__ == "__main__":
    print("[*] Fragmentation Testi Başlıyor...")

    # Örnek veri
    original_data = "Bu bir test verisidir. Uzun veri fragmentasyona uğrayacaktır.".encode('utf-8') * 10  # Uzunlaştırdık

    fragmenter = Fragmenter(max_fragment_size=50)
    fragments = fragmenter.fragment(original_data)

    print(f"Toplam {len(fragments)} parça oluşturuldu.")

    reassembler = Reassembler()
    for frag in fragments:
        reassembler.add_fragment(frag)

    if reassembler.is_complete(fragments[0]['total_fragments']):
        reassembled_data = reassembler.reassemble()
        print("Veri başarıyla birleştirildi:", reassembled_data == original_data)
    else:
        print("Parçalar eksik!")
