#!/usr/bin/env python
# Dosyanın çalıştırılabilir Python scripti olduğunu belirtir.

from __future__ import print_function
# Python 2 ve 3 uyumluluğu için print fonksiyonunu aynı hale getirir.

# Standart kütüphaneler
import unittest
# Python'un birim test (unit test) kütüphanesi

import random
# Rastgele veri üretmek için kullanılıyor

import hashlib
# Python'un hazır SHA-1 implementasyonunu içerir.
# Bizim yazdığımız sha1 koduyla karşılaştırma yapmak için kullanılıyor.

# Kendi yazılmış SHA-1 kütüphanemiz
import sha1


class TestSha1(unittest.TestCase):
    """
    SHA-1 implementasyonunu test eden sınıf.

    unittest.TestCase'ten türediği için içindeki test_ ile başlayan
    fonksiyonlar otomatik olarak test kabul edilir.
    """

    def test_similar(self):
        """
        Çok benzer iki mesajın farklı hash üretip üretmediğini test eder.

        Amaç:
        Mesajda çok küçük bir değişiklik olduğunda hash sonucunun da değişmesi gerekir.
        Bu, hash fonksiyonlarının temel özelliklerinden biridir.
        """
        print('\n>>> running: test_similar')

        # Rastgele bir byte dizisi üret
        first_msg = bytearray(get_random_bytes())

        # Değiştirilmiş mesajı burada oluşturacağız
        modified_msg = bytearray()

        # Mesaj içinden rastgele bir byte seç
        byte_to_modify = random.randrange(0, len(first_msg))

        # İlk mesajın tüm byte'larını dön
        for i, byte in enumerate(first_msg):
            # Eğer seçilen index'teysek o byte'ı 1 artır
            augmentor = 1 if i == byte_to_modify else 0
            modified_msg.append(byte + augmentor)

        # Her iki mesajın SHA-1 özeti alınır
        first_digest = sha1.sha1(bytes(first_msg))
        modified_digest = sha1.sha1(bytes(modified_msg))

        print('... test_similar: checking digest differences')

        # İki digest kesinlikle farklı olmalı
        self.assertNotEqual(first_digest, modified_digest)

        print('... test_similar: success')

    def test_repeatable(self):
        """
        Aynı mesajın her zaman aynı hash değerini verdiğini test eder.

        Amaç:
        Hash fonksiyonları deterministik olmalıdır.
        Yani aynı giriş -> her zaman aynı çıkış.
        """
        print('\n>>> running: test_repeatable')

        # Rastgele bir mesaj üret
        msg = bytearray(get_random_bytes())

        # Aynı mesajı iki kez hashle
        first_digest = sha1.sha1(bytes(msg))
        second_digest = sha1.sha1(bytes(msg))

        print('... test_repeatable: checking for identical digests')

        # Sonuçların aynı olması gerekir
        self.assertEqual(first_digest, second_digest)

        print('... test_repeatable: success')

    def test_comparison(self):
        """
        Kendi yazdığımız SHA-1 kodunu Python hashlib ile karşılaştırır.

        Amaç:
        Bizim implementasyon doğru mu?
        Bunu anlamanın en iyi yolu, güvenilir standart kütüphaneyle aynı sonucu
        üretip üretmediğine bakmaktır.
        """
        print('\n>>> running: test_comparison')

        # Rastgele mesaj üret
        msg = bytearray(get_random_bytes())

        # Kendi SHA-1 implementasyonumuz
        custom_sha1_digest = sha1.sha1(bytes(msg))

        # Python'un hazır SHA-1 implementasyonu
        stdlib_sha1_digest = hashlib.sha1(bytes(msg)).hexdigest()

        print('... test_comparison: checking for identical digests')

        # İkisi birebir aynı olmalı
        self.assertEqual(custom_sha1_digest, stdlib_sha1_digest)

        print('... test_comparison: success')

    def test_associativity(self):
        """
        Parça parça update ederek hash almak ile
        veriyi tek seferde hashlemenin aynı sonucu verdiğini test eder.

        Yani:
        sha1(a + b) == sha1().update(a).update(b)

        Bu özellik özellikle büyük dosyaları parça parça okurken çok önemlidir.
        """
        print('\n>>> running: test_associativity')

        # İki ayrı rastgele mesaj parçası üret
        msg1 = bytearray(get_random_bytes())
        msg2 = bytearray(get_random_bytes())

        # İkisini birleştirip tek seferde hashle
        first_digest = sha1.sha1(bytes(msg1) + bytes(msg2))

        # Aynı işlemi parça parça update ile yap
        sha = sha1.Sha1Hash()
        sha.update(msg1)
        sha.update(msg2)

        second_digest = sha.hexdigest()

        print('... test_associativity: checking for identical digests')

        # İki yöntem de aynı sonucu vermeli
        self.assertEqual(first_digest, second_digest)

        print('... test_associativity: success')


def get_random_bytes():
    """
    Rastgele uzunlukta rastgele byte üretir.

    Açıklama:
    - size değişkeni 1 ile 1000 arasında rastgele seçilir
    - ardından o kadar byte üretilir
    - her byte 0-255 arasında rastgele bir değerdir

    Returns:
        generator olarak byte değerleri döndürür
    """
    size = random.randrange(1, 1000)

    for _ in range(size):
        yield random.getrandbits(8)
        # 8 bit = 1 byte üretir


if __name__ == '__main__':
    # Dosya doğrudan çalıştırılırsa tüm testleri başlatır
    unittest.main()