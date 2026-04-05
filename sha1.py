#!/usr/bin/env python
# Bu satır dosyanın doğrudan çalıştırılabilir bir Python scripti olduğunu belirtir.

from __future__ import print_function
# Python 2 ve Python 3 uyumluluğu için print fonksiyonunu aynı şekilde kullanmayı sağlar.

import struct
# struct modülü, sayıları byte dizilerine çevirmek veya byte dizilerinden sayı okumak için kullanılır.
# SHA-1 içinde özellikle 4 byte -> 32 bit integer dönüşümü için gerekli.

import io
# io modülü, bytes verisini dosya gibi okuyabilmek için kullanılır.


def _left_rotate(n, b):
    """
    32 bitlik bir sayıyı sola doğru b bit döndürür.

    SHA-1 içinde bit döndürme (rotate) çok kullanılan temel işlemlerden biridir.

    Örnek mantık:
    n = 101100...
    sola döndürme -> soldan çıkan bitler sağ tarafa geri gelir

    Parametreler:
        n: 32 bitlik integer
        b: kaç bit sola döndürüleceği

    Dönüş:
        32 bit sınırında sola döndürülmüş değer
    """
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
    # (n << b)     -> sayıyı sola kaydırır
    # (n >> ...)   -> soldan taşan bitleri sağdan geri getirir
    # |            -> iki parçayı birleştirir
    # & 0xffffffff -> sonucu 32 bit ile sınırlar


def _process_chunk(chunk, h0, h1, h2, h3, h4):
    """
    64 byte'lık bir mesaj bloğunu işler ve yeni hash durumunu döndürür.

    SHA-1, mesajı 512 bitlik (64 byte) bloklar halinde işler.
    Her blok işlendiğinde mevcut hash değeri güncellenir.

    Parametreler:
        chunk: 64 byte'lık veri bloğu
        h0, h1, h2, h3, h4: o ana kadarki hash durumunu tutan 5 adet 32 bit sayı

    Dönüş:
        Güncellenmiş yeni (h0, h1, h2, h3, h4) değerleri
    """
    assert len(chunk) == 64
    # Bu fonksiyon sadece 64 byte'lık blok bekler.
    # Farklı boyut gelirse program burada hata verir.

    w = [0] * 80
    # SHA-1 message schedule dizisi.
    # İlk 16 eleman direkt bloktan gelir, kalan 64 eleman türetilir.

    # Chunk'ı 16 tane 4-byte big-endian kelimeye ayır
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]
        # >I -> big-endian unsigned int (4 byte)
        # Örneğin 4 byte'ı 32 bitlik sayıya çevirir.

    # 16 kelimeyi 80 kelimeye genişlet
    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
        # SHA-1 standardına göre:
        # w[i] = leftrotate(w[i-3] XOR w[i-8] XOR w[i-14] XOR w[i-16], 1)

    # Geçici çalışma değişkenleri
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    # SHA-1 ana döngüsü: toplam 80 tur
    for i in range(80):
        if 0 <= i <= 19:
            # İlk 20 tur
            # f = (b AND c) OR ((NOT b) AND d) ifadesinin eşdeğer bir yazımı kullanılıyor
            # Burada bitwise NOT kullanmadan alternatif formül tercih edilmiş
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
            # Bu tur aralığında kullanılan sabit

        elif 20 <= i <= 39:
            # 20-39 arası
            f = b ^ c ^ d
            k = 0x6ED9EBA1

        elif 40 <= i <= 59:
            # 40-59 arası
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC

        elif 60 <= i <= 79:
            # 60-79 arası
            f = b ^ c ^ d
            k = 0xCA62C1D6

        # Ana güncelleme formülü
        a, b, c, d, e = (
            (_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
            a,
            _left_rotate(b, 30),
            c,
            d
        )
        # Burada tüm register'lar bir sonraki tura hazırlanır.
        # SHA-1'in kalbi burasıdır.

    # Bu chunk'ın sonucu mevcut hash durumuna eklenir
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4


class Sha1Hash(object):
    """
    hashlib benzeri çalışan bir SHA-1 sınıfı.

    Bu sınıf sayesinde:
    - veriyi parça parça update() ile verebiliriz
    - digest() ile byte çıktı alabiliriz
    - hexdigest() ile hex çıktı alabiliriz
    """

    name = 'python-sha1'
    # Algoritmanın adı

    digest_size = 20
    # SHA-1 çıktısı 160 bittir = 20 byte

    block_size = 64
    # SHA-1 blok boyutu 512 bittir = 64 byte

    def __init__(self):
        """
        Başlangıç hash durumunu kurar.
        SHA-1 standardında başlangıçta kullanılan sabit değerler vardır.
        """
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )

        # Henüz işlenmemiş ama elde kalan byte'lar burada tutulur.
        # Çünkü veri her zaman tam 64 byte'lık katlar halinde gelmeyebilir.
        self._unprocessed = b''

        # Şu ana kadar işlenmiş toplam byte sayısı
        self._message_byte_length = 0

    def update(self, arg):
        """
        Mevcut hash hesabına yeni veri ekler.

        Bu fonksiyon birden fazla kez çağrılabilir.
        Böylece mesajı tek seferde değil parça parça da hashleyebiliriz.

        Parametre:
            arg: bytes, bytearray veya BytesIO benzeri veri

        Dönüş:
            self
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)
            # Eğer doğrudan bytes geldiyse, bunu dosya gibi okunabilir hale getiriyoruz.

        # Önceden kalan işlenmemiş veriyi tamamlamaya çalış
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # 64 byte oldukça blok blok işle
        while len(chunk) == 64:
            self._h = _process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        # 64 byte'tan az kalan veriyi daha sonra işlemek üzere sakla
        self._unprocessed = chunk
        return self

    def digest(self):
        """
        Final hash çıktısını bytes olarak döndürür.
        Örn: b'\\xa9\\x99...'
        """
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())
        # Her 32 bitlik parçayı big-endian byte dizisine çevirip birleştirir.

    def hexdigest(self):
        """
        Final hash çıktısını hex string olarak döndürür.
        Örn: 'a9993e364706816aba3e25717850c26c9cd0d89d'
        """
        return '%08x%08x%08x%08x%08x' % self._produce_digest()

    def _produce_digest(self):
        """
        Padding işlemini yapar ve son digest değerlerini üretir.

        SHA-1'de mesaj doğrudan işlenmez;
        önce sonuna padding eklenir:
        1) bir adet '1' biti
        2) yeterince '0' biti
        3) orijinal mesaj uzunluğu (bit cinsinden, 64 bit olarak)
        """
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # Mesaj sonuna 1 biti ekle
        # Byte seviyesinde bu: 10000000 = 0x80
        message += b'\x80'

        # Uzunluk 56 mod 64 olacak şekilde sıfırlar ekle
        # Çünkü son 8 byte'a mesaj uzunluğu yazılacak
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # Orijinal mesaj uzunluğunu bit cinsine çevir
        message_bit_length = message_byte_length * 8

        # Bu uzunluğu 64 bit big-endian olarak sona ekle
        message += struct.pack(b'>Q', message_bit_length)
        # >Q -> big-endian unsigned long long (8 byte)

        # Artık elimizde son blok(lar) hazır
        h = _process_chunk(message[:64], *self._h)

        if len(message) == 64:
            return h

        # Eğer padding nedeniyle 2 blok olduysa ikinci bloğu da işle
        return _process_chunk(message[64:], *h)


def sha1(data):
    """
    Kullanımı kolay yardımcı fonksiyon.

    Parametre:
        data: bytes veya dosya benzeri veri

    Dönüş:
        SHA-1 hash sonucu hex string
    """
    return Sha1Hash().update(data).hexdigest()


if __name__ == '__main__':
    # Bu dosya doğrudan çalıştırılırsa aşağıdaki komut satırı kodu çalışır.

    import argparse
    import sys
    import os

    # Komut satırından girilen argümanları okumak için parser oluştur
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'input',
        nargs='*',
        help='input file or message to hash'
    )
    args = parser.parse_args()

    data = None

    if len(args.input) == 0:
        # Eğer kullanıcı argüman vermediyse veriyi standart girişten oku
        try:
            # Python 3'te detach() ile binary okuma sağlanır
            data = sys.stdin.detach()
        except AttributeError:
            # Python 2 / bazı durumlarda Windows için binary mode ayarı
            if sys.platform == "win32":
                import msvcrt
                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)

            data = sys.stdin

        print('sha1-digest:', sha1(data))

    else:
        # Kullanıcı dosya ismi girdiyse tek tek işle
        for argument in args.input:
            if os.path.isfile(argument):
                # Dosya gerçekten varsa binary modda aç
                data = open(argument, 'rb')

                # Hash sonucunu yazdır
                print('sha1-digest:', sha1(data))
            else:
                print("Error, could not find " + argument + " file.")