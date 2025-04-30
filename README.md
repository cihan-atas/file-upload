# Kapsamlı Güvenli Dosya Yükleme (File Upload) Rehberi (PHP Odaklı)

## İçindekiler

1.  [Giriş: Neden Önemli ve Riskler Nelerdir?](#1-giriş-neden-önemli-ve-riskler-nelerdir)
2.  [Temel Dosya Yükleme Süreci](#2-temel-dosya-yükleme-süreci)
    *   [2.1. İstemci Tarafı: HTML Formu](#21-istemci-tarafı-html-formu)
    *   [2.2. Sunucu Tarafı: PHP ve `$_FILES` Süper Globali](#22-sunucu-tarafı-php-ve-_files-süper-globali)
3.  [İstemci Tarafı Doğrulama: İlk Savunma Hattı (Ama Yetersiz!)](#3-istemci-tarafı-doğrulama-ilk-savunma-hattı-ama-yetersiz)
    *   [3.1. HTML5 `accept` Özniteliği](#31-html5-accept-özniteliği)
    *   [3.2. JavaScript ile Doğrulama](#32-javascript-ile-doğrulama)
4.  [Sunucu Tarafı Doğrulama: Güvenliğin Kalesi](#4-sunucu-tarafı-doğrulama-güvenliğin-kalesi)
    *   [4.1. Temel Kontroller: İstek Metodu, Varlık ve Hata Kodları](#41-temel-kontroller-istek-metodu-varlık-ve-hata-kodları)
    *   [4.2. Dosya Boyutu Kontrolü: Kaynak Yönetimi](#42-dosya-boyutu-kontrolü-kaynak-yönetimi)
    *   [4.3. Dosya Türü Doğrulaması: En Kritik Adım](#43-dosya-türü-doğrulaması-en-kritik-adım)
        *   [4.3.1. Neden `$_FILES['...']['type']` Güvenilmezdir?](#431-neden-_files-type-güvenilmezdir)
        *   [4.3.2. Neden Sadece Uzantı Kontrolü Yetersizdir?](#432-neden-sadece-uzantı-kontrolü-yetersizdir)
        *   [4.3.3. Altın Standart: `finfo` ile MIME Türü Doğrulaması](#433-altın-standart-finfo-ile-mime-türü-doğrulaması)
        *   [4.3.4. Uzantı Kontrolü (Ek Güvenlik Katmanı Olarak)](#434-uzantı-kontrolü-ek-güvenlik-katmanı-olarak)
        *   [4.3.5. Beyaz Liste (Whitelist) vs Kara Liste (Blacklist)](#435-beyaz-liste-whitelist-vs-kara-liste-blacklist)
    *   [4.4. Dosya Adı Sanitasyonu ve Güvenliği](#44-dosya-adı-sanitasyonu-ve-güvenliği)
        *   [4.4.1. Dizin Değiştirme (Directory Traversal) Saldırılarını Önleme](#441-dizin-değiştirme-directory-traversal-saldırılarını-önleme)
        *   [4.4.2. Geçersiz Karakterleri Temizleme](#442-geçersiz-karakterleri-temizleme)
        *   [4.4.3. Benzersiz Dosya Adları Oluşturma](#443-benzersiz-dosya-adları-oluşturma)
5.  [Dosyayı Güvenle Taşıma: `move_uploaded_file()`](#5-dosyayı-güvenle-taşıma-move_uploaded_file)
6.  [Güvenli Depolama Stratejileri](#6-güvenli-depolama-stratejileri)
    *   [6.1. Web Kök Dizininden Uzak Durmak](#61-web-kök-dizininden-uzak-durmak)
    *   [6.2. Dizin İzinlerinin Önemi (Permissions)](#62-dizin-izinlerinin-önemi-permissions)
    *   [6.3. Veritabanı ile Entegrasyon](#63-veritabanı-ile-entegrasyon)
    *   [6.4. Dosyaları Güvenli Şekilde Sunma (Serving Files)](#64-dosyaları-güvenli-şekilde-sunma-serving-files)
7.  [İleri Düzey Güvenlik Önlemleri ve Konfigürasyonlar](#7-ileri-düzey-güvenlik-önlemleri-ve-konfigürasyonlar)
    *   [7.1. Web Sunucusu Yapılandırması (`.htaccess`, Nginx)](#71-web-sunucusu-yapılandırması-htaccess-nginx)
    *   [7.2. Dosya İçeriği Analizi ve Sanitasyonu (Image Re-creation vb.)](#72-dosya-içeriği-analizi-ve-sanitasyonu-image-re-creation-vb)
    *   [7.3. Antivirüs / Malware Taraması](#73-antivirüs--malware-taraması)
    *   [7.4. Hız Sınırlama (Rate Limiting)](#74-hız-sınırlama-rate-limiting)
    *   [7.5. İçerik Dağıtım Ağları (CDN)](#75-içerik-dağıtım-ağları-cdn)
    *   [7.6. Kayıt Tutma (Logging) ve İzleme](#76-kayıt-tutma-logging-ve-izleme)
8.  [Örnek Kapsamlı PHP Kodu](#8-örnek-kapsamlı-php-kodu)
9.  [Yaygın Hatalar ve Kontrol Listesi](#9-yaygın-hatalar-ve-kontrol-listesi)
10. [Sonuç](#10-sonuç)

---

## 1. Giriş: Neden Önemli ve Riskler Nelerdir?

Dosya yükleme işlevselliği, kullanıcıların profil resimleri, belgeler, videolar gibi içerikleri paylaşmasını sağlar ve birçok modern web uygulamasının ayrılmaz bir parçasıdır. Ancak bu işlevsellik, siber saldırganlar için cazip bir hedef olabilir. Yanlış yapılandırılmış bir dosya yükleme mekanizması aşağıdaki gibi ciddi risklere yol açabilir:

*   **Uzaktan Kod Çalıştırma (Remote Code Execution - RCE):** En tehlikeli risklerden biridir. Saldırganlar, sunucuda çalıştırılabilecek betikler (PHP, Perl, Shell vb.) yükleyerek sunucunun kontrolünü ele geçirebilir.
*   **Hizmet Reddi (Denial of Service - DoS):** Çok sayıda veya çok büyük dosyalar yükleyerek sunucu kaynaklarını (disk alanı, CPU, bellek) tüketebilirler.
*   **Siteler Arası Betik Çalıştırma (Cross-Site Scripting - XSS):** Özel olarak hazırlanmış dosya adları veya içerikleri (örn. SVG dosyaları) aracılığıyla diğer kullanıcıların tarayıcılarında zararlı JavaScript kodları çalıştırılabilir.
*   **Bilgi İfşası (Information Disclosure):** Sunucudaki hassas yapılandırma dosyaları veya diğer kullanıcıların dosyaları üzerine yazılabilir veya erişilebilir hale gelebilir (özellikle Dizin Değiştirme saldırılarıyla).
*   **Kimlik Sahteciliği (Phishing):** Güvenilir görünen ama aslında zararlı içerik barındıran dosyalar (örn. sahte PDF'ler) yüklenebilir.

Bu rehber, bu riskleri en aza indirmek için katmanlı bir güvenlik yaklaşımı benimseyerek PHP ile nasıl güvenli dosya yükleme mekanizmaları oluşturulacağını detaylandıracaktır. **Temel prensip şudur: KULLANICIDAN GELEN HİÇBİR VERİYE GÜVENME!**

---

## 2. Temel Dosya Yükleme Süreci

### 2.1. İstemci Tarafı: HTML Formu

Dosya yükleme işlemi bir HTML formu ile başlar. Kritik noktalar şunlardır:

*   `method="post"`: Dosya verileri HTTP POST isteği ile gönderilmelidir. GET metodu dosya yüklemeyi desteklemez ve boyut limitleri vardır.
*   `enctype="multipart/form-data"`: Bu kodlama türü, form verilerini farklı bölümlere ayırır ve büyük ikili verilerin (dosyaların) gönderilmesini sağlar. Bu olmadan dosya yükleme çalışmaz.
*   `<input type="file">`: Kullanıcının dosya seçme arayüzünü açar.

```html
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Güvenli Dosya Yükleme Formu</title>
</head>
<body>

<h1>Dosya Yükle</h1>

<form action="upload_handler.php" method="post" enctype="multipart/form-data">
  <!-- Gizli alan ile maksimum dosya boyutu (isteğe bağlı, sunucu tarafı kontrolü esastır) -->
  <input type="hidden" name="MAX_FILE_SIZE" value="5242880" /> <!-- Örnek: 5 MB (5 * 1024 * 1024 bytes) -->
  
  <label for="userfile">Dosya Seçin:</label>
  <input type="file" name="userfile" id="userfile" required> 
  <br><br>
  <input type="submit" value="Dosyayı Yükle" name="submit">
</form>

</body>
</html>
```

*Not: `MAX_FILE_SIZE` gizli alanı, tarayıcıya bir ipucu verir ancak kolayca atlatılabilir. Sunucu tarafı boyut kontrolü **zorunludur**.*

### 2.2. Sunucu Tarafı: PHP ve `$_FILES` Süper Globali

Form gönderildiğinde, PHP yüklenen dosya bilgilerini `$_FILES` süper global dizisinde depolar. `name="userfile"` kullanıldıysa, verilere şöyle erişilir:

*   **`$_FILES['userfile']['name']`**: Orijinal dosya adı (örn: `My Document.pdf`). **GÜVENİLMEZ.** Kullanıcı tarafından belirlenir.
*   **`$_FILES['userfile']['type']`**: Tarayıcının gönderdiği MIME türü (örn: `application/pdf`). **GÜVENİLMEZ.** Kullanıcı tarafından manipüle edilebilir.
*   **`$_FILES['userfile']['size']`**: Dosyanın bayt cinsinden boyutu (örn: `102400`).
*   **`$_FILES['userfile']['tmp_name']`**: Dosyanın sunucudaki geçici konumu (örn: `/tmp/phpAbCdEf`). Bu dosya, betik çalışması bittikten sonra otomatik olarak silinir. Güvenlik kontrolleri bu dosya üzerinde yapılmalıdır.
*   **`$_FILES['userfile']['error']`**: Yükleme sırasında oluşan [hata kodu](https://www.php.net/manual/tr/features.file-upload.errors.php). Hata yoksa `UPLOAD_ERR_OK` (değeri 0) olur.

---

## 3. İstemci Tarafı Doğrulama: İlk Savunma Hattı (Ama Yetersiz!)

İstemci tarafı doğrulama (JavaScript, HTML5 öznitelikleri), kullanıcı deneyimini iyileştirmek ve sunucuya gereksiz istek göndermeden önce bariz hataları (yanlış dosya türü, çok büyük boyut) yakalamak için kullanışlıdır. **Ancak, güvenlik açısından kesinlikle güvenilmemelidir.**

### 3.1. HTML5 `accept` Özniteliği

`<input type="file">` elemanına `accept` özniteliği ekleyerek dosya seçme penceresinde varsayılan olarak gösterilecek dosya türlerini filtreleyebilirsiniz.

```html
<!-- Sadece JPEG ve PNG resimlerini göster -->
<input type="file" name="imagefile" accept="image/jpeg, image/png">

<!-- Resim dosyalarını genel olarak göster -->
<input type="file" name="imagefile" accept="image/*">

<!-- Belirli uzantıları göster -->
<input type="file" name="docfile" accept=".pdf, .doc, .docx"> 
```

**Dezavantajı:** Kullanıcı genellikle "Tüm Dosyalar" seçeneğini seçerek bu filtreyi kolayca geçebilir. Güvenlik sağlamaz, sadece kolaylık sunar.

### 3.2. JavaScript ile Doğrulama

JavaScript kullanarak dosya adı (uzantı), boyut ve bazen tür (deneysel API'lerle) kontrol edilebilir.

```html
<input type="file" id="userfile" name="userfile" onchange="validateClientSide(this)">
<span id="file-error" style="color: red;"></span>

<script>
function validateClientSide(input) {
    const file = input.files[0];
    const errorSpan = document.getElementById('file-error');
    errorSpan.textContent = ''; // Hata mesajını temizle

    if (!file) {
        return; // Dosya seçilmemiş
    }

    // 1. Uzantı Kontrolü (Temel)
    const allowedExtensions = /(\.jpg|\.jpeg|\.png|\.gif|\.pdf)$/i;
    if (!allowedExtensions.exec(file.name)) {
        errorSpan.textContent = 'Geçersiz dosya uzantısı. İzin verilenler: JPG, JPEG, PNG, GIF, PDF';
        input.value = ''; // Seçimi sıfırla
        return false;
    }

    // 2. Boyut Kontrolü
    const maxSize = 5 * 1024 * 1024; // 5 MB
    if (file.size > maxSize) {
        errorSpan.textContent = 'Dosya boyutu çok büyük. Maksimum: 5 MB';
        input.value = ''; 
        return false;
    }

    // 3. MIME Türü Kontrolü (Tarayıcıya bağlı, güvenilmez!)
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (!allowedMimeTypes.includes(file.type)) {
         // Bu kontrol yanıltıcı olabilir, sunucu tarafı finfo daha güvenilirdir.
         // İsteğe bağlı olarak eklenebilir ama çok güvenmeyin.
         console.warn('Tarayıcı MIME türü (' + file.type + ') beklenenden farklı olabilir.');
    }

    console.log('İstemci tarafı temel kontroller başarılı.');
    return true;
}
</script>
```

**Tekrar:** Bu kontroller kullanıcı deneyimi içindir. Kötü niyetli bir kullanıcı, tarayıcı geliştirici araçlarını kullanarak veya `curl` gibi araçlarla isteği manuel olarak oluşturarak bu kontrolleri **tamamen atlatabilir.**

---

## 4. Sunucu Tarafı Doğrulama: Güvenliğin Kalesi

Gerçek güvenlik burada başlar. **Tüm kritik kontroller sunucu tarafında yapılmalıdır.**

### 4.1. Temel Kontroller: İstek Metodu, Varlık ve Hata Kodları

Her şeyden önce, isteğin doğru yöntemle geldiğini, `$_FILES` dizisinin beklenen anahtarı içerdiğini ve temel bir yükleme hatası olmadığını kontrol edin.

```php
<?php
// Sadece POST isteklerini kabul et
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    die("Hata: Yalnızca POST istekleri kabul edilir.");
}

// 'userfile' anahtarının $_FILES dizisinde olup olmadığını kontrol et
if (!isset($_FILES['userfile'])) {
    die("Hata: Formda 'userfile' adında bir dosya alanı bulunamadı veya dosya yüklenmedi.");
}

// Hata kodunu al
$error_code = $_FILES['userfile']['error'];

// Hata kodunu kontrol et
if ($error_code !== UPLOAD_ERR_OK) {
    $upload_errors = [
        UPLOAD_ERR_INI_SIZE   => "Yüklenen dosya php.ini dosyasındaki upload_max_filesize direktifini aşıyor.",
        UPLOAD_ERR_FORM_SIZE  => "Yüklenen dosya HTML formundaki MAX_FILE_SIZE direktifini aşıyor.",
        UPLOAD_ERR_PARTIAL    => "Dosya yalnızca kısmen yüklendi.",
        UPLOAD_ERR_NO_FILE    => "Hiç dosya yüklenmedi.",
        UPLOAD_ERR_NO_TMP_DIR => "Geçici klasör eksik.",
        UPLOAD_ERR_CANT_WRITE => "Dosya diske yazılamadı.",
        UPLOAD_ERR_EXTENSION  => "Bir PHP eklentisi dosya yüklemeyi durdurdu.",
    ];
    $error_message = $upload_errors[$error_code] ?? "Bilinmeyen bir yükleme hatası oluştu (Kod: $error_code).";
    die("Yükleme Hatası: " . $error_message);
}

// Bu noktada, temel yükleme başarılı ve dosya geçici konumda.
echo "Temel kontroller başarılı. Dosya geçici olarak yüklendi.<br>";
?>
```

### 4.2. Dosya Boyutu Kontrolü: Kaynak Yönetimi

`php.ini`'deki `upload_max_filesize` ve `post_max_size` direktifleri genel limitleri belirler, ancak uygulamanız için daha spesifik bir sınır belirlemek genellikle iyi bir fikirdir.

```php
<?php
// ... önceki kontrollerden sonra ...

$file_size = $_FILES['userfile']['size'];
$max_allowed_size = 5 * 1024 * 1024; // 5 MB (bytes)

if ($file_size === 0) {
    die("Hata: Yüklenen dosya boş.");
}

if ($file_size > $max_allowed_size) {
    die("Hata: Dosya boyutu izin verilen limiti (".($max_allowed_size / 1024 / 1024)." MB) aşıyor.");
}

echo "Dosya boyutu kontrolü başarılı ($file_size bytes).<br>";
?>
```

### 4.3. Dosya Türü Doğrulaması: En Kritik Adım

Saldırganların zararlı kod yüklemesini engellemenin anahtarı buradadır.

#### 4.3.1. Neden `$_FILES['...']['type']` Güvenilmezdir?

Tarayıcı, dosya içeriğine bakmadan genellikle dosya uzantısına göre bir MIME türü gönderir. Kullanıcı, bir HTTP isteği düzenleme aracıyla (örneğin Burp Suite) bu değeri kolayca değiştirebilir. Örneğin, `shell.php` dosyasını yüklerken `Content-Type` başlığını `image/jpeg` olarak ayarlayabilir. **Bu değere ASLA GÜVENMEYİN.**

#### 4.3.2. Neden Sadece Uzantı Kontrolü Yetersizdir?

*   **Çift Uzantı (Double Extensions):** Saldırganlar `zararli.php.jpg` gibi dosya adları kullanabilir. Basit bir uzantı kontrolü `.jpg`'yi görüp dosyayı kabul edebilir, ancak bazı web sunucusu yapılandırmaları (özellikle eski veya yanlış yapılandırılmış Apache) ilk uzantıyı (`.php`) tanıyıp dosyayı PHP olarak çalıştırabilir.
*   **Büyük/Küçük Harf Duyarlılığı:** `.jpg`'yi kontrol ederken `.JPG` veya `.JpG` gibi varyasyonları gözden kaçırabilirsiniz. `strtolower()` kullanmak önemlidir.
*   **Aldatma:** Uzantı, dosyanın gerçek içeriğini yansıtmayabilir. `.txt` uzantılı bir dosya aslında derlenmiş bir C kodu olabilir.

#### 4.3.3. Altın Standart: `finfo` ile MIME Türü Doğrulaması

PHP'nin [Fileinfo](https://www.php.net/manual/tr/book.fileinfo.php) eklentisi, dosyanın içeriğindeki "sihirli baytları" (magic bytes) analiz ederek dosyanın gerçek MIME türünü belirler. Bu, tarayıcının gönderdiği veya dosya uzantısının söylediği şeye bakmaksızın, en güvenilir yöntemdir. Çoğu modern PHP kurulumunda varsayılan olarak etkindir.

```php
<?php
// ... önceki kontrollerden sonra ...

// İzin verilen MIME türlerinin beyaz listesi (Whitelist)
$allowed_mime_types = [
    'image/jpeg',   // JPEG resimleri
    'image/png',    // PNG resimleri
    'image/gif',    // GIF resimleri
    'application/pdf', // PDF belgeleri
    'application/msword', // Eski Word .doc
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // Yeni Word .docx
    'text/plain'    // Düz metin dosyaları
    // İhtiyaca göre ekleyin veya çıkarın
];

$tmp_path = $_FILES['userfile']['tmp_name'];

// finfo kaynağını aç
$finfo = finfo_open(FILEINFO_MIME_TYPE);
if ($finfo === false) {
    die("Hata: finfo_open() başarısız oldu."); // finfo eklentisi etkin olmayabilir
}

// Geçici dosyanın MIME türünü al
$detected_mime_type = finfo_file($finfo, $tmp_path);

// finfo kaynağını kapat
finfo_close($finfo);

// Algılanan MIME türünün izin verilenler listesinde olup olmadığını kontrol et
if ($detected_mime_type === false) {
     die("Hata: Dosya MIME türü algılanamadı.");
}

if (!in_array($detected_mime_type, $allowed_mime_types)) {
    die("Hata: Geçersiz dosya türü algılandı ($detected_mime_type). Güvenlik nedeniyle reddedildi.");
}

echo "Güvenilir MIME türü kontrolü başarılı ($detected_mime_type).<br>";
?>
```

#### 4.3.4. Uzantı Kontrolü (Ek Güvenlik Katmanı Olarak)

`finfo` kontrolüne ek olarak, dosya uzantısını da kontrol etmek, özellikle MIME türü ile uzantı arasında bir tutarlılık sağlamak veya belirli kullanım durumları için (örn. sadece `.jpg` ve `.jpeg` kabul etmek ama `image/jpeg` olan `.jfif`'leri engellemek) faydalı olabilir.

```php
<?php
// ... finfo kontrolünden sonra ...

$original_filename = $_FILES['userfile']['name'];
// pathinfo kullanarak uzantıyı güvenli bir şekilde al ve küçük harfe çevir
$file_extension = strtolower(pathinfo($original_filename, PATHINFO_EXTENSION));

// İzin verilen uzantıların beyaz listesi (MIME türleri ile tutarlı olmalı)
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt'];

if (empty($file_extension)) {
    die("Hata: Dosya uzantısı bulunamadı.");
}

if (!in_array($file_extension, $allowed_extensions)) {
    die("Hata: Geçersiz dosya uzantısı (.$file_extension).");
}

// İsteğe bağlı: Algılanan MIME türü ile uzantının tutarlılığını kontrol etme
$mime_to_ext_map = [
    'image/jpeg' => ['jpg', 'jpeg'],
    'image/png'  => ['png'],
    'image/gif'  => ['gif'],
    'application/pdf' => ['pdf'],
    'application/msword' => ['doc'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => ['docx'],
    'text/plain' => ['txt']
];

if (!isset($mime_to_ext_map[$detected_mime_type]) || !in_array($file_extension, $mime_to_ext_map[$detected_mime_type])) {
     die("Hata: Algılanan dosya türü ($detected_mime_type) ile dosya uzantısı (.$file_extension) eşleşmiyor.");
}

echo "Dosya uzantısı kontrolü başarılı (.$file_extension).<br>";
?>
```

#### 4.3.5. Beyaz Liste (Whitelist) vs Kara Liste (Blacklist)

*   **Beyaz Liste (Önerilen):** Yalnızca *izin verdiğiniz* belirli dosya türlerini/uzantılarını tanımlayın. Bilmediğiniz veya beklemediğiniz her şeyi reddedin. Bu çok daha güvenlidir çünkü gelecekte ortaya çıkabilecek yeni tehlikeli dosya türlerini otomatik olarak engeller. Yukarıdaki örnekler beyaz liste yaklaşımını kullanır.
*   **Kara Liste:** Yasaklamak istediğiniz tehlikeli dosya türlerini/uzantılarını (`.php`, `.exe`, `.sh` vb.) listelersiniz. Bu **önerilmez**, çünkü listeniz eksik olabilir ve yeni tehlikeli türler ortaya çıktığında güncel tutmanız gerekir. Bir şeyi unutmak kolaydır.

**Kural: Her zaman beyaz liste kullanın!**

### 4.4. Dosya Adı Sanitasyonu ve Güvenliği

Kullanıcının gönderdiği orijinal dosya adına asla güvenmeyin.

#### 4.4.1. Dizin Değiştirme (Directory Traversal) Saldırılarını Önleme

Saldırganlar, `../../etc/passwd` gibi dosya adları göndererek sunucu dosya sisteminde gezinmeye çalışabilir. `basename()` fonksiyonu, dosya adından tüm yol bileşenlerini kaldırarak sadece dosya adını bırakır ve bu saldırıyı engeller.

```php
<?php
// ... önceki kontrollerden sonra ...
$original_filename = $_FILES['userfile']['name'];
$safe_basename = basename($original_filename); // Örn: "../../file.txt" -> "file.txt"

echo "basename() ile güvenli dosya adı: $safe_basename <br>";
?>
```

#### 4.4.2. Geçersiz Karakterleri Temizleme

Dosya sistemleri ve URL'ler bazı karakterleri (boşluk, `*`, `?`, `/`, `\`, `:`, `<`, `>`, `|`, `"`, Türkçe karakterler vb.) iyi işlemez. Bu karakterleri kaldırmak veya güvenli bir alternatifle (genellikle alt çizgi `_`) değiştirmek önemlidir.

```php
<?php
// ... $safe_basename alındıktan sonra ...

// Yöntem 1: Sadece bilinen güvenli karakterlere izin ver (Alfanümerik, nokta, alt çizgi, tire)
$clean_filename = preg_replace("/[^A-Za-z0-9\.\_\-]/", '_', $safe_basename);

// Yöntem 2: Daha kapsamlı temizlik (Boşlukları _ yap, çoklu _ leri tek _ yap vb.)
$clean_filename = str_replace(' ', '_', $safe_basename); // Boşlukları değiştir
$clean_filename = preg_replace("/[^A-Za-z0-9\.\_\-]/", '', $clean_filename); // İzin verilmeyenleri kaldır
$clean_filename = preg_replace('/_+/', '_', $clean_filename); // Çoklu alt çizgileri tek yap
$clean_filename = trim($clean_filename, '_'); // Başındaki/sonundaki alt çizgileri kaldır

echo "Temizlenmiş dosya adı: $clean_filename <br>";

// Uzantıyı koruduğumuzdan emin olalım (temizlik sonrası tekrar alabiliriz)
$final_extension = strtolower(pathinfo($clean_filename, PATHINFO_EXTENSION));
if (empty($final_extension) || !in_array($final_extension, $allowed_extensions)) {
     // Eğer temizlik uzantıyı bozduysa veya geçersizse, orijinal uzantıyı kullanmayı dene
     $original_extension = strtolower(pathinfo($safe_basename, PATHINFO_EXTENSION));
     if (!empty($original_extension) && in_array($original_extension, $allowed_extensions)) {
         $filename_base = pathinfo($clean_filename, PATHINFO_FILENAME);
         $clean_filename = $filename_base . '.' . $original_extension;
         $final_extension = $original_extension; // Güncelle
         echo "Temizlik sonrası uzantı kurtarıldı: $clean_filename <br>";
     } else {
        die("Hata: Dosya adı temizlendikten sonra geçerli bir uzantı kalmadı.");
     }
}

?>
```

#### 4.4.3. Benzersiz Dosya Adları Oluşturma

Aynı ada sahip dosyaların birbirinin üzerine yazmasını önlemek, dosya adlarındaki olası güvenlik risklerini (örn. `.htaccess` gibi özel adlar) tamamen ortadan kaldırmak ve tahmin edilebilirliği azaltmak için **en güvenli yaklaşım**, yüklenen her dosya için sunucu tarafında **benzersiz bir ad oluşturmaktır.**

```php
<?php
// ... $final_extension belirlendikten sonra ...

// Yöntem 1: uniqid() + microtime (Daha yüksek benzersizlik ihtimali)
// uniqid('prefix_', true) -> 'prefix_' + saniye + mikrosaniye (örn: upload_653a6abc123456.78901234)
$unique_id = uniqid('file_', true); 
$unique_filename = $unique_id . '.' . $final_extension;

// Yöntem 2: Zaman damgası + Rastgele Dizi
// $timestamp = time(); // Saniye cinsinden
// $random_str = bin2hex(random_bytes(8)); // Kriptografik olarak güvenli rastgele 16 karakter
// $unique_filename = $timestamp . '_' . $random_str . '.' . $final_extension;

// Yöntem 3: Dosya içeriğinin Hash'i + Rastgelelik (Çakışma olasılığı çok düşük)
// $file_hash = hash_file('sha256', $tmp_path);
// $random_salt = bin2hex(random_bytes(4));
// $unique_filename = $file_hash . '_' . $random_salt . '.' . $final_extension;

echo "Oluşturulan benzersiz dosya adı: $unique_filename <br>";

// ÖNEMLİ: Orijinal dosya adını, oluşturulan benzersiz adı ve diğer bilgileri 
// (MIME türü, boyut, yükleyen kullanıcı vb.) bir veritabanında saklamak genellikle en iyisidir.
// Böylece dosyayı daha sonra orijinal adıyla listeleyebilir veya arayabilirsiniz.

?>
```

---

## 5. Dosyayı Güvenle Taşıma: `move_uploaded_file()`

**Bu kritik bir adımdır.** Tüm doğrulamalar başarılı olduktan sonra, geçici dosyayı (`$_FILES['userfile']['tmp_name']`) belirlediğiniz kalıcı yükleme dizinine taşımak için **mutlaka** [`move_uploaded_file()`](https://www.php.net/manual/tr/function.move-uploaded-file.php) fonksiyonunu kullanmalısınız.

**Neden `copy()` veya `rename()` değil?**

`move_uploaded_file()`, taşımaya çalıştığı dosyanın gerçekten geçerli bir HTTP POST yüklemesi ile geldiğini kontrol eder. Bu, saldırganların sunucudaki zaten var olan başka dosyaları (örn. `/etc/passwd`) hedef olarak göstermesini veya betiği kandırarak yerel dosya sistemindeki dosyaları işlemesini engeller. `copy()` veya `rename()` bu kontrolü yapmaz.

```php
<?php
// ... tüm kontroller ve $unique_filename oluşturulduktan sonra ...

$upload_directory = '/var/www/my_secure_uploads/'; // Hedef dizin (Web kökü DIŞINDA olabilir!)
$destination_path = $upload_directory . $unique_filename;

// Hedef dizinin var olup olmadığını ve yazılabilir olup olmadığını kontrol et
if (!is_dir($upload_directory)) {
    // Dizini oluşturmaya çalış (recursive = true)
    if (!mkdir($upload_directory, 0750, true)) { // 0750: Sahip rwx, Grup rx, Diğerleri ---
        die("Hata: Yükleme dizini '$upload_directory' oluşturulamadı.");
    }
    echo "Yükleme dizini oluşturuldu: $upload_directory <br>";
}

if (!is_writable($upload_directory)) {
    die("Hata: Yükleme dizini '$upload_directory' yazılabilir değil. İzinleri kontrol edin.");
}

// Dosyayı geçici konumdan hedefe taşı
if (move_uploaded_file($tmp_path, $destination_path)) {
    echo "Dosya başarıyla yüklendi ve kaydedildi: $destination_path <br>";
    
    // Başarı sonrası işlemler (örn. veritabanına kayıt)
    // ...

    // İzinleri ayarla (isteğe bağlı, daha kısıtlı olabilir)
    chmod($destination_path, 0640); // Sahip rw, Grup r, Diğerleri ---

} else {
    // Olası nedenler: İzin sorunları, disk dolu, tmp dosyasının taşınmadan silinmesi vb.
    // Daha fazla hata ayıklama gerekebilir. PHP hata loglarını kontrol edin.
    die("Hata: Dosya kalıcı konuma taşınamadı. Sunucu loglarını kontrol edin.");
}
?>
```

---

## 6. Güvenli Depolama Stratejileri

### 6.1. Web Kök Dizininden Uzak Durmak

**En önemli depolama kuralı:** Mümkünse, yüklenen dosyaları web sunucusunun doğrudan erişilebilir kök dizini (`/var/www/html`, `public_html`, `htdocs` vb.) içine **kaydetmeyin**.

*   **Neden?** Eğer bir şekilde zararlı bir betik (örn. `shell.php`) tüm kontrollere rağmen yüklenirse ve web kökü içindeyse, saldırgan basitçe `http://siteniz.com/uploads/shell.php` adresine giderek bu betiği çalıştırabilir.
*   **Çözüm:** Dosyaları web kök dizininin *dışında* bir klasörde saklayın (örn. `/var/www/secure_uploads/`, `/srv/user_data/files/`). Bu dizinlere web sunucusu tarafından doğrudan URL ile erişilemez.

### 6.2. Dizin İzinlerinin Önemi (Permissions)

*   **Yükleme Dizini:** PHP betiğini çalıştıran web sunucusu kullanıcısının (örn. `www-data`) yükleme dizinine **yazma** izni olmalıdır (`move_uploaded_file` için). Ancak, genellikle **çalıştırma** iznine ihtiyacı yoktur. `0750` (sahip: rwx, grup: rx, diğerleri: ---) veya `0770` (sahip: rwx, grup: rwx, diğerleri: ---) gibi izinler genellikle uygundur. Web sunucusu kullanıcısını ayrı bir gruba ekleyip sadece o gruba yazma izni vermek daha güvenli olabilir. **Asla `0777` kullanmayın!**
*   **Yüklenen Dosyalar:** Dosyalar taşındıktan sonra, genellikle çalıştırma iznine ihtiyaç duymazlar. `chmod($destination_path, 0640)` (sahip: rw, grup: r, diğerleri: ---) veya `0660` gibi daha kısıtlı izinler ayarlamak iyi bir pratiktir.

### 6.3. Veritabanı ile Entegrasyon

Yüklenen her dosyanın meta verilerini (bilgilerini) bir veritabanı tablosunda saklamak şiddetle tavsiye edilir. Bu tablo şunları içerebilir:

*   `id` (Benzersiz kimlik)
*   `user_id` (Yükleyen kullanıcı)
*   `original_filename` (Kullanıcının gönderdiği orijinal ad)
*   `unique_filename` (Sunucuda saklanan benzersiz ad)
*   `filepath` (Sunucudaki tam yol veya yükleme dizinine göreli yol)
*   `mime_type` (Doğrulanmış MIME türü)
*   `filesize` (Bayt cinsinden boyut)
*   `upload_timestamp` (Yükleme zamanı)
*   `status` (Durum: aktif, silinmiş vb.)

Bu, dosyaları yönetmeyi, listelemeyi, aramayı ve erişim kontrolü uygulamayı çok daha kolay hale getirir.

### 6.4. Dosyaları Güvenli Şekilde Sunma (Serving Files)

Dosyaları web kökü dışında saklıyorsanız, kullanıcıların bunlara nasıl erişeceğini sağlamanız gerekir. Doğrudan dosya sistemine bağlantı veremezsiniz. Bunun yerine, bir "aracı" PHP betiği kullanın:

```php
<?php
// download.php veya serve_file.php

session_start(); // Oturum kontrolü için

// 1. Gerekli parametreleri al (örn. dosya ID'si veya benzersiz adı)
$file_identifier = $_GET['id'] ?? null; 
if (!$file_identifier) {
    http_response_code(400); // Bad Request
    die("Dosya belirtilmedi.");
}

// 2. Kullanıcının kimliğini ve yetkisini doğrula
if (!isset($_SESSION['user_id'])) {
    http_response_code(401); // Unauthorized
    die("Bu dosyayı görüntülemek için giriş yapmalısınız.");
}
$user_id = $_SESSION['user_id'];

// 3. Veritabanından dosya bilgilerini çek
// $db = new PDO(...); 
// $stmt = $db->prepare("SELECT filepath, unique_filename, mime_type FROM user_files WHERE id = :id OR unique_filename = :id");
// $stmt->execute([':id' => $file_identifier]);
// $file_info = $stmt->fetch(PDO::FETCH_ASSOC);

// Simülasyon (Gerçek uygulamada DB kullanılmalı)
$file_info = null; 
$storage_path = '/var/www/my_secure_uploads/'; // Yükleme dizini
if ($file_identifier === 'file_653a7b...') { // Örnek ID
    $file_info = [
        'filepath' => $storage_path . 'file_653a7b....jpg', 
        'unique_filename' => 'file_653a7b....jpg',
        'mime_type' => 'image/jpeg'
    ];
}
// ... diğer dosya kontrolleri ...


if (!$file_info) {
    http_response_code(404); // Not Found
    die("Dosya bulunamadı.");
}

// 4. Kullanıcının bu dosyaya erişim yetkisi olup olmadığını kontrol et (veritabanı sorgusuna eklenebilir)
// Örnek: if ($file_info['owner_id'] !== $user_id && !user_is_admin($user_id)) { ... }


$file_path = $file_info['filepath'];

// 5. Dosyanın gerçekten var olup olmadığını kontrol et (ekstra güvenlik)
if (!file_exists($file_path) || !is_readable($file_path)) {
     error_log("Dosya DB'de var ama sistemde yok/okunamaz: " . $file_path);
     http_response_code(500); // Internal Server Error
     die("Dosyaya erişirken bir sorun oluştu.");
}

// 6. Uygun HTTP başlıklarını gönder
header('Content-Type: ' . $file_info['mime_type']);
header('Content-Length: ' . filesize($file_path));
// Tarayıcıda göstermek için 'inline', indirme penceresi için 'attachment'
header('Content-Disposition: inline; filename="' . $file_info['unique_filename'] . '"'); 
// Önbellekleme başlıkları (isteğe bağlı)
header('Cache-Control: private, max-age=0, must-revalidate');
header('Pragma: public'); // IE uyumluluğu için

// 7. Dosya içeriğini çıktı tamponuna gönder ve temizle
ob_clean(); // Önceki çıktıları temizle
flush();    // Tamponu zorla gönder
readfile($file_path); // Dosyayı oku ve çıktıya gönder

exit; // Betiği sonlandır
?>
```

Bu yaklaşım, dosyalara erişimi tamamen kontrol etmenizi sağlar (kimlik doğrulama, yetkilendirme).

---

## 7. İleri Düzey Güvenlik Önlemleri ve Konfigürasyonlar

### 7.1. Web Sunucusu Yapılandırması (`.htaccess`, Nginx)

Eğer dosyaları web kökü içinde bir alt dizinde saklamak *zorundaysanız* (örn. `/uploads`), web sunucusu seviyesinde betik çalıştırmayı engellemek **şarttır**.

*   **Apache (`.htaccess`):** Yükleme dizininize (`/uploads/.htaccess`) aşağıdaki gibi bir dosya ekleyin:

    ```apache
    # /path/to/your/webroot/uploads/.htaccess

    # Tüm bilinen betik uzantılarının çalıştırılmasını engelle
    <FilesMatch "\.(php|phtml|php3|php4|php5|php7|phps|cgi|pl|py|jsp|asp|aspx|sh|exe|dll|htaccess)$">
        Order Allow,Deny
        Deny from all
    </FilesMatch>

    # VEYA daha agresif: Sadece belirli (güvenli) dosya türlerine doğrudan erişime izin ver
    # Order Deny,Allow
    # Deny from all
    # <FilesMatch "\.(?i:jpe?g|gif|png|webp|css|js|pdf|txt)$">
    #    Allow from all
    # </FilesMatch>

    # VEYA en basit: Bu dizinde PHP motorunu tamamen kapat
    # php_flag engine off 

    # Dizin listelemeyi engelle (genellikle zaten kapalıdır ama emin olun)
    Options -Indexes 
    ```

*   **Nginx:** Nginx `.htaccess` kullanmaz. Benzer kuralları sunucu bloğunuzdaki `location` direktifleri ile tanımlamanız gerekir:

    ```nginx
    server {
        # ... diğer ayarlar ...
        root /var/www/html;

        # /uploads dizini için özel lokasyon bloğu
        location /uploads/ {
            # Bu dizinde PHP betiklerinin FPM'e gönderilmesini engelle
            location ~ \.php$ {
                deny all; 
                # VEYA return 403;
                # VEYA return 404; (Dosyanın varlığını gizlemek için)
            }
            
            # Diğer tehlikeli uzantıları da engelleyebilirsiniz
            location ~* \.(htaccess|htpasswd|ini|log|sh|exe|pl|cgi)$ {
                 deny all;
            }

            # Dizin listelemeyi engelle
            autoindex off; 
            
            # Statik dosyaların sunulmasına izin ver (PHP dışındakiler)
            try_files $uri $uri/ =404; 
        }

        # Ana PHP işleyici (diğer dizinler için)
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/run/php/php8.1-fpm.sock; # Sürümünüze göre ayarlayın
        }
    }
    ```

### 7.2. Dosya İçeriği Analizi ve Sanitasyonu (Image Re-creation vb.)

*   **`getimagesize()`:** Resim dosyaları için, `getimagesize()` fonksiyonu dosyanın geçerli bir resim olup olmadığını (ve boyutlarını) kontrol eder. Geçersiz veya bozuk resimler `false` döndürür. Bu, temel bir içerik sağlığı kontrolüdür.
*   **Image Re-creation (Resmi Yeniden Oluşturma):** Daha güçlü bir yöntem, yüklenen resmi GD veya Imagick gibi kütüphaneler kullanarak sunucu tarafında yeniden işlemektir. Orijinal dosya okunur, yeni bir resim tuvali oluşturulur ve pikseller bu yeni tuvale kopyalanır, ardından yeni resim kaydedilir. Bu işlem:
    *   Resim dosyalarına gizlenmiş olabilecek zararlı kodları (genellikle) temizler.
    *   Geçersiz veya standart dışı resim yapılarını düzeltir.
    *   Potansiyel olarak zararlı meta verileri (EXIF içinde gizlenmiş kod vb.) kaldırır.
    *   Standart bir formata (örn. tüm yüklenenleri PNG veya JPG olarak kaydetmek) dönüştürme imkanı sunar.

    ```php
    <?php // GD örneği (Imagick daha güçlüdür ama daha az yaygındır)
    if (strpos($detected_mime_type, 'image/') === 0 && function_exists('imagecreatefromstring')) {
        $source_image_data = file_get_contents($tmp_path);
        $source_image = @imagecreatefromstring($source_image_data); // @ hata basmayı engeller

        if ($source_image !== false) {
            // Yeni bir hedef dosya adı belirle (örn. uzantıyı .png yap)
            $new_unique_filename = uniqid('img_', true) . '.png';
            $new_destination_path = $upload_directory . $new_unique_filename;

            // Resmi PNG olarak kaydet (veya başka formatta)
            if (imagepng($source_image, $new_destination_path, 9)) { // 9 = maksimum sıkıştırma
                echo "Resim başarıyla yeniden oluşturuldu ve kaydedildi: $new_unique_filename <br>";
                imagedestroy($source_image); // Belleği boşalt
                
                // Eski geçici dosyayı sil (artık gerek yok)
                unlink($tmp_path); 

                // Sonraki adımlarda $unique_filename ve $destination_path'i güncelle
                $unique_filename = $new_unique_filename;
                $destination_path = $new_destination_path; // move_uploaded_file artık gereksiz!
                $move_required = false; // İşaretçi
            } else {
                 imagedestroy($source_image);
                 die("Hata: Yeniden oluşturulan resim kaydedilemedi.");
            }
        } else {
            die("Hata: Geçerli bir resim dosyası değil (GD okuyamadı).");
        }
    } 
    // ... (move_uploaded_file sadece $move_required true ise çalışır) ...
    ?>
    ```

### 7.3. Antivirüs / Malware Taraması

Yüksek güvenlik gerektiren sistemlerde (örn. kamu kurumları, bankalar), yüklenen dosyaları sunucuya kaydetmeden önce ClamAV gibi açık kaynaklı veya ticari bir antivirüs motoru ile taratmak iyi bir fikirdir. Bu, sunucuya bilinen virüslerin, trojanların veya diğer zararlı yazılımların bulaşmasını engelleyebilir. PHP'den `exec()` veya özel kütüphaneler aracılığıyla tarama motoru çağrılabilir.

### 7.4. Hız Sınırlama (Rate Limiting)

Saldırganların kısa sürede çok sayıda dosya yükleyerek sunucuyu yormasını (DoS) veya depolama alanını doldurmasını engellemek için hız sınırlaması uygulayın. Bu genellikle web sunucusu (Nginx'in `limit_req_zone` direktifi gibi), güvenlik duvarı veya uygulama seviyesinde (örn. belirli bir IP adresinin veya kullanıcının dakikada/saatte yükleyebileceği dosya sayısını/toplam boyutunu sınırlamak) yapılabilir.

### 7.5. İçerik Dağıtım Ağları (CDN)

Yüklenen (ve güvenli olduğu doğrulanan) statik dosyaları (resimler, CSS, JS, videolar) bir CDN üzerinden sunmak, kendi sunucunuzun yükünü azaltır, dosyaların dünya genelindeki kullanıcılara daha hızlı ulaşmasını sağlar ve bazı CDN'ler ek güvenlik özellikleri (DDoS koruması gibi) sunabilir.

### 7.6. Kayıt Tutma (Logging) ve İzleme

*   Başarılı ve başarısız tüm dosya yükleme girişimlerini ayrıntılı olarak kaydedin:
    *   Zaman damgası
    *   Yükleyen kullanıcının IP adresi ve kimliği (varsa)
    *   Orijinal dosya adı
    *   Kaydedilen dosya adı ve yolu
    *   Dosya boyutu, algılanan MIME türü
    *   Başarı/hata durumu ve hata mesajı
*   Bu logları düzenli olarak izleyin ve şüpheli aktiviteleri (çok sayıda hata, belirli IP'lerden sürekli denemeler vb.) tespit etmek için uyarılar ayarlayın.

---

## 8. Örnek Kapsamlı PHP Kodu

Aşağıda, tartışılan birçok güvenlik önlemini birleştiren daha kapsamlı bir PHP yükleme betiği örneği bulunmaktadır:

```php
<?php
declare(strict_types=1); // Katı tür denetimini etkinleştir
session_start(); // Oturum veya kullanıcı kontrolü için

// --- Yapılandırma ---
define('UPLOAD_DIR', '/var/www/my_secure_uploads/'); // WEB KÖKÜ DIŞINDA!
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5 MB
define('ALLOWED_MIME_TYPES', [
    'image/jpeg', 'image/png', 'image/gif', 'application/pdf'
]);
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'pdf']);
// MIME türlerini uzantılarla eşleştir (Tutarlılık kontrolü için)
define('MIME_EXT_MAP', [
    'image/jpeg' => ['jpg', 'jpeg'],
    'image/png'  => ['png'],
    'image/gif'  => ['gif'],
    'application/pdf' => ['pdf']
]);
define('ENABLE_IMAGE_RECREATION', true); // Resimleri yeniden oluşturmayı etkinleştir/devre dışı bırak

// --- Hata Yönetimi Fonksiyonu ---
function handle_upload_error(string $message, int $http_code = 400): void {
    error_log("Dosya Yükleme Hatası: " . $message); // Sunucu loguna yaz
    http_response_code($http_code);
    // Kullanıcıya genel bir hata mesajı gösterilebilir
    die(json_encode(['success' => false, 'message' => 'Dosya yüklenirken bir hata oluştu. Lütfen tekrar deneyin veya yönetici ile iletişime geçin. Detay: ' . $message])); 
}

// --- Ana İşlem ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    handle_upload_error("Geçersiz istek metodu.", 405);
}

if (!isset($_FILES['userfile'])) {
    handle_upload_error("Dosya bilgisi bulunamadı.", 400);
}

$file = $_FILES['userfile'];

// 1. Temel Hata Kontrolü
if ($file['error'] !== UPLOAD_ERR_OK) {
    $upload_errors = [ /* ... önceki örnekteki gibi ... */ ];
    $error_message = $upload_errors[$file['error']] ?? "Bilinmeyen yükleme hatası (Kod: {$file['error']}).";
    handle_upload_error($error_message);
}

// 2. Boyut Kontrolü
if ($file['size'] === 0) {
    handle_upload_error("Yüklenen dosya boş.");
}
if ($file['size'] > MAX_FILE_SIZE) {
    handle_upload_error("Dosya boyutu izin verilen limiti (" . (MAX_FILE_SIZE / 1024 / 1024) . " MB) aşıyor.");
}

// 3. MIME Türü Doğrulaması (finfo)
$tmp_path = $file['tmp_name'];
if (!is_uploaded_file($tmp_path)) { // Ekstra güvenlik: Dosyanın gerçekten upload olup olmadığını kontrol et
    handle_upload_error("Geçersiz yükleme işlemi.", 403);
}

$finfo = finfo_open(FILEINFO_MIME_TYPE);
if ($finfo === false) { handle_upload_error("Sunucu yapılandırma hatası (finfo).", 500); }
$detected_mime_type = finfo_file($finfo, $tmp_path);
finfo_close($finfo);

if ($detected_mime_type === false) { handle_upload_error("Dosya türü algılanamadı."); }
if (!in_array($detected_mime_type, ALLOWED_MIME_TYPES)) {
    handle_upload_error("Geçersiz dosya türü algılandı ($detected_mime_type).");
}

// 4. Uzantı Kontrolü ve Tutarlılık
$original_filename = $file['name'];
$safe_basename = basename($original_filename); // Dizin değiştirme koruması
$extension = strtolower(pathinfo($safe_basename, PATHINFO_EXTENSION));

if (empty($extension)) { handle_upload_error("Dosya uzantısı bulunamadı."); }
if (!in_array($extension, ALLOWED_EXTENSIONS)) {
    handle_upload_error("Geçersiz dosya uzantısı (.$extension).");
}
if (!isset(MIME_EXT_MAP[$detected_mime_type]) || !in_array($extension, MIME_EXT_MAP[$detected_mime_type])) {
    handle_upload_error("Algılanan dosya türü ($detected_mime_type) ile uzantı (.$extension) eşleşmiyor.");
}

// 5. Benzersiz Dosya Adı Oluşturma
$unique_filename = uniqid('upload_', true) . '.' . $extension;

// 6. Hedef Dizin Kontrolü
if (!is_dir(UPLOAD_DIR)) {
    if (!mkdir(UPLOAD_DIR, 0750, true)) {
        handle_upload_error("Yükleme dizini oluşturulamadı.", 500);
    }
}
if (!is_writable(UPLOAD_DIR)) {
    handle_upload_error("Yükleme dizinine yazılamıyor.", 500);
}

$destination_path = UPLOAD_DIR . $unique_filename;

// 7. (İsteğe Bağlı) Resim Yeniden Oluşturma
$moved_successfully = false;
if (ENABLE_IMAGE_RECREATION && strpos($detected_mime_type, 'image/') === 0 && function_exists('imagecreatefromstring')) {
    $source_image_data = file_get_contents($tmp_path);
    $source_image = @imagecreatefromstring($source_image_data);

    if ($source_image !== false) {
        $output_format = 'png'; // Veya jpeg, webp vb.
        $new_extension = $output_format;
        $unique_filename = uniqid('img_', true) . '.' . $new_extension; // Yeni benzersiz ad
        $destination_path = UPLOAD_DIR . $unique_filename; // Hedefi güncelle

        $save_function = 'image' . $output_format; // imagepng, imagejpeg
        if (function_exists($save_function)) {
            if ($save_function === 'imagejpeg') {
                 $saved = $save_function($source_image, $destination_path, 85); // Kalite 85
            } else {
                 $saved = $save_function($source_image, $destination_path); // PNG için kalite yok (veya sıkıştırma seviyesi)
            }
            
            if ($saved) {
                imagedestroy($source_image);
                unlink($tmp_path); // Geçici dosyayı sil
                $moved_successfully = true; // Taşıma başarılı sayılır
                 chmod($destination_path, 0640); // İzinleri ayarla
                echo "Resim yeniden oluşturuldu ve kaydedildi: $unique_filename <br>";
            } else {
                imagedestroy($source_image);
                handle_upload_error("Yeniden oluşturulan resim kaydedilemedi.");
            }
        } else {
             imagedestroy($source_image);
             handle_upload_error("Hedef resim formatı ($output_format) desteklenmiyor.");
        }
    } else {
         // Resim değilse veya bozuksa, normal taşımaya devam et (opsiyonel, reddedilebilir de)
         echo "Uyarı: Dosya resim olarak yeniden oluşturulamadı, normal olarak taşınacak.<br>";
    }
}

// 8. Dosyayı Taşı (Eğer yeniden oluşturulmadıysa)
if (!$moved_successfully) {
    if (move_uploaded_file($tmp_path, $destination_path)) {
        $moved_successfully = true;
         chmod($destination_path, 0640); // İzinleri ayarla
    } else {
        handle_upload_error("Dosya kalıcı konuma taşınamadı.", 500);
    }
}

// --- Başarı Durumu ---
if ($moved_successfully) {
    echo "Dosya başarıyla yüklendi!<br>";
    echo "Kaydedilen Ad: " . htmlspecialchars($unique_filename, ENT_QUOTES, 'UTF-8') . "<br>";
    
    // Veritabanına kayıt işlemleri burada yapılabilir
    // record_upload_to_db($user_id, $original_filename, $unique_filename, $destination_path, $detected_mime_type, $file['size']);

    // Güvenli sunma betiğine bağlantı (örnek)
    $serve_url = 'serve_file.php?id=' . urlencode($unique_filename); // Veya DB ID'si
    echo 'Dosyayı görüntüle: <a href="' . $serve_url . '" target="_blank">Buraya Tıklayın</a>';

    // Başarılı JSON yanıtı (API ise)
    // echo json_encode(['success' => true, 'filename' => $unique_filename, 'url' => $serve_url]);
}

?>

```

---

## 9. Yaygın Hatalar ve Kontrol Listesi

*   **❌ Hata:** Sadece istemci tarafı doğrulamaya güvenmek.
    *   **✔ Doğru:** Tüm güvenlik kontrollerini **sunucu tarafında** yapmak.
*   **❌ Hata:** `$_FILES['...']['type']` değerine güvenmek.
    *   **✔ Doğru:** `finfo` ile dosya içeriğini analiz ederek MIME türünü belirlemek.
*   **❌ Hata:** Sadece dosya uzantısını kontrol etmek veya eksik kontrol etmek (büyük/küçük harf, çift uzantı).
    *   **✔ Doğru:** Uzantıyı `strtolower()` ve `pathinfo()` ile güvenli almak, beyaz liste kullanmak, MIME türü ile tutarlılığı kontrol etmek.
*   **❌ Hata:** Tehlikeli dosyaları engellemek için kara liste kullanmak.
    *   **✔ Doğru:** Sadece izin verilen dosya türleri/uzantıları için **beyaz liste** kullanmak.
*   **❌ Hata:** Kullanıcının gönderdiği orijinal dosya adını doğrudan kullanmak.
    *   **✔ Doğru:** `basename()` kullanmak, özel karakterleri temizlemek ve **benzersiz bir dosya adı oluşturmak**.
*   **❌ Hata:** Dosyaları taşımak için `copy()` veya `rename()` kullanmak.
    *   **✔ Doğru:** **Mutlaka** `move_uploaded_file()` kullanmak.
*   **❌ Hata:** Yüklenen dosyaları doğrudan web kök dizinine kaydetmek.
    *   **✔ Doğru:** Dosyaları web kök dizini **dışında** güvenli bir konumda saklamak.
*   **❌ Hata:** Yükleme dizinine veya dosyalara aşırı gevşek izinler (`0777`) vermek.
    *   **✔ Doğru:** En az ayrıcalık prensibini uygulamak (`0750`, `0640` gibi).
*   **❌ Hata:** Web kökünde dosya saklarken betik çalıştırmayı engellememek.
    *   **✔ Doğru:** `.htaccess` veya Nginx yapılandırması ile yükleme dizininde betik çalıştırmayı **kesinlikle** engellemek.
*   **❌ Hata:** Dosya bağlantılarını veya adlarını HTML'e basarken XSS koruması yapmamak.
    *   **✔ Doğru:** `htmlspecialchars()` veya uygun şablon motoru kaçış mekanizmalarını kullanmak.
*   **❌ Hata:** Yükleme hatalarını detaylı olarak loglamamak veya izlememek.
    *   **✔ Doğru:** Tüm girişimleri loglamak ve şüpheli aktiviteleri izlemek.

---

## 10. Sonuç

Güvenli dosya yükleme, dikkatli planlama ve katmanlı bir güvenlik yaklaşımı gerektirir. Tek bir kontrol yeterli değildir. Kullanıcı girdisine asla güvenmemek, hem dosya türünü hem uzantısını doğrulamak, dosya adını sanitize etmek, dosyaları güvenli bir yerde saklamak ve sunucu yapılandırmasını doğru yapmak kritik öneme sahiptir. Bu rehberdeki adımları uygulayarak, dosya yükleme işlevselliğinizin hem işlevsel hem de güvende olmasını sağlayabilirsiniz. Güvenlik sürekli bir süreçtir; kütüphanelerinizi ve sunucu yazılımlarınızı güncel tutmayı ve yeni tehditlere karşı bilgi sahibi olmayı unutmayın.
