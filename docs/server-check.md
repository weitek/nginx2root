# Проверка nginx на сервере: пошаговая инструкция

Для случаев, когда снаружи проверить нельзя (CDN, anti-DDoS, закрытая сеть) или
нужно подтвердить вердикт `ПРОВЕРИТЬ НА СЕРВЕРЕ`. Инструкция — **для nginx**
(пакет или своя сборка), не для OpenResty. Все команды выполняются **под root**.

До раздела «Действия» ничего не меняется: только чтение и один дамп конфига.

---

## 0. Подготовка

```bash
sudo -i
whoami
```

Ожидаем `root`. Если `sudo` нет — войдите root напрямую.

---

## 1. Версия nginx

```bash
nginx -v
nginx -V 2>&1
```

Первая команда печатает строку вида `nginx version: nginx/1.24.0`.
Вторая — версию плюс флаги сборки.

Полная версия пакета (для дистрибутивных сборок):

```bash
dpkg -l | grep -E '^ii\s+nginx' 2>/dev/null
rpm -q nginx 2>/dev/null
```

Проверьте, что запущен именно этот бинарник:

```bash
ps -eo pid,args | grep '[n]ginx'
ls -l /proc/$(cat /run/nginx.pid)/exe
```

Если путь в `/proc/.../exe` отличается от `command -v nginx` — `nginx -v`
показывает не тот бинарник, который работает.

### Как читать версию

| Версия | Оценка |
|---|---|
| 1.9.5 – 1.31.8 | код уязвим к CVE-2026-123007 (если включён HTTP/2) |
| 1.30.0 – 1.30.6 | уязвима ветка 1.30 |
| 1.31.9+ или 1.30.7+ | исправлено |
| 1.9.4 и младше | не затронута HTTP/2-уязвимостями |
| `nginx-reuseport/1.30.7`, `nginx-naxsi/1.24.0` | вендорский токен: ядро — цифры после `/` (здесь 1.30.7 и 1.24.0) |
| `1.18.0-6ubuntu14.22` и подобные | дистрибутивная сборка: `nginx -v` не показывает бэкпорт, сверяйте полную версию пакета с advisory (Ubuntu — [USN-8955-1](https://ubuntu.com/security/notices/USN-8955-1)) |

---

## 2. Модули

```bash
nginx -V 2>&1 | tr ' ' '\n' | grep -E -- '--with-http_v2_module|--with-http_v3_module|--with-mail'
```

- `--with-http_v2_module` — в бинарнике есть код HTTP/2 (уязвим, если не пропатчен);
- `--with-http_v3_module` — есть HTTP/3;
- `--with-mail` — есть mail proxy (для CVE-2026-113425).

Если `http_v2_module` отсутствует — CVE-2026-123007 и -123633 неприменимы.

---

## 3. Конфигурация

Сначала проверка синтаксиса и дамп:

```bash
nginx -t
nginx -T > /root/nginx-config-$(date +%F).txt 2>&1
```

> `nginx -T` читает конфиг **с диска**. Если конфиг правили без reload,
> работающая конфигурация может отличаться. Сравните время изменения файлов
> с временем старта master-процесса (`ps -o lstart= -p $(cat /run/nginx.pid)`).

Дальше ищите по дампу (`FILE` — имя созданного файла).

### 3.1. HTTP/2 (CVE-2026-123007, CVE-2026-123633)

```bash
grep -nE 'listen[^;]*http2|^[[:space:]]*http2[[:space:]]+on' /root/nginx-config-*.txt
```

- `listen 443 ssl http2;` — старый синтаксис (nginx ≤ 1.25.0);
- `http2 on;` — новый (1.25.1+);
- пусто — HTTP/2 не включён.

Проверьте **все** `server`-блоки на том же адресе и порту: протокол
согласуется на listening socket, а не на отдельном `location`.

### 3.2. HTTP/3 (CVE-2026-121810)

```bash
grep -nE 'listen[^;]*quic|^[[:space:]]*http3[[:space:]]+on|Alt-Svc' /root/nginx-config-*.txt
ss -lunp 'sport = :443'
```

Если `ss` показывает `nginx` на UDP/443 — QUIC-листener активен.

### 3.3. Resolver + переменный proxy_pass + mirror (CVE-2026-123634)

```bash
grep -nE '^[[:space:]]*resolver[[:space:]]' /root/nginx-config-*.txt
grep -nE 'proxy_pass[[:space:]]+https?://[^;]*\$' /root/nginx-config-*.txt
grep -nE '^[[:space:]]*mirror[[:space:]]' /root/nginx-config-*.txt
```

Нужны все три условия: `resolver`, `proxy_pass` с переменной (DNS-резолв во
время запроса) и `mirror`. `mirror` появился в 1.13.4; на более старых
версиях путь через `mirror` невозможен, но advisory допускает другие
subrequest-механизмы (например SSI).

### 3.4. Mail proxy (CVE-2026-113425)

```bash
grep -nE '^[[:space:]]*mail[[:space:]]*\{|^[[:space:]]*proxy[[:space:]]+on|^[[:space:]]*auth_http[[:space:]]' /root/nginx-config-*.txt
```

Нужны `mail`, `proxy on` и `auth_http` одновременно. Для обычного
веб-сервера этот CVE неприменим.

---

## 4. Фактический протокол на самом сервере

Сначала узнайте, где слушает nginx:

```bash
ss -ltnp | grep nginx
```

Дальше проверьте ALPN на нужном адресе и порту (подставьте свой SNI и порт;
для примера — `127.0.0.1:443`):

```bash
openssl s_client -connect 127.0.0.1:443 -servername example.com -alpn h2,http/1.1 </dev/null 2>&1 \
  | grep -E 'ALPN protocol|No ALPN negotiated'
```

- `ALPN protocol: h2` — HTTP/2 реально работает;
- `No ALPN negotiated` — HTTP/2 выключен.

Если nginx за локальным прокси слушает `127.0.0.1:8080`, проверяйте этот порт
(там может быть обычный HTTP без TLS).

Проверка запросом (если `curl` собран с HTTP/2 — видно в `curl -V`):

```bash
curl -V | head -1
curl -skI --http2 --resolve example.com:443:127.0.0.1 https://example.com/
```

Ошибка `HTTP/2 not supported` означает, что сервер не согласовал h2.

---

## 5. Проверка, не эксплуатировали ли уязвимость

```bash
ss -tinp state established '( sport = :443 )'
```

Запустите дважды с интервалом и сравните `bytes_received`/`bytes_sent`.
Подозрительно: один долгий коннект с быстро растущим входящим трафиком и
много коротких TLS-соединений с того же IP.

```bash
grep -Ei 'worker process.*exited|signal 11|segfault' /var/log/nginx/error.log
coredumpctl list 2>/dev/null | grep nginx
```

Аномальные завершения воркеров — слабый, но полезный признак.

```bash
ps -eo uid,user,pid,ppid,args | grep '[n]ginx: worker'
```

Запомните UID воркера и включите аудит запуска процессов (если есть `auditd`):

```bash
auditctl -a always,exit -F arch=b64 -S execve,execveat -F euid=<UID> -k nginx_worker_exec
ausearch -k nginx_worker_exec -ts recent -i
```

Любой `/bin/sh`, `/bin/bash` или другой процесс, запущенный воркером nginx, —
признак компрометации. Правило видит только события после установки.

---

## 6. Действия

### 6.1. Обновление (основное)

```bash
apt update && apt install --only-upgrade nginx     # Debian/Ubuntu
# или
dnf upgrade nginx                                   # RHEL-семейство
nginx -v
systemctl restart nginx
```

Нужна сборка с ядром **1.31.9+** или **1.30.7+** (либо дистрибутив с
бэкпортом). `reload` не заменяет исполняемый файл — только `restart`.

### 6.2. Временная мера: выключить HTTP/2

nginx 1.25.1 и новее — в каждом затронутом `server`:

```nginx
listen 443 ssl;
http2 off;
```

nginx 1.9.5–1.25.0 — убрать параметр:

```nginx
listen 443 ssl;
```

Затем:

```bash
nginx -t
systemctl reload nginx
ps -eo pid,args | grep 'worker process is shutting down'
```

Если старые воркеры остались — `systemctl restart nginx` (они держат уже
открытые h2-соединения). После этого повторите проверку ALPN из раздела 4.

### 6.3. HTTP/3

В затронутых `server`:

```nginx
listen 443 ssl;
# listen 443 quic reuseport;
http3 off;
add_header Alt-Svc 'clear' always;
```

```bash
nginx -t && systemctl reload nginx
ss -lunp 'sport = :443'
```

В выводе не должно остаться `nginx`.

### 6.4. Resolver + mirror

Уберите `mirror` или замените `proxy_pass` с переменной на фиксированный
`upstream`:

```nginx
upstream backend_fixed {
    server 10.0.0.10:8080;
}
location / {
    mirror off;
    proxy_pass http://backend_fixed;
}
```

`mirror_request_body on;` останавливает протестированный эксплойт, но **не
исправляет** ошибку — не полагайтесь на него.

### 6.5. Mail proxy

Если внешний доступ не нужен — слушать только loopback:

```nginx
listen 127.0.0.1:143;
```

Иначе — ограничить порты 25/110/143/465/587/993/995 на firewall.

---

## 7. Чек-лист

- [ ] `nginx -v` и полная версия пакета записаны;
- [ ] проверено, что запущен именно этот бинарник;
- [ ] `-V` проверен на `--with-http_v2_module`;
- [ ] `nginx -T` сохранён, h2/h3/resolver/mirror/mail проверены по дампу;
- [ ] ALPN на loopback: `h2` или `http/1.1`;
- [ ] `ss -lunp 'sport = :443'` — есть ли QUIC;
- [ ] просмотрены error.log и `ss` на предмет аномалий;
- [ ] при необходимости выполнено обновление и `restart`;
- [ ] после изменений повторно проверен ALPN и `nginx -v`.

Сохраните: вывод `nginx -v`, `nginx -V`, строки из `-T` по найденным
директивам (без сертификатов и паролей), `ss -ltnp`, результат ALPN и
`nginx-config-*.txt` в защищённом месте.

---

Если `Server` снаружи отвечает `openresty`, команды те же, но бинарник и
сервис называются `openresty`, а версия ядра — первые три числа в
`openresty/1.25.3.2` (это `1.25.3`).
