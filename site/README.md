# HTML-версия документации

Одностраничный статический сайт из `README.md` и `docs/server-check.md`.

## Состав

| Файл | Назначение |
|---|---|
| `build.py` | собирает `public/index.html` из `../README.md` и `../docs/server-check.md` |
| `public/index.html` | готовый статический сайт (единственный артефакт) |
| `public/robots.txt` | разрешает индексацию |
| `nginx.conf` | конфиг nginx-контейнера: gzip, кэш, заголовки безопасности |
| `compose.yaml` | контейнер `nginx:1.31-alpine` + метки обратного прокси |

## Сборка

```bash
python3 site/build.py
```

Конвертер Markdown использует только стандартную библиотеку и поддерживает
ровно те конструкции, которые есть в документации: заголовки, таблицы,
fenced-код, списки (включая чек-лист), цитаты и inline-разметку.

## Публикация

Сайт рассчитан на любой обратный прокси, который читает метки контейнеров
(Traefik и аналоги). Домен задаётся переменной окружения:

```bash
export DOCS_DOMAIN=docs.example.com
docker compose -f site/compose.yaml up -d --wait
```

Если `DOCS_DOMAIN` не задан, используется заглушка `docs.example.com`.
Сертификат TLS выпускает обратный прокси; порты 80/443 должны указывать
на него.

После изменения документации достаточно пересобрать HTML — контейнер отдаёт
файл с bind-монтированием, перезапуск не нужен:

```bash
python3 site/build.py
curl -sSI "https://${DOCS_DOMAIN:-docs.example.com}/"
```

## Проверка

```bash
curl -sSI "https://${DOCS_DOMAIN:-docs.example.com}/"   # 200, text/html
curl -sS  "https://${DOCS_DOMAIN:-docs.example.com}/" | head
curl -sSI "http://${DOCS_DOMAIN:-docs.example.com}/"    # редирект на https
```
