# Fumox

*English version: [README.md](./README.md)*

Fumox забирает списки прокси из многих источников, фильтрует и очищает их на лету и отдаёт клиентам чистые, структурированные подписки.

---

## Быстрый старт

Проект в активной разработке.

**Самый быстрый старт: готовые образы из GHCR** (мультиарх `linux/amd64` +
`linux/arm64`, с аттестацией происхождения сборки):

```bash
cp .env.example .env   # задайте настоящий FUMOX_ADMIN__TOKEN
docker compose up -d   # тянет образы и поднимает весь стек
```

Подписки: `http://<host>:8080/sub/{id}` · админ-панель:
<http://127.0.0.1:8081/admin> (вход по токену).

**Предпочитаете сборку из исходников?** Добавьте `--build`, чтобы собрать
образы локально, или запустите бинарники без контейнеров:

```bash
docker compose up -d --build

cargo build                 # тесты: cargo test
cargo run -p fumox-server   # сервер подписок + админка (http://127.0.0.1:8081/admin)
cargo run -p fumox-probe    # демон проверки живучести прокси
```

Используете Podman вместо Docker? [`docker/README.ru.md`](./docker/README.ru.md)
разворачивает тот же стек как podman-под под управлением systemd (quadlet-юниты
или kube-play манифест).

Конфигурация: [`config/app.toml`](./config/app.toml); все ключи имеют
дефолты, переопределение через окружение: `FUMOX_SECTION__KEY`
(например, `FUMOX_ADMIN__TOKEN=secret`).

---

## Гео-обогащение

Гео-обогащение использует базы MaxMind GeoLite2 (`.mmdb`, в репозиторий не
входят), и **сервер скачивает их сам**: при старте он проверяет `[geo].db_dir`
(по умолчанию `config/`) и подтягивает любую отсутствующую, битую или
старше месяца базу, ожидая не дольше `[geo].startup_download_budget_secs`
(60 с), прежде чем начать принимать соединения; более медленная загрузка
продолжается в фоне и вступает в силу со следующего старта. Ручной шаг не
обязателен.

Чтобы положить свои файлы (например, со своей лицензией MaxMind — регистрация
на <https://www.maxmind.com/en/geolite2/signup>), положите их под каноническими
именами в `[geo].db_dir` — `GeoLite2-City.mmdb` (факты о стране/городе) и
`GeoLite2-ASN.mmdb` (номера/организации автономных систем);
`GeoLite2-Country.mmdb` не читается. **Поставляемый Compose-стек
переопределяет каталог на `/shared/geo`** (`FUMOX_GEO__DB_DIR` в
`docker-compose.yml`), а окружение сильнее `app.toml`, поэтому `.mmdb`,
положенный в `./config`, там просто не читается: скопируйте его в volume
`fumox-geo` (`docker compose cp GeoLite2-City.mmdb server:/shared/geo/`) либо
уберите override и задайте `[geo].db_dir` в файле.

Без файла гео-обогащение автоматически отключается (предупреждение в логе),
сервер продолжает работать. Подробности —
[раздел 11 руководства пользователя](./USERGUIDE.ru.md#11-гео-обогащение).

---

## Безопасность

`[admin].token`, единственный критичный секрет «из коробки». Поменяйте его,
прежде чем открывать админку наружу с loopback. **За reverse-proxy нужно задать
два ключа конфигурации**, чтобы per-IP rate limit и `Host`-allowlist работали
корректно:

- `[server].trust_proxy_ips` и `[admin].trust_proxy_ips`: CIDR прокси
  (например, `["127.0.0.1/32"]`, если nginx на том же хосте). Без
  этих ключей все запросы приходят с IP прокси и лимит схлопывается
  в один общий бюджет.
- `[server].allowed_hosts` и `[admin].allowed_hosts`: ваше публичное
  имя хоста (например, `["fumox.example.com"]`). Без этих ключей
  `Host`-заголовок принимается как есть для URL токенов
  `/export/alive/{token}` / `/export/ready/{token}` и для отображаемых
  URL в админке, атакующий, способный подменить `Host`, добьется
  того, что админка отрисует URL на свой домен.

Оба ключа по умолчанию `[]`, чтобы сохранить историческое поведение
при прямом соединении.

- `[admin].secure_cookies` (или ENV-переменная `FUMOX_ADMIN__SECURE_COOKIES`):
  оставляйте `false`, когда панель доступна по plain HTTP
  (`http://127.0.0.1:8081`). Браузер молча отбрасывает
  `Secure`-cookie на `http://`, и со стороны выглядит как успешный вход
  (`admin logged in` в логах), за которым следует постоянный редирект на
  `/admin/login`.
  Ставьте `true`, только если TLS терминируется на reverse-proxy.
  Дефолт в файле: `false`, но `docker-compose.yml` ставит ENV-override
  в `true` (готовность к HTTPS-фронту), а для plain-HTTP `docker compose
  up` задайте `FUMOX_ADMIN__SECURE_COOKIES=false` в `.env`.

---

## Документация

**[Руководство пользователя](./USERGUIDE.ru.md)**, лучшее начало: что такое
Fumox, как он устроен, развертывание (Docker Compose / образ / сборка из
исходников), полный справочник по конфигурации и повседневное использование.
Английская версия: [USERGUIDE.md](./USERGUIDE.md).

## License

This project is licensed under the MIT License - see the LICENSE file for details.

All trademarks are the property of their respective owners.

- [meow-rs](https://github.com/meow-rs/meow-rs) A high-performance Rust implementation of the mihomo (Clash Meta) proxy kernel.

Database Copyright (c) [MaxMind](https://www.maxmind.com/), Inc.
- [GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula)
- [GeoIP2 End User License Agreement](https://www.maxmind.com/en/end-user-license-agreement)
- [Creative Commons Corporation Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/)
