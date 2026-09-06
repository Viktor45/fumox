# Fumox 🥋⚡

*English version: [README.md](./README.md)*

`Fumox` — молниеносный и легкий инструмент для **фильтрации и очистки данных подписок в реальном времени**.

Он применяет высшее алгоритмическое мастерство к хаотичным живым потокам данных, чтобы подписчики мгновенно — на лету — получали только чистые, точные и структурированные обновления.

---

## 💡 Что в имени?

Имя **Fumox** — оптимизированное современное слияние восточной дисциплины и древнеримской скорости:

* **Fu** *(кит. 工夫)* — означает *«мастерство»* или *«навык, достигнутый дисциплиной»*. Это скрытная эффективность, точность маршрутизации и выверенность наших алгоритмов фильтрации.
* **Mox** *(лат.)* — означает *«немедленно»*, *«мгновенно»* или *«тут же»*. Это отражает абсолютную **реальновременность** движка потоков.

### Четыре столпа Fumox:
1. **Призма (Ясность)** — рассекает и преломляет входящие массивы данных на чистые, изолированные темы подписок.
2. **Кузница (Мощь)** — мгновенно переплавляет невалидные полезные нагрузки и перековывает битые логи в строгие, предсказуемые схемы еще до того, как они попадут к подписчикам.
3. **Батут (Скорость)** — подхватывает события реального времени и без задержки запускает адресные обновления прямо в активные вебхуки или потребители.
4. **Помпон (Мягкость)** — служит мягким буфером, который сглаживает экстремальные пики данных и всплески трафика, не давая подписчикам захлебнуться.

---

## Быстрый старт

Проект в активной разработке.

**Самый быстрый старт — готовые образы из GHCR** (мультиарх `linux/amd64` +
`linux/arm64`, с аттестацией происхождения сборки; образ-обертка meow-rs
обновляется ручным workflow):

```bash
cp .env.example .env   # задайте настоящий FUMOX_ADMIN__TOKEN
docker compose up -d   # тянет образы и поднимает весь стек
```

Подписки: `http://<host>:8080/sub/{id}` · админ-панель:
<http://127.0.0.1:8081/admin> (вход по токену).

**Предпочитаете сборку из исходников?** Добавьте `--build`, чтобы собрать
образы локально:

```bash
docker compose up -d --build
```

или запустите бинарники без контейнеров:

```bash
cargo build                 # тесты: cargo test
cargo run -p fumox-server   # сервер подписок + админка (http://127.0.0.1:8081/admin)
cargo run -p fumox-probe    # демон проверки живучести прокси
```

Используете Podman вместо Docker? [`docker/README.ru.md`](./docker/README.ru.md)
разворачивает тот же стек как podman-под под управлением systemd (quadlet-юниты
или kube-play манифест).

Подробности — в [`USERGUIDE.ru.md`](./USERGUIDE.ru.md).

Конфигурация — [`config/app.toml`](./config/app.toml); все ключи имеют
дефолты, переопределение через окружение: `FUMOX_СЕКЦИЯ__КЛЮЧ`
(например, `FUMOX_ADMIN__TOKEN=secret`).

GeoLite2-базы MaxMind (`.mmdb`) не входят в репозиторий — скачайте их в
`config/` отдельно:

1. Зарегистрируйтесь на <https://www.maxmind.com/en/geolite2/signup>
   (бесплатный аккаунт).
2. Скачайте нужную базу через
   [Account → Manage License Keys / Download Databases](https://dev.maxmind.com/geoip/docs/databases/):
   по умолчанию используется `GeoLite2-Country.mmdb` (опционально
   `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`).
3. Положите файл в `config/` под каноническим именем.

Без файла гео-обогащение автоматически отключается (предупреждение в логе),
сервер продолжает работать. Базы MaxMind обновляются еженедельно.

---

## 📖 Документация

**[Руководство пользователя](./USERGUIDE.ru.md)** — лучшее начало: что такое
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
