# Quadlet (podman/systemd) — развертывание Fumox без docker compose

Эквиваленты `docker-compose.yml` в виде quadlet-юнитов: systemd управляет
подом с тремя контейнерами (fumox-server, fumox-probe, meow-rs), как делал
compose. Два варианта на выбор:

| Папка      | Вариант                                        | Когда удобен                                                                                                                            |
| ---------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `quadlet/` | `fumox.pod` + три `.container` + два `.volume` | Нативный способ quadlet — оптимален: явные юниты, точечные volume-монты, `Restart` на каждый контейнер, статус каждого сервиса отдельно |
| `kube/`    | `fumox.kube` + `fumox-pod.yaml`                | Один манифест, близкий к k8s; удобно, если YAML уже привычнее                                                                           |

Нужен podman ≥ 4.4 (лучше 5.x). По умолчанию все описано для **rootless**
(рекомендуется); отличия для root — в конце.

## Подготовка (для обоих вариантов)

Quadlet не собирает образы — юниты ссылаются на локальные имена
`localhost/fumox:local` и `localhost/fumox-meow:local`. Подготовьте их любым
из двух способов:

**Способ 1 — забрать готовые образы из GHCR (быстрее всего):**

```sh
podman pull ghcr.io/viktor45/fumox:latest
podman tag ghcr.io/viktor45/fumox:latest localhost/fumox:local
podman pull ghcr.io/viktor45/fumox-meow:latest
podman tag ghcr.io/viktor45/fumox-meow:latest localhost/fumox-meow:local
```

`ghcr.io/viktor45/fumox` публикует CI (`.github/workflows/docker.yml`);
`ghcr.io/viktor45/fumox-meow` упаковывается вручную workflow'ом
`docker-meow.yml`. Можно обойтись без перетегирования — поправьте строки
`Image=` в юнитах на GHCR-имена напрямую; там же удобно запиннить версию
(`ghcr.io/viktor45/fumox:0.2.0`) вместо `latest`.

**Способ 2 — сборка из исходников** (из корня репозитория):

```sh
podman build -t localhost/fumox:local .
podman build -t localhost/fumox-meow:local docker/meow
```

Каталог конфигурации (app.toml + опциональные GeoLite2-*.mmdb) должен лежать
в понятном абсолютном пути, например `~/fumox/config`:

```sh
mkdir -p ~/fumox/config
cp config/app.toml ~/fumox/config/
cp config/GeoLite2-*.mmdb ~/fumox/config/   # опционально: гео-обогащение
```

## Вариант A: `quadlet/` (рекомендуется)

1. Переменные окружения (`.env`-аналог):

   ```sh
   mkdir -p ~/.config/fumox
   cp docker/quadlet/fumox.env.example ~/.config/fumox/fumox.env
   $EDITOR ~/.config/fumox/fumox.env          # задать FUMOX_ADMIN__TOKEN
   ```

   Кроме `FUMOX_ADMIN__TOKEN` в файле можно задать `FUMOX_CONFIG` — путь к
   TOML-файлу конфигурации внутри контейнера (по умолчанию
   `/app/config/app.toml` из смонтированного каталога). Переменные из юнита
   (`Environment=`) сильнее этого файла, поэтому путь в юнитах не зафиксирован —
   настраивайте его здесь.

2. Установить юниты (все файлы из папки — в один каталог юнитов):

   ```sh
   mkdir -p ~/.config/containers/systemd
   cp docker/quadlet/fumox.pod docker/quadlet/*.volume \
      docker/quadlet/*.container ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox-pod.service
   ```

   Старт пода поднимает все три контейнера (probe запускается после server
   согласно зависимости пода в quadlet; сервер мигрирует БД при первом
   подключении, а probe при `database is locked` повторяет попытки по своему
   backoff).

3. Автостарт без активной сессии: `loginctl enable-linger $USER`.

Проверка: `curl -s http://127.0.0.1:8080/healthz` → `ok`; админка —
<http://127.0.0.1:8081/admin> (на хост публикуется только loopback, как и в
compose). Логи: `journalctl --user -u fumox-server -u fumox-probe -u fumox-meow -f`.

## Вариант B: `kube/`

1. Образы — как выше.
2. Секрет с переменными (`.env`-аналог):

   ```sh
   printf 'FUMOX_ADMIN__TOKEN=change-me\n' | podman secret create fumox-env -
   ```

3. В `fumox-pod.yaml` поправить `hostPath` каталога `config` (сейчас
   `/opt/fumox/config`).
4. Установить и запустить:

   ```sh
   cp docker/kube/fumox.kube docker/kube/fumox-pod.yaml \
      ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox.service
   ```

PVC `fumox-data` и `meow-shared` при первом старте podman автоматически
создает как именованные volume-ы (см. `podman volume ls`). Админ-порт
объявлен с `hostIP: 127.0.0.1` — после старта проверьте `podman port fumox`;
старые podman (без поддержки `hostIP`) опубликуют 8081 на все интерфейсы —
закройте его фаерволом или обновитесь.

## Отличия от docker compose

- `FUMOX_MEOW__API_ADDR: meow:9090` → `127.0.0.1:9090`: в поде общий сетевой
  namespace, DNS-имен сервисов нет. 9090 наружу не публикуется, как и в compose.
- Образы либо тянутся из GHCR, либо собираются вручную (`podman build`);
  compose умеет и то и другое (`up -d` тянет, `up --build` собирает).
- Именованные volume-ы podman (`fumox-data`, `meow-shared`) — не те же
  хранилища, что у docker. Перенос БД из compose:

  ```sh
  docker volume ls | grep fumox          # имя вида <проект>_fumox-data
  podman volume mount fumox-data         # путь в выводе
  cp "$(docker volume inspect <имя> --format '{{ .Mountpoint }}')/fumox.db" \
     "$(podman volume mount fumox-data)/"
  podman volume unmount fumox-data
  ```

  (docker volume mountpoint может требовать root; на macOS/OrbStack данные
  лежат в VM docker.)
- `restart: unless-stopped` → `Restart=on-failure` в секциях `[Service]`
  (systemd не перезапускает явно остановленное — семантика совпадает).
- Секрет `FUMOX_ADMIN__TOKEN` хранится не в `.env` рядом с compose-файлом,
  а в `~/.config/fumox/fumox.env` (вариант A) или в `podman secret`
  (вариант B).

## Обновление версии

С образами из GHCR (способ 1 из «Подготовки»):

```sh
podman pull ghcr.io/viktor45/fumox:latest
podman tag ghcr.io/viktor45/fumox:latest localhost/fumox:local
systemctl --user restart fumox-pod.service   # вариант B: fumox.service
```

С локально собранными:

```sh
git pull
podman build -t localhost/fumox:local .
systemctl --user restart fumox-pod.service   # вариант B: fumox.service
```

(Обертку `fumox-meow` обновляют так же, когда нужен более свежий релиз
meow-rs.)

## Rootful (системный podman)

Те же файлы кладутся в `/etc/containers/systemd/`; `%h` тогда разворачивается
в `/root` (поправьте `EnvironmentFile=` и пути volume на системные), в
`[Install]` замените `default.target` на `multi-user.target`, управление —
`systemctl daemon-reload && systemctl start fumox-pod` (без `--user`).
