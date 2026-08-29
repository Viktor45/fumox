# Quadlet (podman/systemd) — развёртывание Fumox без docker compose

Эквиваленты `docker-compose.yml` в виде quadlet-юнитов: systemd управляет
подом с тремя контейнерами (fumox-server, fumox-probe, meow-rs), как делал
compose. Два варианта на выбор:

| Папка      | Вариант                                        | Когда удобен                                                                                                                            |
| ---------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `quadlet/` | `fumox.pod` + три `.container` + два `.volume` | Нативный способ quadlet — оптимален: явные юниты, точечные volume-монты, `Restart` на каждый контейнер, статус каждого сервиса отдельно |
| `kube/`    | `fumox.kube` + `fumox-pod.yaml`                | Один манифест, близкий к k8s; удобно, если YAML уже привычнее                                                                           |

Нужен podman ≥ 4.4 (лучше 5.x). По умолчанию всё описано для **rootless**
(рекомендуется); отличия для root — в конце.

## Подготовка (для обоих вариантов)

Quadlet не собирает образы — соберите их один раз из корня репозитория:

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

2. Установить юниты (все файлы из папки — в один каталог юнитов):

   ```sh
   mkdir -p ~/.config/containers/systemd
   cp docker/quadlet/fumox.pod docker/quadlet/*.volume \
      docker/quadlet/*.container ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox-pod.service
   ```

   Старт пода тянет все три контейнера (server после него — probe ждёт
   миграцию БД, как `depends_on` в compose).

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
создаёт как именованные volume-ы (см. `podman volume ls`). Админ-порт
объявлен с `hostIP: 127.0.0.1` — после старта проверьте `podman port fumox`;
старые podman (без поддержки `hostIP`) опубликуют 8081 на все интерфейсы —
закройте его фаерволом или обновитесь.

## Отличия от docker compose

- `FUMOX_MEOW__API_ADDR: meow:9090` → `127.0.0.1:9090`: в поде общий сетевой
  namespace, DNS-имён сервисов нет. 9090 наружу не публикуется, как и в compose.
- Сборка образов — вручную (`podman build`), а не `compose up --build`.
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

```sh
git pull
podman build -t localhost/fumox:local .
systemctl --user restart fumox-pod.service   # вариант B: fumox.service
```

## Rootful (системный podman)

Те же файлы кладутся в `/etc/containers/systemd/`; `%h` тогда разворачивается
в `/root` (поправьте `EnvironmentFile=` и пути volume на системные), в
`[Install]` замените `default.target` на `multi-user.target`, управление —
`systemctl daemon-reload && systemctl start fumox-pod` (без `--user`).
