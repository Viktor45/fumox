# Quadlet (podman/systemd): развертывание Fumox без docker compose

Эквиваленты `docker-compose.yml` в виде quadlet-юнитов: systemd управляет
теми же тремя контейнерами (fumox-server, fumox-probe, meow-rs), но разнесенными
по двум подам, так чтобы прокси-ядро физически не могло дотянуться до админки.
Два варианта на выбор:

| Папка      | Вариант                                        | Когда удобен                                                                                                                            |
| ---------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `quadlet/` | `fumox.pod` + `fumox-worker.pod` + три `.container` + три `.volume` | Нативный способ quadlet, оптимален: явные юниты, точечные volume-монты, `Restart` на каждый контейнер, статус каждого сервиса отдельно |
| `kube/`    | `fumox.kube` + `fumox-pod.yaml`                | Один манифест, близкий к k8s; удобно, если YAML уже привычнее                                                                           |

Нужен podman ≥ 4.4 (лучше 5.x). По умолчанию все описано для **rootless**
(рекомендуется); отличия для root в конце.

Поды публикуют только HTTP: HTTPS терминирует обратный прокси перед
прослушивателем сервера. Готовый nginx-пример лежит в `docker/nginx/`
(общий с docker-compose; для podman-раскладки см. раздел «HTTPS для
quadlet/kube»).

## Подготовка (для обоих вариантов)

Quadlet не собирает образы: юниты ссылаются на локальные имена
`localhost/fumox:local` и `localhost/fumox-meow:local`. Подготовьте их любым
из двух способов:

**Способ 1: забрать готовые образы из GHCR (быстрее всего):**

```sh
podman pull ghcr.io/viktor45/fumox:latest
podman tag ghcr.io/viktor45/fumox:latest localhost/fumox:local
podman pull ghcr.io/viktor45/fumox-meow:latest
podman tag ghcr.io/viktor45/fumox-meow:latest localhost/fumox-meow:local
```

`ghcr.io/viktor45/fumox` публикуется workflow `.github/workflows/docker.yml`
по тегам `v*` и вручную через `workflow_dispatch` (см. заголовок файла,
автосборки при push в `main` нет);
`ghcr.io/viktor45/fumox-meow` упаковывается вручную workflow'ом
`docker-meow.yml`. Можно обойтись без перетегирования: поправьте строки
`Image=` в юнитах на GHCR-имена напрямую; там же удобно запиннить версию
(`ghcr.io/viktor45/fumox:0.2.0`) вместо `latest`.

**Способ 2: сборка из исходников** (из корня репозитория):

```sh
podman build -t localhost/fumox:local .
podman build -t localhost/fumox-meow:local docker/meow
```

Каталог конфигурации (только app.toml; файлы GeoLite2-*.mmdb сюда
**не** кладутся, см. ниже) должен лежать в понятном абсолютном пути,
например `~/fumox/config`:

```sh
mkdir -p ~/fumox/config
cp config/app.toml ~/fumox/config/
```

### Токены и секреты

Нужны два независимых секрета, и они никогда не лежат рядом:

| Секрет                  | Кто читает                              | Назначение                                        |
| ----------------------- | ---------------------------------------- | ------------------------------------------------- |
| `FUMOX_ADMIN__TOKEN`    | только сервер                            | токен входа в админку                            |
| `FUMOX_MEOW__API_TOKEN` | probe и ядро                             | секрет внешнего контроллера meow-rs               |

В pod-раскладках сервер тоже читает общий файл окружения, поэтому секрет
контроллера видит и он — ему он не нужен, но этот файл у всех трех
контейнеров общий. Токена админки в нем нет.

Генерируйте оба случайно — литеральный placeholder `change-me` **не** является
токеном: сервер не стартует с ним на не-loopback адресе, а пустое значение
вовсе выключает админку:

```sh
printf 'FUMOX_ADMIN__TOKEN=%s\n' "$(openssl rand -hex 32)"
printf 'FUMOX_MEOW__API_TOKEN=%s\n' "$(openssl rand -hex 32)"
```

Секрет контроллера может содержать только `[A-Za-z0-9._-]`; entrypoint ядра
отвергает всё остальное.

Вариант A (quadlet) хранит их в двух файлах окружения, вариант B (kube) — в
двух `podman secret`: разделение и есть то, что не пускает токен админки к
probe и ядру. Оба файла создаются с правами 600: в них лежит секрет, и
читать его другим пользователям нельзя.

### Гео-обогащение и общие volume-ы

Гео-обогащение смотрит в собственный volume, а не в каталог конфигурации:
оба варианта (и kube-манифест) задают `FUMOX_GEO__DB_DIR=/shared/geo` —
volume, принадлежащий одному серверу (quadlet: `fumox-geo.volume`,
`VolumeName=fumox-geo`; kube: PVC `fumox-geo`). Окружение сильнее
`[geo].db_dir`, поэтому `.mmdb`, положенные в каталог конфигурации, молча
никогда не сканируются. Сервер скачивает базы GeoLite2 в `/shared/geo` при
старте, так что ручной шаг опционален; чтобы положить свои файлы,
скопируйте их в этот volume (`podman volume mount fumox-geo` печатает путь на
хосте — тот же прием, что и в миграции БД ниже).

Обмен конфигурацией ядра — второй, отдельный volume (`fumox-meow.volume`,
`VolumeName=fumox-meow`; kube: PVC `fumox-meow`): probe рендерит T2-пакет в
`/shared/meow/meow.yaml` и горячо перезагружает ядро через его REST API.
Ядру не нужны базы GeoLite2, а серверу — конфигурация ядра, поэтому смешивать
их не надо.

### Безопасность cookie на plain HTTP

И quadlet, и compose публикуют админку на `127.0.0.1:8081` по plain HTTP.
Значит `[admin].secure_cookies` должен оставаться `false`, иначе браузер
молча отбрасывает `Secure`-cookie сессии, и каждый вход выглядит как
успешный `admin logged in` в `journalctl` с постоянным редиректом на
`/admin/login`. Включайте только при TLS-терминации на reverse-proxy:

- вариант A: `FUMOX_ADMIN__SECURE_COOKIES=true` в `fumox-admin.env`
- вариант B: `FUMOX_ADMIN__SECURE_COOKIES=true` в секрете `fumox-admin`

ENV приоритетнее файла (тот же figment merge, что и для остальных
override-переменных). Смена `[admin].token` или переключение
`secure_cookies` инвалидирует все активные сессии на следующем запросе,
поэтому планируйте ротацию токена на тихое окно.

## Вариант A: `quadlet/` (рекомендуется)

1. Переменные окружения — два файла, по одному на аудиторию:

   ```sh
   mkdir -p ~/.config/fumox
   install -m 600 docker/quadlet/fumox.env.example ~/.config/fumox/fumox.env
   install -m 600 docker/quadlet/fumox-admin.env.example ~/.config/fumox/fumox-admin.env
   $EDITOR ~/.config/fumox/fumox.env          # FUMOX_MEOW__API_TOKEN
   $EDITOR ~/.config/fumox/fumox-admin.env    # FUMOX_ADMIN__TOKEN
   ```

   `fumox.env` хранит общие переменные (секрет контроллера и, по желанию,
   `FUMOX_CONFIG`, `FUMOX_MEOW__TEST_URL`,
   `FUMOX_PROBE__ALLOW_PRIVATE_TARGETS`); `fumox-admin.env` — переменные
   админки (токен входа, флаг cookie, SSRF-guard для URL источников) и его
   читает только сервер. `FUMOX_CONFIG` — путь к TOML-файлу конфигурации
   внутри контейнера (по умолчанию `/app/config/app.toml` из смонтированного
   каталога). Переменные из юнита (`Environment=`) сильнее этих файлов,
   поэтому путь в юнитах не зафиксирован, настраивайте его здесь.

2. Установить юниты (все файлы из папки, в один каталог юнитов):

   ```sh
   mkdir -p ~/.config/containers/systemd
   cp docker/quadlet/fumox.pod docker/quadlet/fumox-worker.pod \
      docker/quadlet/*.volume docker/quadlet/*.container \
      ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox-pod.service        # сервер
   systemctl --user start fumox-worker-pod.service  # probe и ядро
   ```

3. Автостарт без активной сессии: `loginctl enable-linger $USER`.

Проверка: `curl -s http://127.0.0.1:8080/healthz` → `ok`; админка
<http://127.0.0.1:8081/admin> (на хост публикуется только loopback, как и в
compose). Логи: `journalctl --user -u fumox-server -u fumox-probe -u fumox-meow -f`.

### Два пода и кто что запускает

`fumox.pod` содержит только сервер; `fumox-worker.pod` — probe и ядро. По
сети они не общаются: сервер и probe работают через общий том с SQLite, а
probe и ядро — через общий том с конфигом. Разделение намеренное: ядро
работает с недоверенным прокси-трафиком, а его конфигурация доступна на
запись probe, поэтому оно не должно доставать до админки даже внутри общего
network namespace.

Оба пода стартуют одновременно и не ждут друг друга. Сервер применяет и
мигрирует схему до того, как binds слушатели; probe читает список прокси из
базы и пишет туда же вердиктыhealth, поэтому сервер ему для работы не нужен.
Единственный общий ресурс — схема, и её применяют обе стороны при старте:
SQLite сериализует двух писателей, и проигравший повторяет попытку, пока
не освободится блокировка (см. `connect_probe_pool` в
`crates/fumox-core/src/db.rs`). Поэтому probe не падает на `database is
locked` — он откатывается по своему backoff, и юнит остается поднятым.

### Правка `app.toml` из админки

`fumox-server.container` монтирует каталог конфига как `:rw,Z`, поэтому страница
*Edit settings* (`/admin/settings/edit`) пишет `/app/config/app.toml` на
месте через `toml_edit`-редактор. Комментарии переживают каждое
сохранение; ENV-переменные `FUMOX_SECTION__KEY` сохраняют приоритет по
merge figment; после сохранения нужно перезапустить server и probe.
`fumox-probe.container` остаётся read-only: probe только читает файл
при старте и никогда в него не пишет. Чтобы выключить редактор, поменяйте
в server-юните `:rw,Z` на `:ro,Z`; страница отрендерится с заблокированными
контролами и красным баннером `set.edit_unwritable`.

## Вариант B: `kube/`

1. Образы: как выше.
2. Два секрета с переменными (`.env`-аналог), каждый со случайным значением:

   ```sh
   printf 'FUMOX_ADMIN__TOKEN=%s\n' "$(openssl rand -hex 32)" \
     | podman secret create fumox-admin -
   printf 'FUMOX_MEOW__API_TOKEN=%s\n' "$(openssl rand -hex 32)" \
     | podman secret create fumox-env -
   ```

   Секрет `fumox-env` несет то, что нужно probe и ядру (секрет контроллера
   и, по желанию, `FUMOX_MEOW__TEST_URL` /
   `FUMOX_PROBE__ALLOW_PRIVATE_TARGETS`). Секрет `fumox-admin` несет токен
   входа в админку и подключен только к контейнеру сервера, так что ни
   probe, ни ядро до панели не достаются. Добавьте
   `FUMOX_ADMIN__SECURE_COOKIES=false` в `fumox-admin`, если панель
   открывается по plain HTTP (обычное состояние этого варианта), или
   `true`, когда перед ней терминируется TLS.

3. В `fumox-pod.yaml` поправить `hostPath` каталога `config` (сейчас
   `/opt/fumox/config`).
4. Установить и запустить:

   ```sh
   cp docker/kube/fumox.kube docker/kube/fumox-pod.yaml \
      ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox.service
   ```

PVC `fumox-data`, `fumox-geo` и `fumox-meow` при первом старте podman
автоматически создает как именованные volume-ы (см. `podman volume ls`).
Админ-порт объявлен с `hostIP: 127.0.0.1`; после старта проверьте
`podman port fumox`; старые podman (без поддержки `hostIP`) опубликуют 8081
на все интерфейсы, закройте его фаерволом или обновитесь.

### Порядок старта и холодный старт

`podman kube play` поднимает контейнеры обоих подов одновременно. Init-контейнер
не может ждать сервер: init-контейнеры выполняются *до* прикладных, поэтому
init с ожиданием `/healthz` замкнул бы под в deadlock. Он и не нужен: probe не
зависит от сервера — он читает список прокси из базы и пишет туда же вердикты
health. Единственный общий ресурс — схема, и её применяют обе стороны при
старте: SQLite сериализует двух писателей, и проигравший повторяет попытку,
пока не освободится блокировка (`connect_probe_pool` в
`crates/fumox-core/src/db.rs`). Compose-раскладка вместо этого gate'ит probe
на healthcheck сервера; pod-раскладка в этом не нуждается.

Поэтому холодный старт выглядит так: сервер мигрирует схему и binds, probe
ждет читаемости базы (повторяя попытки по своему backoff) и начинает циклы.
Ни один контейнер в это окно не выходит, так что restart count остается 0.

## HTTPS для quadlet/kube

`docker/nginx/` содержит образ nginx, который терминирует TLS перед обоими
слушателями. Он параметризован, поэтому один и тот же образ работает в любой
раскладке:

| Переменная              | Compose           | Podman-под (внутри `fumox.pod`) |
| ----------------------- | ----------------- | ------------------------------- |
| `FUMOX_UPSTREAM_PUBLIC` | `server:8080`     | `127.0.0.1:8080`                |
| `FUMOX_UPSTREAM_ADMIN`  | `server:8081`     | `127.0.0.1:8081`                |
| `FUMOX_SERVER_NAME`     | ваш домен         | ваш домен                       |

Compose-вариант резолвит имена сервисов через встроенный DNS Docker
(`127.0.0.11`), podman-варианту резолвер не нужен вовсе, потому что upstream —
литеральный loopback-адрес. Вариант выбирается на этапе сборки:

```sh
# compose (вариант по умолчанию)
podman build -t localhost/fumox-nginx:local docker/nginx

# podman: nginx работает ВНУТРИ пода сервера, рядом с сервером
podman build --build-arg NGINX_FLAVOUR=podman \
  -t localhost/fumox-nginx:local docker/nginx
```

Запуск внутри пода сервера (quadlet) означает, что контейнер nginx делит
network namespace с сервером, поэтому upstream — это loopback-адреса и больше
ничего не должно быть достижимо. Контейнер, вошедший в namespace пода, не
публикует порты сам, поэтому TLS-порт публикует под: добавьте в `fumox.pod`

```ini
PublishPort=80:80
PublishPort=443:443
```

и перезагрузите под

```sh
systemctl --user daemon-reload
systemctl --user restart fumox-pod.service
```

после чего запускайте фронт:

```sh
podman run -d --name fumox-nginx \
  --network pod:fumox \
  --read-only \
  --tmpfs /var/cache/nginx:rw,noexec,nosuid,nodev,mode=1777,size=32m \
  --tmpfs /var/run:rw,noexec,nosuid,nodev,mode=1777,size=8m \
  -v ~/fumox/certs:/certs:ro \
  -e FUMOX_UPSTREAM_PUBLIC=127.0.0.1:8080 \
  -e FUMOX_UPSTREAM_ADMIN=127.0.0.1:8081 \
  -e FUMOX_SERVER_NAME=fumox.example.com \
  localhost/fumox-nginx:local
```

kube-вариант — та же идея в YAML: nginx становится третьим контейнером пода
`fumox`, который по определению делит его network namespace, поэтому
loopback-upstream работают, а порт публикует под:

```yaml
    - name: nginx
      image: localhost/fumox-nginx:local
      env:
        - name: FUMOX_UPSTREAM_PUBLIC
          value: "127.0.0.1:8080"
        - name: FUMOX_UPSTREAM_ADMIN
          value: "127.0.0.1:8081"
        - name: FUMOX_SERVER_NAME
          value: fumox.example.com
      ports:
        - containerPort: 443
          hostPort: 443
          protocol: TCP
      volumeMounts:
        - name: certs
          mountPath: /certs
          readOnly: true
```

(volume `certs` — это `hostPath` на каталог с `fullchain.pem` и
`privkey.pem`.)

Когда перед панелью есть TLS, выставьте `FUMOX_ADMIN__SECURE_COOKIES=true`
(вариант A: `fumox-admin.env`; вариант B: секрет `fumox-admin`), иначе
браузер отбросит cookie сессии.

Какие host names принимает фронт, решает сам Fumox:
`[server].allowed_hosts` (`FUMOX_SERVER__ALLOWED_HOSTS`). Nginx-фронт
нормализует заголовок `Host` (дефолтные порты отбрасываются, недефолтный
порт сохраняется, а Host, не являющийся простым hostname, заменяется на
каноническое имя), так что подделанный Host не попадет в сгенерированную
ссылку.

## Отличия от docker compose

- `FUMOX_MEOW__API_ADDR: meow:9090` → `127.0.0.1:9090`: в поде общий сетевой
  namespace, DNS-имен сервисов нет. 9090 наружу не публикуется, как и в compose.
- В compose два network-а (`default` + `meow`), в pod-раскладке ту же
  изоляцию дает разделение на поды.
- Образы либо тянутся из GHCR, либо собираются вручную (`podman build`);
  compose умеет и то и другое (`up -d` тянет, `up --build` собирает).
- Именованные volume-ы podman (`fumox-data`, `fumox-geo`, `fumox-meow`) это не
  те же хранилища, что у docker. Перенос БД из compose:

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
  (systemd не перезапускает явно остановленное, семантика совпадает).
- Секрет `FUMOX_ADMIN__TOKEN` хранится не в `.env` рядом с compose-файлом,
  а в `~/.config/fumox/fumox-admin.env` (вариант A) или в `podman secret`
  (вариант B).

## Обновление версии

**Сначала сделайте резервную копию БД.** Сервер мигрирует схему при старте, и
миграция идет в том же процессе, что и обслуживание запросов: неудачная
миграция оставляет том с наполовину примененной схемой. Скопируйте
`fumox.db` (и его соседей `-wal` / `-shm`) из тома перед рестартом, например
через `podman volume mount fumox-data` и обычный `cp`.

С образами из GHCR (способ 1 из «Подготовки»):

```sh
podman pull ghcr.io/viktor45/fumox:latest
podman tag ghcr.io/viktor45/fumox:latest localhost/fumox:local
systemctl --user restart fumox-pod.service        # вариант B: fumox.service
systemctl --user restart fumox-worker-pod.service  # вариант B: тот же юнит
```

Если юниты ссылаются прямо на GHCR-образ (без перетегирования), достаточно
pull и рестарта — шаг `podman tag` не нужен:

```sh
podman pull ghcr.io/viktor45/fumox:0.2.0
systemctl --user restart fumox-pod.service
```

С локально собранными:

```sh
git pull
podman build -t localhost/fumox:local .
systemctl --user restart fumox-pod.service        # вариант B: fumox.service
systemctl --user restart fumox-worker-pod.service  # вариант B: тот же юнит
```

(Обертку `fumox-meow` обновляют так же, когда нужен более свежий релиз
meow-rs.)

## Rootful (системный podman)

Те же файлы кладутся в `/etc/containers/systemd/`; `%h` тогда разворачивается
в `/root` (поправьте `EnvironmentFile=` и пути volume на системные), в
`[Install]` замените `default.target` на `multi-user.target`, управление:
`systemctl daemon-reload && systemctl start fumox-pod` (без `--user`).
