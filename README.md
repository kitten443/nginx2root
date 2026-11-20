# nginx2root — чекер уязвимости (Python 3 / Go)

Чекер для **nginx2root** — набора из пяти уязвимостей nginx
([CVE-2026-123007](https://www.cve.org/CVERecord?id=CVE-2026-123007),
[CVE-2026-123634](https://www.cve.org/CVERecord?id=CVE-2026-123634),
[CVE-2026-123633](https://www.cve.org/CVERecord?id=CVE-2026-123633),
[CVE-2026-121810](https://www.cve.org/CVERecord?id=CVE-2026-121810),
[CVE-2026-113425](https://www.cve.org/CVERecord?id=CVE-2026-113425))
и отдельной уязвимости SCTP в ядре Linux, с которой RCE в worker'е
превращается в root на хосте.

Проверяет сайт по URL, список сайтов из файла или локальный nginx.
В режиме `--local` дополнительно разбирает `nginx -V`, `nginx -T`,
версию пакета ОС и состояние модуля SCTP.

В репозитории две реализации с одинаковым CLI: Python (`n2check.py`)
и Go (`n2check.go`, только стандартная библиотека).

> ⚠️ Инструмент **только диагностирует**. Он не содержит эксплойтов,
> не отправляет атакующих запросов и не проверяет фактическую
> эксплуатацию. Запускайте его только на своих системах.

## Установка Python и Go

В репозитории две реализации: Python (`n2check.py`) и Go (`n2check.go`).
Обе используют только стандартную библиотеку, поэтому `pip install`,
`npm install` и внешние Go-модули не нужны.

| Инструмент | Минимум | Рекомендуется |
|---|---|---|
| Python | 3.8 | 3.11+ (3.12/3.13/3.14) |
| Go | 1.21 | 1.27.x |

Для `--local` нужен установленный nginx; для чтения конфигурации через
`nginx -T` обычно нужен root.

### Python

Сначала проверьте, что уже установлено:

```bash
python3 --version
python --version
```

Если команда не найдена или версия ниже 3.8 — установите Python одним из
способов ниже. Для новых систем берите 3.11+; ветки 3.8–3.10 уже не
получают обычных обновлений безопасности.

#### Linux: универсальный способ через pyenv

Подходит, если нужна конкретная версия и нет root:

```bash
curl https://pyenv.run | bash
```

Добавьте в `~/.bashrc` или `~/.zshrc`:

```bash
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```

Затем:

```bash
exec "$SHELL"
pyenv install --list | grep -E '^  3\.(11|12|13|14)'
pyenv install 3.12.8       # подставьте любую версию из списка
pyenv global 3.12.8
python --version
```

#### Debian и Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv
python3 --version
```

Если нужна более новая версия в Ubuntu:

```bash
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.12 python3.12-venv
python3.12 --version
```

В Debian для нестандартной версии используйте pyenv или backports —
deadsnakes предназначен для Ubuntu.

#### RHEL, Fedora, AlmaLinux, Rocky, Oracle Linux, Amazon Linux

```bash
sudo dnf install -y python3 python3-pip
python3 --version
```

Если в репозитории есть отдельные версии:

```bash
sudo dnf install -y python3.12
python3.12 --version
```

В Amazon Linux 2 вместо `dnf` используйте `yum`. Если нужной версии нет
в репозитории, ставьте pyenv.

#### Alpine Linux

```bash
sudo apk add python3
python3 --version
```

#### Arch Linux

```bash
sudo pacman -S python
python3 --version
```

#### SUSE / openSUSE

```bash
sudo zypper install python3
python3 --version
```

#### macOS

```bash
xcode-select --install
brew install python@3.12
python3.12 --version
```

Или скачайте установщик с [python.org](https://www.python.org/downloads/).
Для нескольких версий удобен pyenv:

```bash
brew install pyenv
pyenv install 3.12.8
pyenv global 3.12.8
```

#### Windows

1. Скачайте установщик с [python.org](https://www.python.org/downloads/windows/).
2. При установке включите **Add python.exe to PATH**.
3. Откройте новый терминал и проверьте:

```powershell
py --version
py -3.12 n2check.py --version
```

Вариант через winget:

```powershell
winget install -e --id Python.Python.3.12
```

Если `py` не найден, переустановите Python с включённым PATH или
используйте полный путь к `python.exe`.

#### Виртуальное окружение (необязательно)

Скрипту не нужны сторонние пакеты, но venv полезен, чтобы не смешивать
версии:

```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
python --version
```

### Go

Проверьте установленную версию:

```bash
go version
```

Нужен Go 1.21+. Если версия ниже или команда не найдена — установите Go.

#### Linux: официальный tarball

Самый предсказуемый способ получить свежую версию:

```bash
GO_VERSION=1.27.4
ARCH=amd64          # для ARM64: ARCH=arm64

curl -LO "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-${ARCH}.tar.gz"
export PATH="$PATH:/usr/local/go/bin"
go version
```

Чтобы PATH сохранился после перезагрузки:

```bash
echo 'export PATH="$PATH:/usr/local/go/bin"' >> ~/.profile
source ~/.profile
```

Актуальную версию смотрите на [go.dev/dl](https://go.dev/dl/) или:

```bash
curl -s 'https://go.dev/VERSION?m=text'
```

#### Linux без root

```bash
GO_VERSION=1.27.4
mkdir -p "$HOME/.local"
curl -LO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
tar -C "$HOME/.local" -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
export PATH="$HOME/.local/go/bin:$PATH"
go version
```

#### Пакетные менеджеры

```bash
# Debian / Ubuntu (проверьте версию: может быть старее 1.21)
sudo apt install -y golang-go

# RHEL / Fedora / AlmaLinux / Rocky / Oracle Linux / Amazon Linux
sudo dnf install -y golang
# или, если доступен go-toolset:
sudo dnf install -y go-toolset

# Alpine
sudo apk add go

# Arch
sudo pacman -S go

# SUSE / openSUSE
sudo zypper install go
```

После установки из пакетного менеджера обязательно проверьте `go version`.
Если версия ниже 1.21 — используйте официальный tarball.

#### macOS

```bash
brew install go
go version
```

Или установщик `.pkg` с [go.dev/dl](https://go.dev/dl/).

#### Windows

1. Скачайте MSI с [go.dev/dl](https://go.dev/dl/).
2. Установите (по умолчанию `C:\Program Files\Go`).
3. Откройте новый терминал:

```powershell
go version
go env GOROOT GOPATH
```

Вариант через winget:

```powershell
winget install -e --id GoLang.Go
```

Если `go` не найден, добавьте `C:\Program Files\Go\bin` в PATH.

#### Конкретная версия Go

Если нужна не одна, а несколько версий, удобно использовать официальный
launcher (требует уже установленный Go):

```bash
go install golang.org/dl/go1.27.4@latest
"$(go env GOPATH)/bin/go1.27.4" download
"$(go env GOPATH)/bin/go1.27.4" version
```

Либо распакуйте tarball в отдельный каталог и вызывайте его напрямую:

```bash
sudo tar -C /opt -xzf go1.27.4.linux-amd64.tar.gz
/opt/go/bin/go version
```

### Сборка проекта

```bash
git clone https://github.com/kitten443/nginx2root.git
cd nginx2root

# Python
python3 n2check.py --version

# Go
go build -o n2check .
./n2check --version
```

Windows:

```powershell
py n2check.py --version
go build -o n2check.exe .
.\n2check.exe --version
```

`go mod download` не нужен: внешних зависимостей нет.

## Что делает

- **По URL**: читает заголовок `Server`, извлекает версию nginx и проверяет
  её по официальным диапазонам. Дополнительно согласует ALPN (`h2`) и
  смотрит `Alt-Svc` на признаки HTTP/3.
- **По списку** (`--file`): сканирует много сайтов — синхронно,
  многопоточно (`--threads N`) или асинхронно (`--async`).
- **Локально** (`--local`): запускает `nginx -v`, `nginx -V`, `nginx -T`,
  определяет сборку (HTTP/2, HTTP/3, mail), опасные директивы
  (`http2`, `quic`, `resolver`, `proxy_pass` с переменной, `mirror`,
  `auth_http`) и версию пакета ОС.
- **Debian, Ubuntu, RHEL, CentOS, Fedora, AlmaLinux, Rocky, Oracle Linux,
  Amazon Linux, Alpine, SUSE, Arch, FreeBSD**: учитывает security-патчи
  для низких версий
  nginx. Без этого `nginx -v` показывает «уязвимую» 1.22.1/1.26.3, хотя
  пакет уже исправлен. Для RPM-систем из changelog извлекаются конкретные
  CVE, поэтому частичный фикс не считается полным.
- **SCTP**: в `--local` проверяет, загружен ли модуль, встроен ли он в ядро
  и заблокирован ли через `modprobe.d`. Это advisory: на код возврата
  не влияет.

## Использование

```bash
# Проверить сайт
python3 n2check.py https://example.com
python3 n2check.py https://example.com --json
python3 n2check.py https://example.com --timeout 15
python3 n2check.py https://example.com --insecure   # не проверять TLS-сертификат

# Проверить локальный nginx
python3 n2check.py --local
sudo python3 n2check.py --local                     # чтобы nginx -T прочитал конфиг
python3 n2check.py --local --nginx /usr/sbin/nginx
python3 n2check.py --local --json

# Список сайтов: одна строка — один URL, # — комментарий
python3 n2check.py --file sites.txt
python3 n2check.py --file sites.txt --threads 10
python3 n2check.py --file sites.txt --threads 50 --async
cat sites.txt | python3 n2check.py --file - --threads 10 --json
```

### Go-версия

CLI, JSON-схема, коды возврата и правила проверки пакетов совпадают с Python.
Собрать и запустить:

```bash
go build -o n2check .
./n2check https://example.com --json
sudo ./n2check --local
./n2check --file sites.txt --threads 20
```

Пример `sites.txt`:

```
# свои проекты
https://example.com
https://shop.example.com  # интернет-магазин
https://blog.example.com
```

Пример вывода по URL:

```
VULNERABLE: nginx 1.31.8
  Server: nginx/1.31.8
  HTTP/2: да (ALPN h2)
  HTTP/3: не рекламируется (отсутствие Alt-Svc не доказывает отсутствие QUIC)
  Примечание: версия из баннера может не учитывать бэкпорт дистрибутива; для Debian проверьте пакет локально: --local.
  CVE-2026-123007 (переполнение в HTTP/2 flow control): EXPOSED — сервер согласовал HTTP/2 по ALPN (h2)
  CVE-2026-123634 (use-after-free в DNS resolver): UNKNOWN — нужны resolver, proxy_pass с переменной и subrequest — конфигурация не видна удалённо
  CVE-2026-123633 (use-after-free в HTTP/2 (upstream)): POSSIBLE — HTTP/2 включён; наличие upstream проверяется по конфигурации
  CVE-2026-121810 (use-after-free в HTTP/3 (upstream)): UNKNOWN — HTTP/3 удалённо не подтверждён; отсутствие Alt-Svc ничего не доказывает
  CVE-2026-113425 (use-after-free в mail proxy (auth_http)): UNKNOWN — нужен mail proxy с proxy on и auth_http — конфигурация не видна удалённо
```

Пример локального вывода:

```
VULNERABLE: nginx 1.26.3
  Сборка: HTTP/2=да, HTTP/3=да, mail=да
  Конфигурация: HTTP/2=да, HTTP/3=нет, resolver=да, proxy_pass с переменной=да, mirror=да, mail proxy=да
  CVE-2026-123007 (переполнение в HTTP/2 flow control): EXPOSED — HTTP/2 включён в конфигурации
  CVE-2026-123634 (use-after-free в DNS resolver): POSSIBLE — есть resolver, proxy_pass с переменной и subrequest (mirror/SSI)
  CVE-2026-123633 (use-after-free в HTTP/2 (upstream)): POSSIBLE — HTTP/2 включён и есть proxy_pass/grpc_pass на upstream
  CVE-2026-121810 (use-after-free в HTTP/3 (upstream)): NOT EXPOSED — HTTP/3/QUIC не включён в конфигурации
  CVE-2026-113425 (use-after-free в mail proxy (auth_http)): EXPOSED — mail-блок с proxy on и auth_http
  SCTP в ядре (LPE до root): WARNING — модуль sctp не загружен, но может загрузиться автоматически; если SCTP не нужен, добавьте install sctp /bin/false
```

## Патчи дистрибутивов и репозиториев

`nginx -v` **не меняется** после backport: пакет обновляется, а upstream-версия
остаётся прежней. Поэтому `--local` определяет семейство ОС и пакетный менеджер:

- **Debian/Ubuntu** — `dpkg-query` + `dpkg --compare-versions`;
- **RHEL, Fedora, AlmaLinux, Rocky, Oracle Linux, Amazon Linux, SUSE** —
  `rpm -qf` и `rpm -q --changelog`; из changelog извлекаются конкретные CVE,
  поэтому «частично исправленный» пакет не выдаётся за полностью исправленный;
- **Alpine** — `apk` и таблица исправленных версий по веткам;
- **Arch Linux** — `pacman -Q` + upstream-версия;
- **FreeBSD** — `pkg query` + upstream-версия.

Если пакет закрывает только часть CVE, статус пакета будет
**«исправлено частично»**, а незакрытые CVE останутся `VULNERABLE`.

### Debian

| Релиз | Исправленный пакет | Advisory |
|---|---|---|
| Debian 12 bookworm | `1.22.1-9+deb12u11` | [DLA-4918-1](https://security-tracker.debian.org/tracker/DLA-4918-1) |
| Debian 13 trixie | `1.26.3-3+deb13u11` | [DSA-6642-1](https://security-tracker.debian.org/tracker/DSA-6642-1) |
| Debian sid | `1.30.6-4` | — |
| Debian testing/forky | `1.30.6-3` ещё уязвим (на 20.11.2026) | ждать `1.30.6-4` |

В bookworm нет HTTP/3, поэтому `CVE-2026-121810` к 1.22.1 не применима.
Для nginx.org-пакетов (`1.30.7-1~bookworm`, `1.31.8-1~bookworm`) вердикт
считается по upstream-версии, иначе `1.31.8` ошибочно выглядел бы «новее»
Debian-исправления `1.22.1`.

### Ubuntu

Ubuntu закрыла nginx2root в [USN-9159-1](https://usn.ubuntu.com/USN-9159-1)
(19.11.2026). Версии пакетов:

| Релиз | Исправленный пакет |
|---|---|
| 26.10 stonking | `1.30.4-7ubuntu1.2` |
| 26.04 LTS resolute | `1.28.3-2ubuntu1.13` |
| 24.04 LTS noble | `1.24.0-2ubuntu7.20` |
| 22.04 LTS jammy | `1.18.0-6ubuntu14.23` |
| 20.04 LTS focal | `1.18.0-0ubuntu1.7+esm5` (Ubuntu Pro) |
| 18.04 LTS bionic | `1.14.0-0ubuntu1.11+esm6` (Ubuntu Pro) |
| 16.04 LTS xenial | `1.10.3-0ubuntu0.16.04.5+esm11` (Ubuntu Pro) |
| 14.04 LTS trusty | `1.4.6-1ubuntu3.9+esm10` (Ubuntu Pro; 123007 не применима) |

`CVE-2026-121810` исправлена только в 26.04/26.10 — в 1.18/1.24 нет HTTP/3.
Для старых выпусков нужен действующий Ubuntu Pro/ESM.

Ubuntu отдельно отмечает, что в старых 1.14/1.18 существует аналогичный
cleartext HTTP/2 путь для `CVE-2026-123633`; чекер ориентируется на
официальный диапазон nginx.org (1.19.7+), поэтому при `listen ... http2`
без `ssl` сверяйтесь с USN-9159-1.

### RHEL, CentOS, AlmaLinux, Rocky, Oracle Linux, Amazon Linux

| Система | Исправленный пакет | Advisory |
|---|---|---|
| RHEL 9, nginx 1.20.1 | `1.20.1-32.el9_9.2` | RHSA-2026:100748 |
| CentOS Stream 9 | на 20.11.2026 фикса нет: в c9s `1.20.1-32` | ждать RHEL-сборку |
| CentOS Stream 10 | на 20.11.2026 фикса нет: в c10s `1.26.3` | ждать RHEL-сборку |
| CentOS Linux 7/8 | EOL | официальных фиксов нет |
| RHEL 9, nginx:1.26 | `1.26.3-10.module+el9.9.0+25360+9b756829.4` | RHSA-2026:100745 |
| RHEL 9, nginx:1.24 | `1.24.0-9.module+el9.9.0+25361+10e8035d.4` | RHSA-2026:100746 |
| RHEL 9 EUS, nginx:1.24 | `1.24.0-7.module+el9.8.0+25374+40bd8b35.7` | RHSA-2026:100750 |
| RHEL 8, nginx:1.24 | `1.24.0-3.module+el8.10.0+25364+53b7037a.9` | RHSA-2026:100747 |
| AlmaLinux 9 | `1.20.1-32.el9_9.1.alma.3` | [ALSA-2026:A025](https://errata.almalinux.org/9/ALSA-2026-A025.html) |
| AlmaLinux 10 | `1.26.3-16.el10_3.1.alma.2` | [ALSA-2026:A024](https://errata.almalinux.org/10/ALSA-2026-A024.html) |
| Oracle Linux 9, nginx:1.26 | `1.26.3-10.0.2.module+el9.9.0+91132+a75313dd.1` | [ELSA-2026-500648](https://linux.oracle.com/errata/ELSA-2026-500648.html) |
| Oracle Linux 10 | `1.26.3-16.0.1.el10_3.3` | [ELSA-2026-100744](https://linux.oracle.com/errata/ELSA-2026-100744.html) |
| Amazon Linux 2023 | `1.30.7-1.amzn2023.0.1` | ALAS2023-2026-3494 |
| Amazon Linux 2 (Nginx1 Extra) | `1.30.7-1.amzn2.0.1` | ALAS2NGINX1-2026-018 |
| Rocky Linux | проверяйте `rpm -q --changelog nginx` | отдельный advisory на 20.11.2026 не подтверждён |

CentOS Stream 9/10 — rolling-превью RHEL: фикс приходит вместе с RHEL-сборкой.
На 20.11.2026 в c9s/c10s ещё не было changelog-записи с `CVE-2026-123007`;
проверяйте `rpm -q --changelog nginx`. CentOS Linux 7/8 не получают
официальных обновлений — только сторонний extended support (например, TuxCare)
или миграция.

Важно: разные advisory закрывают разный набор CVE. Например, AlmaLinux 9
в A025 указывает только `CVE-2026-123007` и `CVE-2026-123633`; если changelog
пакета не содержит остальные CVE, они останутся в статусе `VULNERABLE`.

### Alpine

| Ветка | Исправленный пакет |
|---|---|
| edge, 3.24 | `1.30.7-r0` |
| 3.23, 3.22 | `1.28.3-r8` |
| 3.21 | `1.26.3-r4` |

### SUSE

| Продукт | Исправленный пакет | Статус на 19.11.2026 |
|---|---|---|
| openSUSE Tumbleweed | `1.31.9-1.1` | выпущен |
| SLES 15 SP4/SP5 LTSS | `1.21.5-150400.3.28.1` | в QA |
| SLES 15 SP6/SP7 | `1.21.5-150600.10.30.1` | в QA |
| SLES 16, openSUSE Leap 16 | ожидается | проверяйте SUSE CVE page |

### Fedora

На 20.11.2026 в стабильных Fedora 43/44/45 был `nginx 1.30.6-2` — это ещё
**уязвимая** версия (нужен 1.30.7). Проверяйте `dnf update nginx` и
`rpm -q --changelog nginx`: чекер ищет в changelog конкретные CVE.

### Arch Linux и FreeBSD

- Arch: `nginx 1.30.7-1` (сборка 18.11.2026).
- FreeBSD: обновление порта `www/nginx` до 1.30.7/1.31.9; `pkg` показывает
  установленную версию, чекер сравнивает её с upstream.

### nginx.org

Официальные релизы: **1.30.7 stable** и **1.31.9 mainline**. Пакеты nginx.org
для дистрибутивов (например, `1.30.7-1~bookworm`) проверяются по upstream-версии.

### Пример

```
OK: nginx 1.22.1
  Пакет: nginx 1.22.1-9+deb12u11 (bookworm) — исправлено; исправление: 1.22.1-9+deb12u11 (DLA-4918-1) [dpkg]
```

Удалённо версию пакета не видно: сайт отдаёт только `Server: nginx/1.22.1`.
URL-режим честно покажет `VULNERABLE` и подскажет проверить пакет локально.

На nginx 1.22.1 из Debian 12 директивы `http2 off;` ещё нет. Если нужно
временно отключить HTTP/2 до установки патча, уберите параметр `http2`
из соответствующих `listen`-директив.

## Уязвимые версии

Официальные данные [nginx.org](https://nginx.org/en/security_advisories.html):
исправлены в **1.30.7 (stable)** и **1.31.9 (mainline)**.

| CVE | Что нужно | Уязвимые версии | Закрывается выключением HTTP/2? |
|---|---|---|---|
| CVE-2026-123007 | HTTP/2 включён | 1.9.5 – 1.31.8 | Да |
| CVE-2026-123634 | `resolver` + `proxy_pass` с переменной + subrequest (`mirror`/SSI) | 0.6.18 – 1.31.8 | Нет |
| CVE-2026-123633 | HTTP/2 + forwarding на upstream | 1.19.7 – 1.31.8 | Да |
| CVE-2026-121810 | HTTP/3 + forwarding на upstream | 1.25.0 – 1.31.8 | Нет |
| CVE-2026-113425 | mail proxy с `proxy on` и `auth_http` | 0.5.33 – 1.31.8 | Нет |

Для CVE-2026-123634 одного `mirror off` недостаточно: Xint отмечает,
что другие subrequest-механизмы (например, SSI) могут вести к тому же
use-after-free. Надёжнее заменить `proxy_pass` с переменной на фиксированный
`upstream`.

## SCTP и root

Пять уязвимостей nginx дают выполнение команд с правами worker'а.
Xint показал цепочку с отдельной уязвимостью SCTP в ядре Linux
(появилась в 4.15), которая повышает права до root и, в тестах Xint,
позволяет выйти из Docker-контейнера на хост. Отдельный CVE для этой
уязвимости Xint не называет; на момент раскрытия (18.11.2026) патча
ядра ещё не было — следите за обновлениями ядра.

Если SCTP не используется, заблокируйте модуль:

```bash
echo 'install sctp /bin/false' | sudo tee /etc/modprobe.d/disable-sctp.conf
```

`blacklist sctp` сам по себе не мешает явной загрузке через `modprobe`.
Чекер в `--local` показывает состояние SCTP, но **не меняет код возврата**:
это дополнительная рекомендация, а не вердикт по nginx2root.

## Коды возврата

| Код | Статус | Значение |
|---|---|---|
| 0 | `OK` | Версия/пакет исправлены |
| 1 | `VULNERABLE` | Версия в уязвимом диапазоне (с учётом пакета ОС в `--local`) |
| 3 | `UNKNOWN` | Версия не определена: скрытый `Server`, CDN, сетевая ошибка, неизвестный пакет |
| 2 | — | Ошибка аргументов командной строки |

Для `--file` коды агрегируются: `1` важнее `3`, `3` важнее `0`.

## JSON

Одиночная проверка:

```json
{
  "patch_status": "vulnerable",
  "nginx_version": "1.31.8",
  "server": "nginx/1.31.8",
  "http2": true,
  "http3_advertised": false,
  "reason": "nginx 1.31.8",
  "exit_code": 1,
  "cves": [
    {
      "cve": "CVE-2026-123007",
      "title": "переполнение в HTTP/2 flow control",
      "version_status": "vulnerable",
      "exposure": "exposed",
      "detail": "сервер согласовал HTTP/2 по ALPN (h2)"
    }
  ]
}
```

В `--local` добавляются `build`, `config`, `package`, `advisories`.
В `package` есть `status` (`fixed`/`partial`/`vulnerable`/`unknown`),
`source` (`dpkg`, `rpm-changelog`, `apk`, `pacman`, `pkg`, `upstream`)
и `fixed_cves` — какие именно CVE закрыл пакет.
В `--file --json` каждый результат — отдельная JSON-строка (JSON Lines)
с полем `url`.

## Ограничения

- URL-режим видит только заголовок `Server`. При `server_tokens off`,
  CDN/WAF или другом фронтенде версия будет `UNKNOWN` — это не значит
  «безопасно».
- ALPN показывает согласование `h2`, но не доказывает, что HTTP/2 включён
  в конкретном `server`-блоке. `Alt-Svc` с `h3` — признак HTTP/3, но его
  отсутствие не доказывает, что QUIC-листенера нет.
- Удалённо не видны `resolver`, `proxy_pass` с переменной, `mirror`,
  upstream и mail-блок. Поэтому для CVE-2026-123634, CVE-2026-123633,
  CVE-2026-121810 и CVE-2026-113425 URL-режим часто даёт `UNKNOWN`
  или `POSSIBLE`.
- `--local` разбирает конфигурацию эвристически. `nginx -T` показывает
  итоговый конфиг, включая `include`, но без root его прочитать нельзя.
- Сравнение пакетов актуально на **20.11.2026**. Для Debian/Ubuntu
  используется `dpkg` и таблица исправленных версий; для RPM-систем —
  `rpm -q --changelog` (если changelog не вырезан в сборке); для Alpine —
  таблица веток; для Arch/FreeBSD — upstream-версия. Неучтённый бэкпорт
  может дать ложный `VULNERABLE`; сверяйтесь с advisory вендора.
- Разные advisory закрывают разный набор CVE. Если пакет исправлен
  частично, чекер покажет «исправлено частично» и оставит незакрытые CVE
  в статусе `VULNERABLE`.
- SUSE SLES 15-пакеты на 19.11.2026 были в QA; до установки такой версии
  чекер считает систему уязвимой.
- Чекер не выполняет эксплуатацию и не подтверждает наличие фикса в
  конкретном бинарнике — только оценивает версию, пакет и конфигурацию.

## Источники

- [nginx.org — security advisories](https://nginx.org/en/security_advisories.html)
- [Xint — NGINX2Root](https://xint.io/blog/nginx2root-remote-code-execution)
- [Wiz — nginx HTTP/2 RCE](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities)
- [Debian Security Tracker — CVE-2026-123007](https://security-tracker.debian.org/tracker/CVE-2026-123007)
- [DSA-6642-1](https://security-tracker.debian.org/tracker/DSA-6642-1)
- [DLA-4918-1](https://security-tracker.debian.org/tracker/DLA-4918-1)
- [Ubuntu USN-9159-1](https://usn.ubuntu.com/USN-9159-1)
- [Red Hat CVE-2026-123007](https://access.redhat.com/security/cve/cve-2026-123007)
- [CentOS Stream nginx spec (c9s/c10s)](https://gitlab.com/redhat/centos-stream/rpms/nginx)
- [AlmaLinux ALSA-2026:A025](https://errata.almalinux.org/9/ALSA-2026-A025.html)
- [AlmaLinux ALSA-2026:A024](https://errata.almalinux.org/10/ALSA-2026-A024.html)
- [Oracle Linux ELSA-2026-500648](https://linux.oracle.com/errata/ELSA-2026-500648.html)
- [Oracle Linux ELSA-2026-100744](https://linux.oracle.com/errata/ELSA-2026-100744.html)
- [Amazon Linux ALAS2NGINX1-2026-018](https://alas.aws.amazon.com/AL2/ALAS2NGINX1-2026-018.html)
- [Alpine secdb — CVE-2026-123007](https://security.alpinelinux.org/vuln/CVE-2026-123007)
- [SUSE CVE-2026-123007](https://www.suse.com/security/cve/CVE-2026-123007.html)
- [Arch Linux nginx package](https://archlinux.org/packages/extra/x86_64/nginx/)
- [Equixly — nginx2root](https://equixly.com/blog/2026/11/18/nginx2root-disabling-http-2-stops-two-of-five-nginx-rce-flaws/)

## Лицензия

Apache License 2.0, см. [LICENSE](LICENSE).
