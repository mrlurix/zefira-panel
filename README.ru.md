# Zefira

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-live-brightgreen)](https://mrlurix.github.io/zefira-panel/)
[![Pentest](https://img.shields.io/badge/pentest-129%2F129-success)](https://github.com/mrlurix/zefira-panel/blob/main/attack_test.py)

> 🌐 **Языки:** [English](README.md) · [فارسی](README.fa.md) · [中文](README.zh.md) · **Русский**

> 📚 **Документация: [mrlurix.github.io/zefira-panel](https://mrlurix.github.io/zefira-panel/)** — руководство по установке, руководство пользователя, справочник API, частые вопросы.

Простая панель для управления и продажи VPN-аккаунтов. Начиналась как личный инструмент для моих серверов, затем была приведена в вид, пригодный для публичного использования.

Работает с VLESS, VLESS-REALITY, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard, OpenVPN, L2TP/IPsec, Cisco AnyConnect и SOCKS5. Один пользователь может иметь сразу несколько протоколов и получает **одну** ссылку подписки.

Сделано на FastAPI + SQLite. Docker не нужен, достаточно Python.

### Скриншоты

![Вход](screenshots/screenshot-login.png)
![Панель](screenshots/screenshot-dashboard.png)
![Панель пользователя](screenshots/screenshot-user-dashboard.png)
![Настройки внешнего вида](screenshots/screenshot-appearance.png)

### Установка на сервер

Одной командой:

```bash
curl -fsSL https://raw.githubusercontent.com/mrlurix/zefira-panel/main/install.sh | sudo bash
```

Предпочитаете сначала прочитать? Скачайте, посмотрите, и запустите **именно эту** копию:

```bash
d="$(mktemp -d)"                       # приватный каталог, читаемый только вами
curl -fsSL -o "$d/install.sh" \
  https://raw.githubusercontent.com/mrlurix/zefira-panel/v1.15.55/install.sh
less "$d/install.sh"
sudo bash "$d/install.sh"
rm -rf "$d"
```

> Оба способа работают. Однострочный вариант передаёт всё, что upstream отдаёт в этот момент, прямо в корневую оболочку, поэтому если вам важно, **какой** код выполняется от root, используйте второй: он попадает в каталог, который `mktemp` только что создал для вас (фиксированный `/tmp/zefira-inst` мог быть заранее создан другим локальным пользователем, а `mkdir -p` молча succeeds на каталоге, которым он не владеет), а тег `v1.15.55` фиксирует сам установщик.
>
> Затем установщик клонирует исходники панели по тегу релиза, который идёт с ним. Если нужно жёстче — указать точный коммит:
>
> ```bash
> ZEFIRA_EXPECTED_SHA=<коммит из 40 символов> sudo bash install.sh
> ```
>
> Отклоняется, если клон не этот коммит. `ZEFIRA_INSTALL_REF=main` возвращает прежнее поведение «следить за веткой». Установщик также отказывается использовать сам `/opt/zefira` как источник: это дерево доступно служебной учётной записи, и доверие к нему передало бы служебный плацдарм root'у.

Скрипт ставит зависимости Python, создаёт службу systemd и сохраняет учётные данные первого входа в `instance/first-run-credentials.txt` (права 600) — прочитайте через `sudo cat` и удалите после первого входа. Работает на Ubuntu / Debian / Alma / Rocky (нужен Python 3.10+).

С включённой опцией nginx панель слушает только `127.0.0.1`, и файрвол открывает лишь 80/443; без неё панель отвечает обычным HTTP на выбранном порту, поэтому поставьте TLS перед ней, прежде чем заводить реальные аккаунты.

Удаление: `sudo bash install.sh --uninstall`

### Ручная установка

```bash
git clone https://github.com/mrlurix/zefira-panel.git
cd zefira-panel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header --no-proxy-headers
```

Слушайте на `127.0.0.1` и поставьте перед ним обратный прокси с TLS. `--host 0.0.0.0` публикует вход администратора открытым текстом (без Secure cookie, без HSTS).

Первый запуск записывает имя пользователя и пароль администратора в `instance/first-run-credentials.txt` (права 600) и печатает только путь. Если до старта задан `ZEFIRA_ADMIN_PASSWORD`, используется он.

> **Запускайте ровно один worker.** Лимитеры, блокировки восстановления/обновления, цикл наблюдения за узлами и кэш настроек живут в памяти процесса: `--workers N` умножает бюджеты лимитеров и перемешивает восстановления. Масштабируйтесь машинами, а не worker'ами.
>
> Это **проверяется**, а не просто рекомендуется: панель читает `WEB_CONCURRENCY` при запуске и **отказывается стартовать** с числом больше одного, называя, что именно сломается. Если вы действительно вынесли это состояние в общее хранилище, `ZEFIRA_ALLOW_MULTI_WORKER=1` подтверждает это — и пишет предупреждение, что без общих лимитеров панель ничем не защищена.

Вход по умолчанию: `http://YOUR_SERVER_IP:8000`

### Что вы получаете

- Пользователи с лимитом трафика, сроком действия и заметками. Поддерживается start-on-first-use, если хотите, чтобы отсчёт начинался только после первого подключения. Карандаш в каждой строке редактирует заметку, объём, срок и лимит устройств.
- Несколько протоколов на пользователя, все в одной подписке. Поддерживаются обычные base64-подписки и Clash YAML (`?format=clash`). В имени ссылки показывается простой логин.
- **Лента подписки несёт только share-ссылки и ничего больше.** `WireGuard`, `OpenVPN`, `L2TP/IPsec` и `Cisco AnyConnect` — файловые протоколы: `.conf`/`.ovpn` не является URI, поэтому никакой импортёр ссылок его не прочитает, — и они выдаются файлами: карточка на панели, кнопка **Download config** у пользователя или ZIP. Поэтому тариф, состоящий *только* из файловых протоколов, нечего перечислять, и лента отвечает `422` с этим объяснением вместо страницы текста, который клиент разобрать не может. До v1.15.8 эти файлы встраивались в ленту под заголовком `### OpenVPN ###`; клиент пропускал ровно одну строку, начинающуюся с `#`, а остальные ~90 получал как узлы.
- Панель в браузере: открытая в браузере ссылка подписки показывает расход трафика, ссылки, QR и приложения; VPN-клиенты всегда получают сырые байты.
- Inbounds: задавайте дополнительные порты/хосты для каждого протокола, и каждый пользователь получит ссылки на все них. Inbounds можно закрепить за серверными узлами — офлайн-узлы автоматически исключаются из ссылок.
- Серверные узлы: регистрируйте удалённые серверы с проверкой здоровья раз в 5 минут, задержкой и аптаймом; проверка по требованию, включение/отключение, безопасное удаление.
- Обход цензуры: ключи REALITY генерируются внутри панели, ссылки используют `xtls-rprx-vision` и автоматически ротируют SNI.
- Туннельные узлы BackPack: создавайте туннели для серверов в Иране и за рубежом, скачивайте руководство с уже подставленным токеном и проверяйте, доступна ли иранская сторона. Панель закреплена на BackPack **v1.8.5** и выставляет его новые возможности настоящими полями: **лимит трафика** на каждый туннель, **расписание перезапуска** для обоих концов, **резервные адреса**, которые перехватывают трафик, когда хост в Иране перестаёт отвечать, и **пресет производительности** (`turbo` / `aggressive` / `conservative` / `custom`). У каждого туннеля также свой **SNI** для carrier подмены.
- QR-код для каждой подписки, скачивание конфигов в ZIP.
- Пузырь ИИ-ассистента: помощник только внутри панели (сначала Groq, также OpenAI/Anthropic/Gemini/Ollama) для новичков.
- Обновление в один клик из GitHub с предпросмотром changelog прямо в панели.
- **Developer API**: токены со скоупами (`zfp_…` bearer) для Telegram-ботов и дашбордов — заголовок CSRF не нужен. Скоупы: `full` или минимальный `bot` (только список и создание пользователей). Раздел Developer API внутри панели показывает ваши токены, создаёт новый и выдаёт готовый к запуску пример.
- Полная персонализация: цвета темы, название бренда, сообщение на панели — плюс **раскладка меню**, которую можно переставлять и укорачивать (Dashboard, Users, Inbounds, Personalize и Settings остаются всегда), и показ/скрытие каждой карточки на самой панели клиента.
- Сильный пароль на чувствительных действиях, полный журнал аудита, статистика системы, уведомления в Telegram по желанию.
- Резервное копирование и восстановление в JSON (оба с подтверждением паролем), опционально зашифрованные бэкапы. Также импорт и экспорт всех настроек.
- Работает как непривилегированный системный пользователь `zefira` (никогда root); квота трафика применяется к подпискам.

Полные руководства — на сайте документации (ссылка вверху).

### Настройки, которые стоит поменять

Большее есть в самой панели: **Settings -> Server / Hosts Settings** (домен, порты, DNS, настройки REALITY) и **Settings -> Remote Access** (публичный URL, доверенные прокси).

Если предпочитаете env-файлы, скопируйте `.env.example` в `.env`. Переменные окружения используются только как значения по умолчанию при первом запуске.

### Безопасность

Я старался держать её жёстко: scrypt для паролей, JWT в HttpOnly-куках, ограничение частоты входа (по исходному IP, проверяется до любого хеширования), проверка CSRF, строгий CSP, параметризованные запросы, никакого innerHTML для пользовательских данных и журнал аудита.

**Что зашифровано:** учётные данные Telegram/AI, ключи хостов REALITY и WireGuard, токены туннелей и зашифрованные бэкапы (AES/Fernet с `instance/secret.key`). **Что не зашифровано:** учётные данные VPN каждого клиента в базе (`secret_data`) — это обычный JSON в `instance/zefira.db` и в незашифрованном бэкапе, намеренно, чтобы панель могла перестраивать ссылки без цикла расшифровки. Относитесь к базе и незашифрованным бэкапам как к учётным данным клиентов: держите `instance/` на `700`, используйте зашифрованные бэкапы или полнодисковое шифрование и прочитайте [SECURITY.md](SECURITY.md).

### Запуск тестов

Эти наборы бьют по работающей панели снаружи. Запустите панель, затем выполняйте их по одному (перезапуская панель между наборами). Либо все сразу: `python run_all_tests.py admin YOURPASS`. Наборы не зависят от порядка и в конце возвращают панель к заводским настройкам.
Всего 61 набор тестов: 17 онлайн (нужна работающая панель) и 44 статических (ничего не нужно).


**Онлайн-наборы** — требуют работающей панели:

```bash
python security_test.py      http://127.0.0.1:8000 admin YOURPASS  # злоупотребления/защита
python functional_test.py    http://127.0.0.1:8000 admin YOURPASS  # сквозные сценарии
python feature_test.py       http://127.0.0.1:8000 admin YOURPASS  # покрытие возможностей
python attack_test.py        http://127.0.0.1:8000 admin YOURPASS  # живые атаки
python attack_quota_test.py  http://127.0.0.1:8000 admin YOURPASS  # границы квот/схемы
python attack_paths_test.py  http://127.0.0.1:8000 admin YOURPASS  # пути оператора
python frontend_bugs_test.py http://127.0.0.1:8000 admin YOURPASS  # регрессии фронтенда
python panel_sections_test.py http://127.0.0.1:8000 admin YOURPASS  # разделы панели
python security_audit_test.py http://127.0.0.1:8000 admin YOURPASS
python mcp_routes_test.py      http://127.0.0.1:8000 admin YOURPASS   # the MCP panel routes, end to end
python mcp_conformance_test.py http://127.0.0.1:8000 admin YOURPASS   # MCP conformance, real SDK, both transports  # аудит безопасности
python settings_cards_test.py http://127.0.0.1:8000 admin YOURPASS  # каждая карточка настроек, сквозным образом
```

`feature_test.py` обходит возможности панели раздел за разделом и утверждает, что каждая возможность **действительно работает** (реальные ссылки в подписке, декодируемый QR, рабочий архив конфигов, матрица scope бота, циклы бэкап/восстановление…), а не просто доступна. `attack_test.py` сам выпускает враждебный трафик: подмена заголовков, сохранённый XSS, обход пути, чрезмерно большие и глубоко вложенные тела, трюки с Unicode/кодировкой, timing oracle, лавина входов, попытки вытеснить ограничитель и полная матрица аутентификации.

**Без сервера (наборы на Python)** — выполняют поставляемый код, а не читают его, потому что каждый дефект ниже прошёл ревью на уровне исходников:

```bash
python installer_test.py          # гарантии установщика, статическими проверками
python dashboard_link_test.py     # ссылка панели клиента при установке с угаданным доменом
python proxy_trust_test.py        # доверие прокси и согласованность client IP
python link_encoding_test.py      # кодирование имени в share-ссылке
python update_guard_test.py       # защита обновления от подмены runtime-состояния
python migration_guard_test.py    # шаги миграции схемы, каждый в своей транзакции
python env_symlink_guard_test.py  # запись .env установщиком через симлинк
python bump_assets_guard_test.py  # входные данные обновления версии ресурсов
python i18n_test.py               # шаблоны и JS панели против всех локалей
python docs_coverage_test.py      # каждый эндпоинт, раздел и настройка задокументированы
python secret_at_rest_test.py  # секреты клиентов зашифрованы на диске
python security_hardening_test.py  # усиление аудита: бюджет раскрытия секретов, fail-closed scope
python subscription_token_test.py  # токен подписки не читается с диска
python installer_unit_test.py  # безопасность heredoc в установщике
python installer_guard_test.py  # guards симлинка и баннера установщика
python api_scope_test.py  # контроль scope у API-токена
python api_coverage_test.py  # справочник API покрывает все маршруты
python settings_guard_test.py  # guards настроек и загрузки
python restore_guard_test.py  # guards восстановления, снапшотов и лимита токенов
python telegram_hint_test.py  # подсказки об ошибках Telegram
python operability_test.py  # отказ от нескольких worker, связь запросов, покрытие аннотациями
python settings_groups_test.py  # настройки сгруппированы, ничего не потеряно
python release_notes_test.py  # заметки о релизе не устарели
python readme_i18n_test.py  # согласованность переводов README
python harness_login_test.py  # тестовая обвязка доходит до админа
python update_status_latency_test.py                  # страница обновления не ждёт GitHub
python backpack_tunnel_test.py               # возможности туннеля BackPack v1.8.5
python ai_url_guard_test.py                 # URL запроса к ИИ совпадает с проверенным базовым адресом
python reliability_guards_test.py   # the defects an agent sweep found stay fixed
python migration_run_test.py       # the migration list, executed
python security_doc_test.py              # the security policy states no coverage figure
```

**Без сервера (2 скрипта Node)** — для четырёх языков сайта документации:

```bash
node i18n_dict_check.js           # словари документации, загруженные и проверенные
node i18n_render_check.js
python audit_retention_test.py                       # audit retention figure matches the code
python type_hints_test.py                              # type annotations do not regress
python menu_order_test.py                               # the three menu orders agree
python api_response_shapes_test.py                  # API reference matches reality (live)
python logging_format_test.py                       # the log format, plain and JSON
python key_loss_test.py                            # a missing master key cannot be silent
python restore_report_test.py                       # the restore report says what was lost
python mcp_client_ip_test.py                       # an MCP call is attributed to its caller
python client_ip_test.py                            # who a request is counted as
python mcp_tools_test.py                                 # the MCP tool table
python mcp_docs_test.py                              # the MCP tool table in the reference
python mcp_exec_test.py                                  # MCP call building and the HTTP executor
python mcp_asgi_exec_test.py                             # the in-panel MCP executor
python mcp_protocol_test.py                              # MCP JSON-RPC dispatch
python mcp_stdio_test.py                                 # the MCP stdio transport
python mcp_guards_test.py                                # MCP bug-hunt regression guards         # рендерер документации с враждебными строками
```

`i18n_dict_check.js` существует потому, что документация на четырёх языках должна оставаться согласованной, а проверял это никто. Он загружает `docs/assets/i18n.js`, читает тот объект, который получит браузер, и падает при ключе, отсутствующем или пустом в каком-либо языке, при значении, в котором склеились две записи, при мусорной кодировке, при `data-i18n`, написанном не так, как его читает `applyI18n`, и при странице, ссылающейся на ключ, которого нет ни в одном языке. О **совпадающих с английским** значениях он сообщает, но не падает, потому что это иногда верно: `GitHub Security Advisories` — собственное название функции GitHub.

После правки чего-либо под `docs/` запустите `python docs/build_index.py`. Она перестраивает индекс поиска, даёт каждому заголовку устойчивый якорь и **сама** поднимает счётчик сброса кэша через `docs/bump_assets.py`. Последнее не косметика: счётчик живёт в четырнадцати местах, и если поднять его только на двенадцати страницах, `docs.js` и `support-ai.js` продолжат запрашивать **предыдущие** `search-index.json` и `site-knowledge.json` — свежий HTML, устаревшие результаты поиска и бот поддержки, отвечающий по базе знаний прошлой недели.

Количество проверок в каждом наборе **намеренно не** указано: оно меняется с каждой новой проверкой, а устаревшее число хуже отсутствия числа, потому что выглядит как то, с чем можно сравнивать. Читайте его из самого прогона — каждый набор печатает `N/N checks passed`.

### Зависимости

`requirements.txt` хранит поддерживаемые вручную **прямые** закрепления (то, что вы обновляете намеренно). `requirements.lock` — полностью разрешённый и **закреплённый по хешам** набор, который на самом деле устанавливают `install.sh` и обновление внутри панели:

```bash
pip install --require-hashes --no-deps -r requirements.lock
```

Точные закрепления верхнего уровня никогда не закрепляли транзитивный граф: один только `uvicorn[standard]` тянет дюжину диапазонов версий, поэтому две установки одного и того же `requirements.txt` могли выполнить разный код. После правки `requirements.txt` пересоберите закрепление, затем проверьте его:

```bash
python tools_lock.py
python verify_lock_hashes.py
```

> **Всегда запускайте проверку.** Закрепление собирается на одной машине и ставится на другой, а хеш, покрывающий только платформу машины-сборщика, обрывает установку на сервере — или, что хуже, оставляет закрепление, которое ничего не проверяет. Более ранняя версия `tools_lock.py` записывала только те артефакты, которые могла скачать локально, из-за чего 11 из 31 пакетов не устанавливались на Linux. `verify_lock_hashes.py` сверяет каждый записанный хеш с PyPI.

### API

Это обычный REST API, всё под `/api/*`. Полную таблицу смотрите на странице Docs внутри панели или откройте инструменты разработчика браузера, работая с панелью.

### Лицензия

MIT — см. [LICENSE](LICENSE). Делайте что хотите, только сохраните уведомление.

### Пожертвование

Если Zefira вам помогает, можно его поддержать: адреса кошельков на [странице пожертвований](https://mrlurix.github.io/zefira-panel/donate.html).

```text
TRX BEP-20:    0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18
ETH BEP-20:    0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18
USDC BEP-20:   0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18
```

---

Если понравилось, поставьте звезду. Issue и PR приветствуются.

[English](README.md) · [فارسی](README.fa.md) · [中文](README.zh.md) · **Русский**