# Моніторинг: метрики, дашборд, алерти

Документ описує метрики Prometheus, які експортує `radius-server`
(`prometheus.path`, за замовчуванням `/metrics`, порт `prometheus.port`,
див. `server/radius.server.conf.yml`), готовий дашборд для Grafana і
рекомендовані правила алертів.

- Дашборд: [`grafana-dashboard.json`](grafana-dashboard.json)
- Правила алертів (Prometheus/Alertmanager): [`alerts.yml`](alerts.yml)

## 1. Довідник метрик

### Запити RADIUS

| Метрика | Тип | Мітки | Опис |
|---|---|---|---|
| `rad_request_count` | counter | `host` | Кількість запитів від NAS |
| `rad_request_ip_count` | counter | `host` | Кількість відповідей з конкретним `ip_address` |
| `rad_request_pool_count` | counter | `host` | Кількість відповідей з `pool_name` |
| `rad_request_by_pool_count` | counter | `host`, `pool_name` | Кількість запитів у розрізі конкретного пула |
| `rad_acct_requests_count` | counter | `host`, `server_name` | Кількість Accounting-Request |
| `rad_mac_server_count` | counter | `host`, `mac`, `server_name`, `response_type` | Деталізація по мак-адресі абонента. Вмикається `prometheus.detailed: true` - **обережно**, необмежено росте в пам'яті процесу, у продакшн-навантаженні дає ріст RSS до кількох ГБ/год (див. `doc/LOAD_TESTING.md`) |

### Помилки

| Метрика | Тип | Мітки | Опис |
|---|---|---|---|
| `rad_critical_count` | counter | `caller` | Критичні помилки (запит лишається без відповіді - таймаут на NAS) |
| `rad_errors_count` | counter | `caller` | Помилки нижчого рівня (наприклад, не вдалось виставити один атрибут у відповіді) |
| `rad_warnings_count` | counter | `caller` | Попередження |

### ClientDB (`processor: script`)

| Метрика | Тип | Мітки | Опис |
|---|---|---|---|
| `rad_clientdb_devices_count` | gauge | - | Кількість пристроїв (`db.devices`), завантажених останнім reload |
| `rad_clientdb_binds_count` | gauge | `source` | Кількість прив'язок (`db.binds.<source>`), завантажених останнім reload |
| `rad_clientdb_last_reload_timestamp_seconds` | gauge | - | Unix-час останнього **успішного** reload по HTTP |
| `rad_clientdb_redis_connected` | gauge | - | Стан з'єднання з Redis для live-оновлень binds: `1` - підключено, `0` - ні. Присутня в `/metrics` лише якщо `script.database.redis.addr` заданий |
| `rad_clientdb_live_update_received_count` | counter | `db_type` | Кількість live-оновлень, отриманих з Redis (див. [`REDIS_BIND_EVENTS.md`](REDIS_BIND_EVENTS.md)) |
| `rad_clientdb_live_update_errors_count` | counter | `db_type` | Кількість live-оновлень, які не вдалось застосувати (невалідний json, невідомий `db_type`/`action`, відсутні обов'язкові поля) |
| `rad_clientdb_live_update_last_timestamp_seconds` | gauge | - | Unix-час останнього отриманого live-оновлення (незалежно від того, застосувалось воно успішно чи ні) |

> `rad_clientdb_redis_connected` рахується окремим періодичним `PING` до
> Redis (раз на 15с, див. `clientdb/redis.go:watchRedisConnection`), а не
> станом самої підписки - бібліотека `go-redis` перепідключає pub/sub
> внутрішньо і не віддає назовні момент розриву/відновлення з'єднання,
> тому пряме опитування - єдиний надійний спосіб побачити стан "зараз".

### API backend (`processor: api`)

| Метрика | Тип | Мітки | Опис |
|---|---|---|---|
| `rad_api_alive_status` | gauge | `api_addr` | `1` - адреса жива, `0` - виключена з ротації (`api.*.alive_checking`) |
| `rad_api_post_auth_queue_len` | gauge | - | Довжина черги відправки post-auth подій в API |
| `rad_api_acct_queue_len` | gauge | - | Довжина черги відправки acct-подій в API |
| `rad_cache_responses_count` | gauge | - | Кількість відповідей, що зараз лежать у кеші (`api.auth.caching`) |

### Службові

| Метрика | Тип | Мітки | Опис |
|---|---|---|---|
| `rad_sys_version` | counter | `version`, `build_date` | Версія процесу. Значення завжди `1` (інкрементується один раз при старті) - зростання лічильника за `changes()` означає рестарт процесу |

Плюс стандартні метрики `go_*` (горутини, `heap`, GC) і `process_*` (CPU,
RSS, файлові дескриптори) від `promhttp`/`client_golang`.

## 2. Дашборд Grafana

Файл [`grafana-dashboard.json`](grafana-dashboard.json) - готова модель
дашборда, імпортується напряму: Grafana → Dashboards → New → Import →
Upload JSON file. При імпорті буде запропоновано вибрати Prometheus
datasource (змінна `datasource`).

Змінна `host` (multi-select, за замовчуванням "All") фільтрує панелі,
пов'язані з конкретним NAS (`rad_request_count` і похідні).

Розділи дашборда:

1. **Overview** - версія сервера, сумарний RPS, critical-помилки/хв, вік
   останнього reload clientdb; графіки запитів по NAS, по типу відповіді
   (ip/pool), топ-10 пулів, помилки по рівнях і `caller`.
2. **ClientDB & live updates** - кількість пристроїв/прив'язок, стан
   з'єднання з Redis, вік останнього reload і останнього live-оновлення,
   темп live-оновлень і помилок по них.
3. **API backend** - живість API-адрес, довжина черг post_auth/acct,
   розмір кешу відповідей (актуально лише при `processor: api`).
4. **Process runtime** - горутини, heap, CPU.

## 3. Алерти

Файл [`alerts.yml`](alerts.yml) - готовий файл правил у форматі
Prometheus rule file (`rule_files:` в `prometheus.yml`), доставляється в
Alertmanager стандартним шляхом Prometheus alerting.

Підключення в `prometheus.yml`:

```yaml
rule_files:
  - /etc/prometheus/rules/dhcp-radius-server-alerts.yml
```

Коротко про правила (деталі й точні вирази - у самому файлі):

| Алерт | Severity | Суть |
|---|---|---|
| `RadiusNoRequests` | critical | Немає жодного запиту 5 хвилин - сервер не слухає/недоступний для NAS |
| `RadiusCriticalErrorsHigh` | critical | Понад 5 CRITICAL-помилок/хв протягом 5 хвилин |
| `RadiusErrorsElevated` | warning | Підвищений рівень ERROR протягом 10 хвилин |
| `RadiusNoSuccessfulResponses` | critical | Запити є, але жоден не завершується видачею IP/пула |
| `ClientDBReloadStale` | critical | clientdb не оновлювалась понад 15 хв (типовий `refresh_interval` - 5 хв) |
| `ClientDBEmpty` | critical | `rad_clientdb_devices_count == 0` - авторизація по option82 неможлива |
| `ClientDBRedisDisconnected` | warning | Втрачено з'єднання з Redis - live-оновлення не застосовуються (reload по HTTP далі працює) |
| `ClientDBLiveUpdateStale` | warning | З'єднання є, але live-оновлень немає понад годину |
| `ClientDBLiveUpdateErrorsHigh` | warning | Багато live-оновлень не застосовується - проблема у форматі повідомлень зовнішньої системи |
| `RadiusAPIAddressDown` | critical | Адреса API недоступна понад 3 хв (`processor: api`) |
| `RadiusAPIQueueGrowing` | warning | Черга post_auth/acct до API не розбирається |
| `RadiusProcessRestarted` | info | Процес перезапустився |
| `RadiusGoroutinesHigh` | warning | Аномальна кількість горутин - можливий leak |

`ClientDBRedisDisconnected`/`ClientDBLiveUpdateStale` мають сенс лише при
налаштованому `script.database.redis.addr` - якщо Redis не
використовується, метрика `rad_clientdb_redis_connected` взагалі
відсутня в `/metrics`, і правила на ній просто ніколи не спрацюють (не
потребують додаткового `unless`/`absent()`).
