### Швидкий запуск через готовий образ (ghcr.io)

На відміну від [../docker](../docker) (збирає образ з вихідного коду), цей спосіб
качає лише файли, потрібні для запуску - `docker-compose.yml`, `.env-example` і
приклади lua-скриптів - і використовує вже зібраний образ
`ghcr.io/meklis/dhcp-radius-server` (публікується автоматично при релізі, див.
`.github/workflows/build.yml`). Повне клонування репозиторію не потрібне.

0. Встановіть docker і docker compose
1. Запустіть інсталятор (за замовчуванням якір - `master`, каталог -
   `./dhcp-radius-server`):
   ```
   curl -fsSL https://raw.githubusercontent.com/meklis/dhcp-radius-server/master/install/compose/install.sh | bash
   ```
   Або з явним тегом релізу і каталогом:
   ```
   curl -fsSL .../install.sh -o install.sh && bash install.sh v0.3.3 /opt/dhcp-radius-server
   ```
2. Відредагуйте `.env` (створюється автоматично з `.env-example`) - обов'язково
   `CLIENTDB_URL`, за потреби `IMAGE_TAG` (тег образу, за замовчуванням `latest`)
3. За потреби відредагуйте власні скрипти в `./scripts` (`auth.lua`/`acct.lua`/
   `post_auth.lua`) - вони монтуються поверх `/opt/scripts` в контейнері
4. `docker compose up -d`

Повторний запуск `install.sh` оновлює `docker-compose.yml`, `.env-example` і
скрипти в `./scripts` до актуальної версії з репозиторію - існуючий `.env` не
перезаписується.
