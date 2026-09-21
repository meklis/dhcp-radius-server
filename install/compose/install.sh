#!/usr/bin/env bash
# Скачивает всё необходимое для запуска dhcp-radius-server через готовый образ
# из ghcr.io (docker-compose.yml, .env-example, config.yaml, примеры lua-скриптов) в
# отдельный каталог - без клонирования всего репозитория.
#
# Использование:
#   curl -fsSL https://raw.githubusercontent.com/meklis/dhcp-radius-server/master/install/compose/install.sh | bash
#   ./install.sh [ref] [target_dir]
#     ref        - ветка/тег репозитория, откуда качать файлы (по умолчанию master)
#     target_dir - каталог назначения (по умолчанию ./dhcp-radius-server)
set -euo pipefail

REF="${1:-master}"
TARGET_DIR="${2:-$(pwd)/dhcp-radius-server}"
REPO_RAW="https://raw.githubusercontent.com/meklis/dhcp-radius-server/${REF}"

mkdir -p "$TARGET_DIR/scripts"
cd "$TARGET_DIR"

echo "Скачиваю файлы (ref=${REF}) в ${TARGET_DIR} ..."

curl -fsSL "$REPO_RAW/install/compose/docker-compose.yml" -o docker-compose.yml
curl -fsSL "$REPO_RAW/install/compose/.env-example" -o .env-example
curl -fsSL "$REPO_RAW/script/examples/auth.lua" -o scripts/auth.lua
curl -fsSL "$REPO_RAW/script/examples/acct.lua" -o scripts/acct.lua
curl -fsSL "$REPO_RAW/script/examples/post_auth.lua" -o scripts/post_auth.lua

if [ ! -f config.yaml ]; then
	curl -fsSL "$REPO_RAW/server/radius.server.conf.yml" -o config.yaml
else
	curl -fsSL "$REPO_RAW/server/radius.server.conf.yml" -o config.yaml.dist
	echo "config.yaml уже существует, не перезаписываю - актуальная версия сохранена как config.yaml.dist для сверки."
fi

if [ ! -f .env ]; then
	cp .env-example .env
	echo "Создан .env из .env-example - обязательно отредактируйте его (минимум CLIENTDB_URL) перед запуском."
else
	echo ".env уже существует, не перезаписываю - при необходимости сверьте с .env-example вручную."
fi

cat <<EOF

Готово. Дальше:
  cd ${TARGET_DIR}
  \$EDITOR .env
  docker compose up -d
EOF
