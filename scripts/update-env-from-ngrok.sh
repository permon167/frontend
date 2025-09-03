#!/usr/bin/env bash
set -euo pipefail

echo "🔎 Consultando ngrok en http://127.0.0.1:4040 ..."
URL=$(curl -s http://127.0.0.1:4040/api/tunnels \
  | grep -o '"public_url":"https:[^"]*' \
  | head -n1 | cut -d\" -f4)

if [ -z "${URL:-}" ]; then
  echo "❌ No encuentro túnel https en ngrok. ¿Está corriendo?"
  exit 1
fi

echo "REACT_APP_API_BASE=$URL" > .env
echo "✅ .env actualizado con $URL"
