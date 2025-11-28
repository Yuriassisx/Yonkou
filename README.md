# Yonkou
Secret Hunter

🕵️‍♂️ Leak Hunter EXTREME
Scanner Avançado de Exposição de Secrets, Chaves e APIs Sensíveis

O Leak Hunter EXTREME é uma ferramenta avançada de análise estática e dinâmica focada na detecção de exposição de credenciais sensíveis, incluindo:

Chaves de API

Tokens de autenticação

Credenciais mobile (Android/iOS)

Segredos cloud (AWS, GCP, Azure)

Credenciais internas

Segredos históricos preservados pelo Wayback Machine

Secrets em JavaScript e JSON

Ele combina 500+ regexes profissionais, multi-threading, busca histórica e análise profunda de arquivos remotos.
Ideal para pentesters, analistas de segurança, bug hunters e times de AppSec.

📌 Principais Funcionalidades
🔍 1. Análise Completa de URLs

Coleta de HTML

Extração de JavaScript interno e externo

Varredura de arquivos JSON referenciados

Detecção de endpoints sensíveis

📦 2. Suporte a Lista de URLs

Permite análise massiva, ideal para corporações, escopos amplos ou coleta CTI.

🕰 3. Wayback Machine Integration

Coleta de snapshots históricos

Download automático de JS/JSON antigos

Busca de segredos expostos no passado
➡ Ideal para encontrar leaks que já foram removidos

🔑 4. 500+ Regexes Extremas

Inclui:

AWS / GCP / Azure / IBM secrets

Tokens OAuth2, JWT, Bearer, Session

Firebase Web/API keys

iOS .plist sensitive entries

Expo/React Native secrets

Docker / Kubernetes / Terraform segredos

Private keys / SSH / PEM

Webhooks sensíveis

Credenciais hardcoded

Padrões mobile avançados

⚡ 5. Multi-threading

Roda com alta performance, configurável via --threads.

🔴 6. Indicação em Vermelho

Achados sensíveis aparecem em vermelho para destaque imediato.

⏳ 7. Barra de Progresso

Todas as etapas usam tqdm, incluindo:

Download

Análise

Processamento de snapshots

Verificação de arquivos

📁 8. Dump de Scripts

Permite salvar todos arquivos capturados para análise manual posterior.

📜 9. Relatório em JSON

Exporta um arquivo com:

URL

Tipo de exposição

Regex acionada

Localização

Trecho encontrado

🚀 Instalação
1. Clone o repositório
git clone https://github.com/seuuser/leakhunter-extreme.git
cd leakhunter-extreme

2. Instale as dependências
pip install -r requirements.txt


Bibliotecas usadas:

requests

tqdm

colorama

beautifulsoup4

🖥️ Modo de Uso
⭐ Escanear uma única URL
python3 scanner_extremo.py --url https://alvo.com

📄 Escanear lista de URLs
python3 scanner_extremo.py --list targets.txt


Formato:

https://site1.com
https://site2.com
https://api.app.com

📦 Salvar relatório JSON
python3 scanner_extremo.py --url https://alvo.com --output resultados.json

⏱ Aumentar o número de threads
python3 scanner_extremo.py --threads 30 --list targets.txt

🕰 Desativar Wayback Machine
python3 scanner_extremo.py --url https://alvo.com --no-wayback

🎯 Buscar somente JS
python3 scanner_extremo.py --only-js --url https://alvo.com

🧩 Buscar somente JSON
python3 scanner_extremo.py --only-json --url https://alvo.com

🔴 Exibir apenas achados sensíveis
python3 scanner_extremo.py --only-hits --url https://alvo.com

🗃 Remover resultados duplicados
python3 scanner_extremo.py --dedup

🔧 Modo Verboso
python3 scanner_extremo.py --verbose

🔥 Modo Turbo (máxima performance)
python3 scanner_extremo.py --turbo

📁 Salvar todos os JS/JSON baixados
python3 scanner_extremo.py --dump-js dumps/ --url https://alvo.com

🧠 Comando mais completo possível
python3 scanner_extremo.py \
  --list targets.txt \
  --threads 30 \
  --output resultados.json \
  --dump-js jsdump/ \
  --turbo \
  --dedup \
  --verbose

📊 Estrutura do Projeto
📦 LeakHunter-EXTREME
├── scanner_extremo.py   # código completo e único
├── requirements.txt
├── README.md
└── dumps/               # opcional, criado automaticamente

⚠️ Aviso Legal

Esta ferramenta deve ser utilizada somente para:

Testes autorizados

Pentests contratados

Auditorias internas

Pesquisas acadêmicas

Uso indevido é responsabilidade exclusiva do operador.

🤝 Contribuindo

Pull requests e melhorias são bem-vindas.

🛡 Mantido por

Equipe especializada em:

Segurança ofensiva

AppSec

DevSecOps

Threat Hunting
