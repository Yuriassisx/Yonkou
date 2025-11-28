# 🕵️‍♂️ Leak Hunter EXTREME  
### Scanner Avançado de Secrets, Chaves e APIs Sensíveis

O **Leak Hunter EXTREME** é uma ferramenta profissional destinada à identificação e auditoria de exposição de segredos em superfícies web e arquivos públicos. Ela ajuda a encontrar chaves de API, tokens, credenciais hardcoded, arquivos JavaScript/JSON expostos e vazamentos históricos (Wayback Machine). Ideal para pentests autorizados, bug bounty, CTI, AppSec e auditorias internas.

> **Aviso legal:** use apenas em alvos nos quais você tem autorização explícita. O uso indevido é de responsabilidade do operador.

---

## 🚀 Funcionalidades Principais

- 🔎 Análise completa de URLs (HTML, JS, JSON)  
- 🕸️ Crawling inteligente (segue links internos e assets)  
- 🕰️ Integração com Wayback Machine (snapshots históricos)  
- 🧠 Conjunto configurável de padrões (regex) para detecção de secrets  
- 📱 Cobertura de padrões mobile (Android / iOS / frameworks híbridos)  
- ☁️ Cobertura de padrões cloud e DevOps (AWS/GCP/Azure/CI/CD/containers)  
- 🔥 Multi-threading para alta performance  
- ⏳ Barra de progresso (tqdm) para acompanhar execução  
- 🟥 Destaque de achados sensíveis no terminal (color output)  
- 💾 Dump opcional de arquivos baixados para análise offline  
- 📊 Exportação de relatório JSON (resultados consolidados)  
- 🧹 Opções para deduplicação e filtragem de falsos positivos  
- 🔧 CLI com múltiplas flags para controle fino de execução

---

## 🧰 Requisitos

- Python 3.8+  
- Pacotes Python (ex.: `requests`, `beautifulsoup4`, `tqdm`, `colorama`)  
- Conexão com internet para Wayback Machine e downloads de assets

Instalação rápida (exemplo):
```bash
pip install requests beautifulsoup4 tqdm colorama
🖥️ Uso (exemplos de CLI)
Observação: o README descreve as opções de uso e não inclui o código-fonte do scanner. Adapte as flags conforme a implementação do seu script.

🔹 Escanear uma única URL
bash
Copiar código
python3 scanner_extremo.py --url https://alvo.com
🔹 Escanear uma lista de URLs
bash
Copiar código
python3 scanner_extremo.py --list targets.txt
Formato do targets.txt:

arduino
Copiar código
https://site1.com
https://site2.com
https://api.alvo.com
🔹 Salvar relatório JSON
bash
Copiar código
python3 scanner_extremo.py --url https://alvo.com --output resultados.json
🔹 Limitar threads (default ex.: 10)
bash
Copiar código
python3 scanner_extremo.py --list targets.txt --threads 20
🔹 Desativar Wayback Machine (opcional)
bash
Copiar código
python3 scanner_extremo.py --url https://alvo.com --no-wayback
🔹 Buscar apenas arquivos JavaScript
bash
Copiar código
python3 scanner_extremo.py --url https://alvo.com --only-js
🔹 Buscar apenas JSON endpoints
bash
Copiar código
python3 scanner_extremo.py --url https://alvo.com --only-json
🔹 Exibir somente hits (silenciar ruído)
bash
Copiar código
python3 scanner_extremo.py --url https://alvo.com --only-hits
🔹 Remover resultados duplicados
bash
Copiar código
python3 scanner_extremo.py --url https://alvo.com --dedup
🔹 Modo verboso (logs detalhados)
bash
Copiar código
python3 scanner_extremo.py --url https://alvo.com --verbose
🔹 Modo turbo (máxima performance)
bash
Copiar código
python3 scanner_extremo.py --list targets.txt --turbo
🔹 Dump de arquivos JS/JSON baixados
bash
Copiar código
python3 scanner_extremo.py --url https://alvo.com --dump-js ./jsdump/
🔹 Comando completo (exemplo de uso avançado)
bash
Copiar código
python3 scanner_extremo.py \
  --list targets.txt \
  --threads 30 \
  --output resultado.json \
  --dump-js jsdump/ \
  --turbo \
  --dedup \
  --verbose
⚙️ Configurações e opções importantes
Conjunto de padrões (regex): o motor aceita uma lista configurável de expressões regulares para detectar diferentes tipos de segredos. Recomendado revisar e ajustar para reduzir falsos positivos.

Profundidade do crawler: configure limites de profundidade ou domínio para evitar escaneamentos fora do escopo.

Rate limit / delays: se você estiver varrendo um alvo com proteção, use delays e respeite o robots.txt quando apropriado.

Proxy / interceptador: para análise em um ambiente controlado (ex.: Burp), exporte variáveis HTTP_PROXY/HTTPS_PROXY.

Dumping: arquivos baixados podem ser salvos localmente com hashes para auditoria e evidência.

Logs: habilite logs rotativos para conservar histórico das execuções.

📁 Estrutura sugerida do repositório
bash
Copiar código
📦 LeakHunter-EXTREME
├── scanner_extremo.py        # script principal (implementação autorizada)
├── README.md                 # este arquivo
├── requirements.txt          # dependências
├── targets.txt               # exemplo de lista de URLs
└── dumps/                    # pasta criada automaticamente para dumps
🔎 Como o scanner opera (visão técnica)
Input: URL única ou lista de URLs.

Normalização: normaliza URLs, valida esquema (http/https) e prepara fila.

Download inicial: baixa HTML da página-alvo.

Extração: extrai <script src>, <a href>, <link>, e referências a .json, .map etc.

Fila de assets: adiciona assets (JS/JSON) à fila de download/scan.

Wayback Machine: (quando habilitado) consulta snapshots, adiciona assets históricos à fila.

Análise: executa padrões configuráveis (regex) sobre os conteúdos baixados.

Relato em tempo real: prints coloridos para hits; barra de progresso atualiza conforme a fila é consumida.

Output consolidado: gera results.json com todos os achados, deduplicados e classificados.

Dump opcional: salva cópias dos arquivos baixados para análise manual.

🔐 Boas práticas e recomendações
Use apenas em alvos autorizados. Tenha sempre escopo e permissão documentada.

Revise e restrinja os padrões (regex) para seu escopo alvo para reduzir falsos positivos.

Isolar ambientes de análise (máquina dedicada, VPN corporativa, proxies controlados).

Rotacionamento e notificação: quando encontrar secrets válidos, notifique o dono da conta e gire chaves imediatamente.

Documente evidências (hash de arquivos, timestamps, snapshot do Wayback) para relatórios de auditoria.

Rate limit e backoff: evite sobrecarregar serviços e reduzir risco de bloqueio/ban.

📊 Formato de saída (exemplo de results.json)
O relatório JSON consolidado pode incluir (exemplo genérico):

json
Copiar código
[
  {
    "target": "https://alvo.com",
    "asset_url": "https://alvo.com/static/app.js",
    "pattern_name": "JWT",
    "match": "eyJ...abc",
    "context_snippet": "...",
    "timestamp": "2025-11-27T21:00:00Z"
  }
]
🛡️ Uso responsável & Aviso legal
Ferramentas de detecção de secrets podem ser poderosas. Utilize este projeto apenas para fins legais e éticos:

Auditoria interna com autorização

Testes contratados (pentest) com escopo definido

Programas de bug bounty que permitam este tipo de varredura

O autor não é responsável por uso indevido.

🤝 Contribuições
Contribuições bem-vindas (pull requests, issues, sugestões). Antes de submeter regexes ou módulos novos, verifique o impacto de segurança e a compatibilidade com o escopo ético do projeto.
