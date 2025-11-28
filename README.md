# 🕵️‍♂️ Leak Hunter EXTREME

### Scanner Avançado de Secrets, Chaves e APIs Sensíveis

O **Leak Hunter EXTREME** é uma ferramenta profissional destinada à
identificação e auditoria de exposição de segredos em superfícies web e
arquivos públicos.\
Ela auxilia na detecção de **chaves de API, tokens, credenciais
hardcoded, JS/JSON expostos e vazamentos históricos (Wayback Machine)**.

Ideal para: **Pentest autorizado, Bug Bounty, CTI, AppSec, Engenharia
Reversa e Auditorias Internas**.

> ⚠️ **Aviso legal:** Utilize *apenas* em alvos nos quais você possui
> **autorização explícita**.\
> O uso indevido é de responsabilidade exclusiva do operador.

------------------------------------------------------------------------

## 🚀 Funcionalidades Principais

-   🔎 **Análise completa de URLs** (HTML, JS, JSON)
-   🕸️ **Crawling inteligente**
-   🕰️ **Wayback Machine**
-   🧠 **Regex configurável**
-   📱 Cobertura mobile
-   ☁️ Cloud & DevOps
-   🔥 **Multi-threading**
-   ⏳ **Progress bar**
-   🟥 Destaque colorido
-   💾 **Dump** de arquivos
-   📊 **Exportação JSON**
-   🧹 Deduplicação
-   🔧 CLI completa

------------------------------------------------------------------------

## 🧰 Requisitos

-   Python 3.8+
-   requests, beautifulsoup4, tqdm, colorama

### Instalação

``` bash
pip install requests beautifulsoup4 tqdm colorama
```

------------------------------------------------------------------------

# 🖥️ Uso (exemplos CLI)

## URL única

``` bash
python3 scanner_extremo.py --url https://alvo.com
```

## Lista de URLs

``` bash
python3 scanner_extremo.py --list targets.txt
```

targets.txt:

    https://site1.com
    https://site2.com
    https://api.alvo.com

## Salvar JSON

``` bash
python3 scanner_extremo.py --url https://alvo.com --output resultados.json
```

## Threads

``` bash
python3 scanner_extremo.py --threads 20
```

## Sem Wayback

``` bash
python3 scanner_extremo.py --no-wayback
```

## Only JS

``` bash
python3 scanner_extremo.py --only-js
```

## Only JSON

``` bash
python3 scanner_extremo.py --only-json
```

## Only hits

``` bash
python3 scanner_extremo.py --only-hits
```

## Dedup

``` bash
python3 scanner_extremo.py --dedup
```

## Verbose

``` bash
python3 scanner_extremo.py --verbose
```

## Turbo

``` bash
python3 scanner_extremo.py --turbo
```

## Dump JS

``` bash
python3 scanner_extremo.py --dump-js ./jsdump/
```

## Avançado

``` bash
python3 scanner_extremo.py   --list targets.txt   --threads 30   --output resultado.json   --dump-js jsdump/   --turbo   --dedup   --verbose
```

------------------------------------------------------------------------

# ⚙️ Configurações

-   Regex configurável
-   Limite de profundidade
-   Rate limit & delays
-   Proxy
-   Dumping
-   Logs rotativos
-   Deduplicação

------------------------------------------------------------------------

# 📁 Estrutura

``` bash
📦 LeakHunter-EXTREME
├── scanner_extremo.py
├── README.md
├── requirements.txt
├── targets.txt
└── dumps/
```

------------------------------------------------------------------------

# 🔎 Operação Técnica

1.  Input
2.  Normalização
3.  Download HTML
4.  Extração
5.  Fila de assets
6.  Wayback
7.  Análise de regex
8.  Relatório em tempo real
9.  Output JSON
10. Dump opcional

------------------------------------------------------------------------

# 🔐 Boas práticas

-   Use apenas com autorização
-   Ajuste regexes
-   Ambiente isolado
-   Notifique e rotacione chaves
-   Registre evidências
-   Use rate limit

------------------------------------------------------------------------

# 📊 Exemplo JSON

``` json
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
```

------------------------------------------------------------------------

# 🛡️ Uso responsável

-   Auditoria interna
-   Pentest autorizado
-   Bug bounty permitido

------------------------------------------------------------------------

# 🤝 Contribuições

Pull Requests são bem-vindos!
