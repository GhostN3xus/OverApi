# 🔒 OverApi - Universal API Security Scanner

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-pentesting-red.svg)](https://github.com/GhostN3xus/OverApi)

**OverApi** é uma ferramenta CLI profissional e modular para testes de segurança ofensivos e defensivos em APIs. Suporta REST, GraphQL, SOAP, gRPC, WebSockets e Webhooks.

---

## 🚀 Instalação Rápida

### Método 1: Instalação via pip (Recomendado)

```bash
# Clone o repositório
git clone https://github.com/GhostN3xus/OverApi.git
cd OverApi

# Instale a ferramenta
pip install -e .

# Agora você pode usar o comando 'overapi' em qualquer lugar
overapi --version
```

### Método 2: Instalação local sem pip

```bash
# Clone o repositório
git clone https://github.com/GhostN3xus/OverApi.git
cd OverApi

# Instale as dependências
pip install -r requirements.txt

# Use diretamente
python -m overapi --version
```

### Método 3: Ambiente virtual (Recomendado para desenvolvimento)

```bash
# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Instalar
pip install -e .

# Usar
overapi --version
```

---

## 📖 Uso Básico

### Comando Principal

Após instalação, use o comando `overapi`:

```bash
# Ver ajuda
overapi --help

# Ver informações do sistema
overapi info

# Escanear uma API
overapi scan --url https://api.example.com
```

### Scan Rápido

```bash
# Scan básico
overapi scan --url https://api.example.com

# Com relatório HTML
overapi scan --url https://api.example.com --out report.html

# Modo agressivo
overapi scan --url https://api.example.com --mode aggressive --threads 20
```

---

## 🎯 Exemplos Práticos

### 1. Scan REST API com Autenticação

```bash
overapi scan \
  --url https://api.example.com \
  --auth-token "seu-token-jwt-aqui" \
  --out report.html
```

### 2. Scan GraphQL API

```bash
overapi scan \
  --url https://api.example.com/graphql \
  --type graphql \
  --mode aggressive \
  --json results.json
```

### 3. Scan com Proxy (Burp Suite)

```bash
overapi scan \
  --url https://api.example.com \
  --proxy http://127.0.0.1:8080 \
  --no-verify-ssl \
  --header "Authorization: Bearer token123"
```

### 4. Scan SOAP API

```bash
overapi scan \
  --url https://api.example.com/soap \
  --type soap \
  --timeout 60 \
  --out soap_report.html
```

### 5. Scan Personalizado com Wordlist

```bash
overapi scan \
  --url https://api.example.com \
  --wordlist /usr/share/wordlists/api-endpoints.txt \
  --max-endpoints 5000 \
  --threads 30
```

### 6. Scan Seguro (Sem Injeções)

```bash
overapi scan \
  --url https://api.example.com \
  --mode safe \
  --no-injection \
  --no-fuzzing
```

### 7. Scan Completo com Todos os Recursos

```bash
overapi scan \
  --url https://api.example.com \
  --mode aggressive \
  --threads 20 \
  --timeout 45 \
  --auth-token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --header "X-Api-Key: your-api-key" \
  --cookie "session=abc123" \
  --proxy http://127.0.0.1:8080 \
  --no-verify-ssl \
  --out complete_report.html \
  --json complete_report.json \
  --verbose
```

---

## 🛠️ Opções de Linha de Comando

### 🎯 Configuração do Alvo

| Opção | Descrição |
|-------|-----------|
| `--url URL` | URL da API alvo (obrigatório) |
| `--type TYPE` | Tipo de API: rest, graphql, soap, grpc, websocket, auto (padrão: auto) |

### ⚙️ Configuração do Scan

| Opção | Descrição |
|-------|-----------|
| `--mode MODE` | Modo: safe, normal, aggressive (padrão: normal) |
| `--threads N` | Número de threads (padrão: 10, máx: 50) |
| `--timeout SEC` | Timeout das requisições em segundos (padrão: 30) |
| `--max-endpoints N` | Máximo de endpoints a descobrir (padrão: 1000) |
| `--delay SEC` | Delay entre requisições em segundos (padrão: 0) |

### 🔑 Autenticação & Headers

| Opção | Descrição |
|-------|-----------|
| `--header "Key: Value"` | Header customizado (pode usar múltiplas vezes) |
| `--auth-token TOKEN` | Token de autenticação (adiciona como Bearer token) |
| `--cookie COOKIE` | Valor do cookie |
| `--user-agent UA` | User-Agent customizado (padrão: OverApi/1.0) |

### 🌐 Rede & SSL

| Opção | Descrição |
|-------|-----------|
| `--proxy URL` | URL do proxy (http://ip:port ou socks5://ip:port) |
| `--verify-ssl` | Verificar certificados SSL (padrão: habilitado) |
| `--no-verify-ssl` | Desabilitar verificação SSL (NÃO recomendado) |
| `--custom-ca PATH` | Caminho para bundle de certificados CA customizado |

### 🧪 Módulos de Teste

| Opção | Descrição |
|-------|-----------|
| `--no-fuzzing` | Desabilitar fuzzing/descoberta de endpoints |
| `--no-injection` | Desabilitar testes de injeção (SQLi, XSS, etc.) |
| `--no-ratelimit` | Desabilitar testes de rate limit |
| `--no-bola` | Desabilitar testes BOLA |
| `--no-auth-bypass` | Desabilitar testes de bypass de autenticação |

### 📚 Wordlists & Dados

| Opção | Descrição |
|-------|-----------|
| `--wordlist PATH` | Wordlist customizada para descoberta de endpoints |
| `--payload-file PATH` | Arquivo de payloads customizados para testes de injeção |

### 📊 Saída & Relatórios

| Opção | Descrição |
|-------|-----------|
| `--out PATH` | Caminho para relatório HTML (ex: report.html) |
| `--json PATH` | Caminho para relatório JSON (ex: results.json) |
| `--outdir DIR` | Diretório de saída para relatórios (padrão: ./reports) |
| `--log-file PATH` | Caminho para arquivo de log |

### 🔧 Opções Gerais

| Opção | Descrição |
|-------|-----------|
| `-v, --verbose` | Saída verbose (modo debug) |
| `-q, --quiet` | Modo silencioso (saída mínima) |
| `--no-banner` | Desabilitar exibição do banner |
| `-V, --version` | Mostrar versão |

---

## 🔍 Recursos

### Detecção de Tipo de API
- ✅ Detecção automática de tipos de API
- ✅ Identificação baseada em heurísticas inteligentes
- ✅ Suporte para APIs não documentadas (scan cego)

### Descoberta de Endpoints
- ✅ Fuzzing baseado em wordlist
- ✅ Parsing de documentação Swagger/OpenAPI
- ✅ Introspecção GraphQL
- ✅ Parsing WSDL para SOAP
- ✅ Reflexão gRPC

### Testes de Segurança
- ✅ **OWASP API Top 10** - Testes de vulnerabilidades
- ✅ Testes de Injeção (SQLi, XSS, NoSQL, Command Injection)
- ✅ BOLA (Broken Object Level Authorization)
- ✅ Detecção de bypass de autenticação
- ✅ Testes de rate limit
- ✅ Detecção de exposição de dados
- ✅ Testes de lógica de negócio
- ✅ Análise JWT
- ✅ SSRF Testing

### Relatórios
- ✅ Relatórios HTML profissionais com código de cores por severidade
- ✅ Relatórios JSON estruturados
- ✅ Sumário executivo com avaliação de risco
- ✅ Evidências detalhadas de vulnerabilidades

---

## 📂 Estrutura do Projeto

```
OverApi/
├── overapi/
│   ├── cli.py                 # Interface CLI aprimorada
│   ├── __main__.py            # Entry point do módulo
│   ├── core/                  # Módulos core
│   │   ├── api_detector.py    # Detector de tipo de API
│   │   ├── config.py          # Configurações
│   │   ├── logger.py          # Sistema de logging
│   │   └── exceptions.py      # Exceções customizadas
│   ├── modules/               # Módulos específicos de API
│   │   ├── rest/              # Scanner REST
│   │   ├── graphql/           # Scanner GraphQL
│   │   ├── soap/              # Scanner SOAP
│   │   ├── grpc/              # Scanner gRPC
│   │   ├── websocket/         # Scanner WebSocket
│   │   ├── webhook/           # Scanner Webhook
│   │   └── security/          # Módulos de segurança
│   │       ├── auth/          # Análise JWT
│   │       ├── injection/     # Testes de injeção
│   │       ├── business_logic/# Testes de lógica
│   │       └── reporting/     # Relatórios avançados
│   ├── scanner/               # Engines de scanning
│   │   ├── scanner.py         # Scanner principal
│   │   ├── fuzzer.py          # Fuzzer de endpoints
│   │   └── security_tester.py # Testes de segurança
│   ├── utils/                 # Utilitários
│   │   ├── http_client.py     # Cliente HTTP
│   │   ├── wordlist_loader.py # Carregador de wordlists
│   │   └── validators.py      # Validadores
│   └── report/                # Geração de relatórios
│       ├── html_generator.py  # Gerador HTML
│       ├── json_generator.py  # Gerador JSON
│       └── report_generator.py# Gerenciador de relatórios
├── tests/                     # Testes automatizados
├── main.py                    # Script standalone (deprecated)
├── setup.py                   # Configuração de instalação
├── requirements.txt           # Dependências
└── README.md                  # Este arquivo
```

---

## 🧪 Modos de Scan

### Safe Mode (`--mode safe`)
- Scanning passivo
- Sem fuzzing agressivo
- Timeout alto
- Apenas detecção básica

### Normal Mode (`--mode normal`) - **Padrão**
- Equilíbrio entre velocidade e cobertura
- Fuzzing moderado
- Testes de injeção básicos
- Recomendado para uso geral

### Aggressive Mode (`--mode aggressive`)
- Scanning intensivo
- Fuzzing completo
- Todos os testes de injeção
- Múltiplas threads
- Melhor cobertura

---

## 🔐 Considerações de Segurança

⚠️ **IMPORTANTE**: Esta ferramenta deve ser usada apenas para:
- Testes de segurança autorizados
- Pentesting com permissão explícita
- Auditorias de segurança contratadas
- Ambientes de desenvolvimento/teste próprios

🚫 **NÃO USE** para:
- Testes não autorizados
- Ataques maliciosos
- Exploração de sistemas de terceiros sem permissão

---

## 📝 Exemplos de Saída

### Relatório HTML
Relatórios HTML incluem:
- Dashboard executivo
- Sumário de vulnerabilidades por severidade
- Timeline do scan
- Detalhes técnicos de cada vulnerabilidade
- Evidências (requests/responses)
- Recomendações de correção

### Relatório JSON
Formato estruturado para integração com outras ferramentas:
```json
{
  "scan_info": {
    "target": "https://api.example.com",
    "start_time": "2025-12-02T10:30:00",
    "end_time": "2025-12-02T10:45:00",
    "duration": 900
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "critical",
      "endpoint": "/api/users",
      "evidence": "..."
    }
  ],
  "statistics": {
    "total_requests": 1500,
    "endpoints_found": 45,
    "vulnerabilities": 12
  }
}
```

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/MinhaFeature`)
3. Commit suas mudanças (`git commit -m 'Add: Minha nova feature'`)
4. Push para a branch (`git push origin feature/MinhaFeature`)
5. Abra um Pull Request

---

## 📜 Licença

Este projeto está licenciado sob a MIT License - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 🔗 Links Úteis

- 📚 [Documentação Completa](https://github.com/GhostN3xus/OverApi/wiki)
- 🐛 [Reportar Bugs](https://github.com/GhostN3xus/OverApi/issues)
- 💬 [Discussões](https://github.com/GhostN3xus/OverApi/discussions)
- 🔒 [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

---

## 📊 Suporte

Para suporte:
1. Consulte a [documentação](https://github.com/GhostN3xus/OverApi/wiki)
2. Procure em [issues existentes](https://github.com/GhostN3xus/OverApi/issues)
3. Abra uma [nova issue](https://github.com/GhostN3xus/OverApi/issues/new)

---

## 🎓 Recursos de Aprendizado

- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [API Security Best Practices](https://github.com/shieldfy/API-Security-Checklist)
- [GraphQL Security](https://graphql.org/learn/best-practices/#security)

---

**Versão**: 1.0.0
**Mantido por**: GhostN3xus
**Status**: Ativo ✅

---

*⚖️ Use esta ferramenta de forma responsável e ética. Apenas para testes de segurança autorizados.*
