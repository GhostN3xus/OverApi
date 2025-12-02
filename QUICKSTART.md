# 🚀 Guia de Início Rápido - OverApi

## Instalação em 30 segundos

```bash
git clone https://github.com/GhostN3xus/OverApi.git
cd OverApi
pip install -e .
overapi --version
```

## Seu Primeiro Scan

### 1. Scan Básico

```bash
overapi scan --url https://api.example.com
```

### 2. Scan com Relatório HTML

```bash
overapi scan --url https://api.example.com --out report.html
```

### 3. Ver o Relatório

```bash
firefox report.html  # ou google-chrome, etc.
```

## Exemplos Comuns

### REST API com Token JWT

```bash
overapi scan \
  --url https://api.example.com \
  --auth-token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --out report.html
```

### GraphQL API

```bash
overapi scan \
  --url https://api.example.com/graphql \
  --type graphql \
  --mode aggressive
```

### Scan através de Proxy (Burp Suite)

```bash
overapi scan \
  --url https://api.example.com \
  --proxy http://127.0.0.1:8080 \
  --no-verify-ssl
```

### Scan Rápido (Sem Injeções)

```bash
overapi scan \
  --url https://api.example.com \
  --mode safe \
  --no-injection \
  --no-fuzzing
```

### Scan Completo (Agressivo)

```bash
overapi scan \
  --url https://api.example.com \
  --mode aggressive \
  --threads 30 \
  --out complete_report.html \
  --json complete_report.json \
  --verbose
```

## Comandos Úteis

```bash
# Ver ajuda geral
overapi --help

# Ver ajuda do comando scan
overapi scan --help

# Ver informações do sistema
overapi info

# Ver versão
overapi --version
```

## Estrutura de Relatórios

Os relatórios são salvos por padrão em `./reports/`:

```
reports/
├── overapi_report_2025-12-02_10-30-00.html  # Relatório HTML
└── overapi_results_2025-12-02_10-30-00.json # Resultados JSON
```

## Modos de Scan

| Modo | Velocidade | Cobertura | Uso Recomendado |
|------|-----------|-----------|-----------------|
| `safe` | ⚡⚡⚡ | ⭐⭐ | Ambientes de produção |
| `normal` | ⚡⚡ | ⭐⭐⭐ | Uso geral (padrão) |
| `aggressive` | ⚡ | ⭐⭐⭐⭐⭐ | Pentesting completo |

## Headers Customizados

```bash
# Múltiplos headers
overapi scan \
  --url https://api.example.com \
  --header "Authorization: Bearer token123" \
  --header "X-Api-Key: abc123" \
  --header "X-Custom-Header: value"
```

## Desabilitar Testes Específicos

```bash
# Sem fuzzing e rate limit tests
overapi scan \
  --url https://api.example.com \
  --no-fuzzing \
  --no-ratelimit
```

## Configuração de Threads

```bash
# Scan rápido com mais threads (cuidado com rate limiting!)
overapi scan \
  --url https://api.example.com \
  --threads 50 \
  --delay 0.1  # 100ms de delay entre requests
```

## Wordlist Customizada

```bash
overapi scan \
  --url https://api.example.com \
  --wordlist /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  --max-endpoints 5000
```

## Troubleshooting

### Problema: SSL Certificate Error

```bash
# Solução: Desabilitar verificação SSL (apenas para testes!)
overapi scan --url https://api.example.com --no-verify-ssl
```

### Problema: Rate Limited

```bash
# Solução: Adicionar delay e reduzir threads
overapi scan \
  --url https://api.example.com \
  --threads 5 \
  --delay 0.5
```

### Problema: Timeout Errors

```bash
# Solução: Aumentar timeout
overapi scan \
  --url https://api.example.com \
  --timeout 60
```

## Próximos Passos

1. 📖 Leia o [README completo](README.md)
2. 🔍 Explore os [Módulos de Segurança](SECURITY_MODULES.md)
3. 📚 Consulte a [Documentação Completa](https://github.com/GhostN3xus/OverApi/wiki)
4. 🐛 Reporte bugs em [Issues](https://github.com/GhostN3xus/OverApi/issues)

---

**Dica**: Use sempre `overapi scan --help` para ver todas as opções disponíveis!
