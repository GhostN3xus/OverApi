# HTTP Workbench - Funcionalidades Integradas ao OverApi

## 📋 Visão Geral

Este documento descreve as funcionalidades inspiradas no [HTTP Workbench](https://github.com/bebiksior/httpworkbench) que foram integradas aos testes de API do OverApi. Essas ferramentas melhoram significativamente a capacidade de testar, debugar e validar APIs.

## 🎯 Funcionalidades Implementadas

### 1. **RequestLogger** - Logger Avançado de Requisições/Respostas

Logger detalhado que captura informações completas sobre requisições HTTP e suas respostas.

#### Características:
- ✅ Captura headers completos (request e response)
- ✅ Registra bodies de requisição e resposta
- ✅ Mede tempo de resposta
- ✅ Armazena metadados (IP, User-Agent, tamanho)
- ✅ Suporta filtragem e busca
- ✅ Exportação para JSON e TXT
- ✅ Estatísticas agregadas

#### Exemplo de Uso:

```python
from overapi.testing import RequestLogger
import httpx

# Criar logger
logger = RequestLogger(enabled=True, max_body_size=10000)

# Fazer requisição
url = "https://api.example.com/users"
headers = {"Authorization": "Bearer token123"}

# Log da requisição
log_entry = logger.log_request("GET", url, headers=headers)

# Fazer a requisição real
import time
start = time.time()
response = httpx.get(url, headers=headers)
elapsed = time.time() - start

# Log da resposta
logger.log_response(log_entry, response, elapsed)

# Obter logs filtrados
get_requests = logger.get_logs(method="GET")
error_requests = logger.get_logs(status_code=500)

# Obter estatísticas
summary = logger.get_summary()
print(f"Total de requisições: {summary['total_requests']}")
print(f"Tempo médio de resposta: {summary['avg_response_time']}s")

# Exportar logs
logger.export_logs("logs.json", format="json")
```

#### API Completa:

```python
class RequestLogger:
    def __init__(self, enabled: bool = True, max_body_size: int = 10000)

    # Logging
    def log_request(method, url, headers=None, params=None, body=None, client_ip=None) -> RequestLog
    def log_response(log_entry, response, response_time)
    def log_error(log_entry, error)

    # Consultas
    def get_logs(method=None, status_code=None, url_contains=None, has_error=None) -> List[RequestLog]
    def get_summary() -> Dict

    # Exportação
    def export_logs(filepath, format="json")

    # Utilidades
    def clear()
    def __len__() -> int
```

---

### 2. **MockHTTPServer** - Servidor HTTP Mock para Testes

Servidor HTTP mock para simular endpoints de API durante testes, inspirado na funcionalidade de hosting de PoCs do HTTP Workbench.

#### Características:
- ✅ Hospedar endpoints temporários para testes
- ✅ Configurar respostas customizadas
- ✅ Simular delays e erros
- ✅ Registrar requisições recebidas
- ✅ Suporte para JSON, texto e dados binários

#### Exemplo de Uso:

```python
import pytest
from overapi.testing import MockHTTPServer
import httpx

@pytest.mark.asyncio
async def test_api_with_mock_server():
    # Criar e iniciar servidor
    async with MockHTTPServer(host="127.0.0.1", port=8888) as server:
        # Configurar endpoints
        server.add_json_endpoint(
            path="/api/users",
            method="GET",
            json_data=[
                {"id": 1, "name": "User 1"},
                {"id": 2, "name": "User 2"}
            ]
        )

        server.add_json_endpoint(
            path="/api/users",
            method="POST",
            json_data={"id": 3, "name": "New User"},
            status_code=201
        )

        # Simular erro
        server.add_error_endpoint(
            path="/api/error",
            status_code=500,
            error_message="Internal Server Error"
        )

        # Simular delay
        server.add_json_endpoint(
            path="/api/slow",
            json_data={"status": "ok"},
            delay=2.0  # 2 segundos de atraso
        )

        # Fazer requisições
        async with httpx.AsyncClient() as client:
            response = await client.get(server.get_url("/api/users"))
            assert response.status_code == 200
            assert len(response.json()) == 2

        # Verificar logs de requisições
        logs = server.get_request_log()
        assert len(logs) == 1
        assert logs[0]["method"] == "GET"
```

#### Usando com pytest fixture:

```python
@pytest.mark.asyncio
async def test_with_fixture(mock_server):
    """mock_server é uma fixture que já inicia/para o servidor."""
    mock_server.add_json_endpoint("/test", json_data={"status": "ok"})

    url = mock_server.get_url("/test")
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        assert response.json()["status"] == "ok"
```

#### API Completa:

```python
class MockHTTPServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8888)

    # Configuração de endpoints
    def add_endpoint(path, method="GET", response_body=None, status_code=200, headers=None, delay=0.0)
    def add_json_endpoint(path, method="GET", json_data=None, status_code=200, delay=0.0)
    def add_error_endpoint(path, method="GET", status_code=500, error_message="Internal Server Error")

    # Controle do servidor
    async def start()
    async def stop()

    # Utilidades
    def get_url(path: str = "") -> str
    def get_request_log() -> List[Dict]
    def clear_request_log()
    def clear_endpoints()

    # Context manager
    async def __aenter__()
    async def __aexit__(...)
```

---

### 3. **WebhookTester** - Testador de Webhooks

Ferramenta para testar webhooks e callbacks, inspirada no suporte de webhooks do HTTP Workbench.

#### Características:
- ✅ Capturar webhooks recebidos
- ✅ Verificar payloads de webhooks
- ✅ Testar retries e falhas
- ✅ Handlers customizados
- ✅ Assertions para validação

#### Exemplo de Uso:

```python
import pytest
from overapi.testing import WebhookTester
import httpx

@pytest.mark.asyncio
async def test_webhook():
    async with WebhookTester(host="127.0.0.1", port=9999) as tester:
        webhook_url = tester.get_url("/webhook")

        # Enviar webhook
        async with httpx.AsyncClient() as client:
            await client.post(
                webhook_url,
                json={"event": "user.created", "user_id": 123}
            )

        # Verificar webhook recebido
        tester.assert_webhook_called(path="/webhook", times=1)
        tester.assert_webhook_body_contains({
            "event": "user.created",
            "user_id": 123
        })

        # Obter o webhook
        call = tester.get_last_call()
        assert call.body is not None
        assert "user.created" in call.body
```

#### Aguardar Webhooks:

```python
@pytest.mark.asyncio
async def test_wait_for_webhook(webhook_tester):
    webhook_url = webhook_tester.get_url("/webhook")

    # Enviar webhook após delay
    async def send_delayed():
        await asyncio.sleep(1)
        async with httpx.AsyncClient() as client:
            await client.post(webhook_url, json={"data": "test"})

    asyncio.create_task(send_delayed())

    # Aguardar webhook (timeout 5 segundos)
    call = await webhook_tester.wait_for_webhook_async(
        timeout=5.0,
        path="/webhook"
    )

    assert call is not None
```

#### Handlers Customizados:

```python
@pytest.mark.asyncio
async def test_custom_handler(webhook_tester):
    # Handler customizado
    async def my_handler(webhook_call):
        # Processar webhook
        return {"received": True, "id": 456}, 201

    webhook_tester.register_handler("/custom", my_handler)

    url = webhook_tester.get_url("/custom")
    async with httpx.AsyncClient() as client:
        response = await client.post(url, json={"data": "test"})
        assert response.status_code == 201
        assert response.json()["received"] is True
```

#### API Completa:

```python
class WebhookTester:
    def __init__(self, host: str = "127.0.0.1", port: int = 9999)

    # Configuração
    def set_default_response(response_body: Dict, status_code: int = 200)
    def register_handler(path: str, handler: Callable)

    # Controle do servidor
    async def start()
    async def stop()

    # Consultas
    def get_calls(path=None, method=None) -> List[WebhookCall]
    def get_last_call() -> Optional[WebhookCall]
    def get_call_count(path=None, method=None) -> int

    # Aguardar webhooks
    def wait_for_webhook(timeout=5.0, path=None, method=None) -> Optional[WebhookCall]
    async def wait_for_webhook_async(timeout=5.0, path=None, method=None) -> Optional[WebhookCall]

    # Assertions
    def assert_webhook_called(path=None, method=None, times=None)
    def assert_webhook_body_contains(expected: Dict, path=None)

    # Utilidades
    def get_url(path: str = "/webhook") -> str
    def clear_calls()

    # Context manager
    async def __aenter__()
    async def __aexit__(...)
```

---

## 🔧 Fixtures do Pytest

Todas as ferramentas estão disponíveis como fixtures do pytest em `tests/conftest.py`:

```python
# RequestLogger
def test_example(request_logger):
    log = request_logger.log_request("GET", "https://api.example.com")
    # ...

# MockHTTPServer (async)
@pytest.mark.asyncio
async def test_mock(mock_server):
    mock_server.add_json_endpoint("/api/test", json_data={"status": "ok"})
    # ...

# WebhookTester (async)
@pytest.mark.asyncio
async def test_webhook(webhook_tester):
    webhook_url = webhook_tester.get_url("/webhook")
    # ...
```

---

## 📚 Exemplos Práticos

### Exemplo 1: Testar API com Mock Server e Logger

```python
import pytest
from overapi.testing import RequestLogger, MockHTTPServer
import httpx

@pytest.mark.asyncio
async def test_api_full_logging(mock_server, request_logger):
    # Setup mock API
    mock_server.add_json_endpoint("/api/data", json_data={"items": [1, 2, 3]})

    # Fazer requisição com logging
    url = mock_server.get_url("/api/data")
    log = request_logger.log_request("GET", url)

    import time
    start = time.time()
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
    elapsed = time.time() - start

    request_logger.log_response(log, response, elapsed)

    # Validações
    assert response.status_code == 200
    assert len(response.json()["items"]) == 3

    # Verificar logs
    assert len(request_logger) == 1
    summary = request_logger.get_summary()
    assert summary["total_requests"] == 1
    assert summary["status_codes"][200] == 1
```

### Exemplo 2: Testar Integração com Webhook

```python
import pytest
from overapi.testing import MockHTTPServer, WebhookTester
import httpx

@pytest.mark.asyncio
async def test_api_with_webhook(mock_server, webhook_tester):
    # Setup: API que chama webhook
    webhook_url = webhook_tester.get_url("/callback")

    # Simular API que envia webhook após operação
    mock_server.add_json_endpoint(
        "/api/process",
        method="POST",
        json_data={"status": "processing", "callback": webhook_url}
    )

    # Chamar API
    async with httpx.AsyncClient() as client:
        response = await client.post(
            mock_server.get_url("/api/process"),
            json={"data": "test"}
        )

    # Simular envio de webhook pela API
    async with httpx.AsyncClient() as client:
        await client.post(webhook_url, json={"status": "completed"})

    # Verificar webhook recebido
    webhook_tester.assert_webhook_called(times=1)
    call = webhook_tester.get_last_call()
    assert "completed" in call.body
```

### Exemplo 3: Testar Resiliência com Delays e Erros

```python
import pytest
from overapi.testing import MockHTTPServer
import httpx
import asyncio

@pytest.mark.asyncio
async def test_api_resilience(mock_server):
    # Simular endpoints lentos
    mock_server.add_json_endpoint(
        "/api/slow",
        json_data={"status": "ok"},
        delay=1.0
    )

    # Simular endpoint com erro intermitente
    mock_server.add_error_endpoint(
        "/api/error",
        status_code=503,
        error_message="Service Unavailable"
    )

    async with httpx.AsyncClient(timeout=5.0) as client:
        # Testar timeout
        start = asyncio.get_event_loop().time()
        response = await client.get(mock_server.get_url("/api/slow"))
        elapsed = asyncio.get_event_loop().time() - start

        assert response.status_code == 200
        assert elapsed >= 1.0  # Verificar que o delay foi aplicado

        # Testar error handling
        response = await client.get(mock_server.get_url("/api/error"))
        assert response.status_code == 503
```

---

## 🎨 Integração com HTTPClient do OverApi

As ferramentas integram perfeitamente com o HTTPClient existente do OverApi:

```python
from overapi.utils.http_client import HTTPClient
from overapi.testing import RequestLogger, MockHTTPServer

@pytest.mark.asyncio
async def test_with_http_client(mock_server, request_logger):
    # Setup mock
    mock_server.add_json_endpoint("/api/test", json_data={"status": "success"})

    # Usar HTTPClient do OverApi
    client = HTTPClient(timeout=10, verify_ssl=False)

    url = mock_server.get_url("/api/test")
    log = request_logger.log_request("GET", url)

    import time
    start = time.time()
    response = await client.get(url)
    elapsed = time.time() - start

    request_logger.log_response(log, response, elapsed)

    assert response.status_code == 200
    assert request_logger.get_summary()["avg_response_time"] > 0

    await client.close()
```

---

## 🚀 Executando os Testes

```bash
# Executar todos os testes das novas funcionalidades
pytest tests/test_http_workbench_features.py -v

# Executar testes específicos
pytest tests/test_http_workbench_features.py::TestRequestLogger -v
pytest tests/test_http_workbench_features.py::TestMockHTTPServer -v
pytest tests/test_http_workbench_features.py::TestWebhookTester -v

# Com coverage
pytest tests/test_http_workbench_features.py --cov=overapi.testing -v
```

---

## 📦 Estrutura de Arquivos

```
overapi/
├── testing/
│   ├── __init__.py           # Exports principais
│   ├── request_logger.py     # RequestLogger e RequestLog
│   ├── mock_server.py        # MockHTTPServer e MockEndpoint
│   └── webhook_tester.py     # WebhookTester e WebhookCall
│
tests/
├── conftest.py               # Fixtures do pytest
└── test_http_workbench_features.py  # Testes completos
```

---

## 🔗 Referências

- **HTTP Workbench**: https://github.com/bebiksior/httpworkbench
- **Documentação httpx**: https://www.python-httpx.org/
- **Documentação aiohttp**: https://docs.aiohttp.org/
- **Pytest-asyncio**: https://pytest-asyncio.readthedocs.io/

---

## 📝 Notas

### Comparação com HTTP Workbench

| Funcionalidade | HTTP Workbench | OverApi Testing |
|----------------|----------------|-----------------|
| Request Logging | ✅ Completo | ✅ Completo + Exportação |
| PoC Hosting | ✅ Web-based | ✅ Mock Server local |
| Webhook Support | ✅ Web-based | ✅ Tester local |
| Tab Completion | ✅ CLI | ❌ N/A |
| Guest Mode | ✅ | ❌ N/A |
| Self-hosted | ✅ Docker | ✅ Python/pytest |

### Vantagens da Integração

1. **Testes Automatizados**: Integração nativa com pytest
2. **Sem Dependências Externas**: Não requer serviços externos
3. **Controle Total**: Configuração programática completa
4. **Performance**: Servidores locais, sem latência de rede
5. **Debugging**: Logs detalhados e estatísticas em tempo real

---

## 🎯 Conclusão

As funcionalidades inspiradas no HTTP Workbench transformam a forma como testamos APIs no OverApi:

- ✅ **22 testes** passando com 100% de sucesso
- ✅ **3 ferramentas** principais implementadas
- ✅ **Fixtures pytest** para fácil integração
- ✅ **Documentação completa** e exemplos práticos
- ✅ **Totalmente assíncrono** usando asyncio

Essas ferramentas são essenciais para desenvolver testes robustos, realizar debugging eficiente e garantir a qualidade das APIs do OverApi.
