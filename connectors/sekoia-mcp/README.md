# SEP MCP Server

Serveur [Model Context Protocol](https://modelcontextprotocol.io) qui expose
la **Sekoia Extended Platform** à Cursor, Claude Desktop, ou tout client MCP.

## Outils

| Tool | Description |
|------|-------------|
| `sep_health` | Santé control-plane |
| `sep_llm_status` | Fournisseurs LLM + MCP enregistrés |
| `sep_notify_channels` | Canaux webhook/Slack/Teams/… |
| `sep_mail_config` | Config e-mail (SMTP masqué) |
| `sep_alerts` | Alertes d’ingestion |
| `sep_intakes_health` | Santé intakes |
| `sep_notify_test_mail` | Test e-mail |
| `sep_notify_test_channel` | Test canal |
| `sep_llm_chat` | Chat via LLM configuré dans SEP |
| `sep_gateway_catalog` | Catalogue API |

## Installation locale

```bash
cd connectors/sekoia-mcp
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Cursor

Le dépôt fournit `.cursor/mcp.json`. Variables attendues (héritées de l’env
Cursor ou définies dans le bloc `env`) :

```json
{
  "mcpServers": {
    "sep": {
      "command": "python3",
      "args": ["connectors/sekoia-mcp/server.py"],
      "env": {
        "SEKOIA_CONTROLPLANE_URL": "http://127.0.0.1:8901",
        "INTERNAL_API_TOKEN": "<même valeur que .env>"
      }
    }
  }
}
```

Le control-plane publie `127.0.0.1:8901` (`FP_SEKOIA_CP_PORT`).

## Test manuel

```bash
export SEKOIA_CONTROLPLANE_URL=http://127.0.0.1:8901
export INTERNAL_API_TOKEN=…
python3 -c "
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import asyncio, os
async def main():
    params = StdioServerParameters(command='python3', args=['server.py'], env=dict(os.environ))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            print([t.name for t in tools.tools])
            out = await s.call_tool('sep_health', {})
            print(out)
asyncio.run(main())
"
```
