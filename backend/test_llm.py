import asyncio, json, os
os.environ["DATABASE_URL"] = os.environ.get("DATABASE_URL", "postgresql+asyncpg://guardnous:guardnous@postgres:5432/guardnous")

async def test():
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from app.core.config import settings
    from app.services.agents.config import resolve_llm_settings, get_org_config
    from app.services.agents.llm import LLMClient
    from app.services.agents.tools import TOOL_SCHEMAS

    engine = create_async_engine(str(settings.DATABASE_URL))
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        # Check if there is any org config in DB
        from sqlalchemy import select, text
        rows = await db.execute(text("SELECT id, organization_id, provider, model, base_url, api_version, enabled FROM llm_configs LIMIT 5"))
        configs = rows.fetchall()
        print("DB LLM configs:", configs)

        if configs:
            org_id = configs[0][1]
            resolved = await resolve_llm_settings(db, org_id)
            print("Resolved provider:", resolved.provider)
            print("Resolved model:", resolved.model)
            print("Resolved base_url:", resolved.base_url)
            print("Resolved api_version:", resolved.api_version)
            print("Resolved api_key set:", bool(resolved.api_key))

            client = LLMClient(config=resolved)
            print("Endpoint:", client._openai_endpoint())

            # Test WITHOUT tools first
            msgs = [{"role": "user", "content": "Say hello in one word"}]
            print("\n--- Test 1: Chat without tools ---")
            try:
                result = await client.chat(msgs)
                print("SUCCESS:", result.content[:200])
            except Exception as e:
                print("FAILED:", str(e)[:300])

            # Test WITH tools
            print("\n--- Test 2: Chat with tools ---")
            try:
                result = await client.chat(msgs, tools=TOOL_SCHEMAS)
                print("SUCCESS:", result.content[:200])
            except Exception as e:
                print("FAILED:", str(e)[:300])
        else:
            print("No LLM configs in DB - using env defaults")

    await engine.dispose()

asyncio.run(test())