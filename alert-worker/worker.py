import os
import asyncio
import httpx
from datetime import datetime, timezone


INDEXER=os.getenv(
    "WAZUH_INDEXER_URL"
)

INDEXER_USER=os.getenv(
    "WAZUH_INDEXER_USER"
)

INDEXER_PASS=os.getenv(
    "WAZUH_INDEXER_PASSWORD"
)

MCP_URL=os.getenv(
    "MCP_URL"
)

MIN_LEVEL=int(
    os.getenv(
        "MIN_ALERT_LEVEL",
        "10"
    )
)

INTERVAL=int(
    os.getenv(
        "POLL_INTERVAL",
        "10"
    )
)


seen=set()


async def query_alert():

    query={
        "size":20,
        "sort":[
            {
                "@timestamp":{
                    "order":"desc"
                }
            }
        ],
        "query":{
            "range":{
                "rule.level":{
                    "gte":MIN_LEVEL
                }
            }
        }
    }


    async with httpx.AsyncClient(
        verify=False,
        auth=(
            INDEXER_USER,
            INDEXER_PASS
        )
    ) as client:

        r=await client.post(
            f"{INDEXER}/wazuh-alerts-*/_search",
            json=query,
            timeout=30
        )

        return r.json()



async def call_mcp(alert):

    srcip = (
        alert
        .get("_source",{})
        .get("data",{})
        .get("srcip")
    )


    if not srcip:
        return


    payload={
        "indicator":srcip,
        "provider":"all"
    }


    async with httpx.AsyncClient() as client:

        r=await client.post(
            f"{MCP_URL}/tools/advanced_threat_intelligence",
            json=payload,
            timeout=60
        )

        print(
            "MCP RESULT",
            r.text
        )



async def main():

    print(
        "Wazuh AI Alert Worker Started"
    )


    while True:

        try:

            data=await query_alert()


            hits=data.get(
                "hits",
                {}
            ).get(
                "hits",
                []
            )


            for alert in hits:

                alert_id=alert["_id"]


                if alert_id in seen:
                    continue


                seen.add(
                    alert_id
                )


                print(
                    "\nNEW ALERT",
                    alert_id
                )


                print(
                    alert["_source"]
                    .get("rule")
                )


                await call_mcp(
                    alert
                )


        except Exception as e:

            print(
                "ERROR",
                e
            )


        await asyncio.sleep(
            INTERVAL
        )


asyncio.run(main())
