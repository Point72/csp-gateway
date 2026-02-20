import argparse
import asyncio

from csp_gateway import AsyncGatewayClient, GatewayClient, GatewayClientConfig

# Put your configuration here
config = GatewayClientConfig(host="HOSTNAME", port=8000, api_key="12345")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="WebSocket demo")
    parser.add_argument("choice", choices=["sync", "async"])
    args = parser.parse_args()

    if args.choice == "sync":
        print("Running synchronous example...")
        sync_client = GatewayClient(config)

        # Sync Example
        sync_client.stream(channels=["example", "example_list"], callback=print)

    else:
        print("Running asynchronous example...")
        async_client = AsyncGatewayClient(config)

        # Async example
        async def print_all():
            async for datum in async_client.stream(channels=[]):
                print(datum)

        async def subscribe():
            await async_client.subscribe("example")
            await async_client.subscribe("example_list")
            await async_client.publish("example", {"x": 12345, "y": "54321"})

        all_routines = asyncio.gather(print_all(), subscribe())

        asyncio.get_event_loop().run_until_complete(all_routines)
