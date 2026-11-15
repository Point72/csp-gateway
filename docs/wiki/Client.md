# Gateway Client Example

Here is a notebook demonstrating the fundamentals of the `GatewayClient` object.

This class is a convenience wrapper around the various `HTTP` requests used to interact with a running `GatewayServer` (with `REST` endpoints enabled). It relies on the [httpx](https://www.python-httpx.org/) and [aiohttp](https://docs.aiohttp.org/en/stable/index.html) libraries, and derives most of its functionality from the [openapi](https://www.openapis.org/) specification provided on the running `GatewayServer` (usually available at `/openapi.json`).

## Client Configuration

A `GatewayClient` is configured via a `GatewayClientConfig`, a minimal [pydantic](https://docs.pydantic.dev/) model to specify details such as protocol (`http`/`https`), host, port, etc. By default, we should provide `host` and `port`.

We can also specify in the config `return_type`, which specifies how the response should be returned for `REST` requests. The available options are:

- `ReturnType.Raw`: Return the raw JSON response as a list of dictionaries
- `ReturnType.Wrapper`: Return a `ResponseWrapper` object that provides access to the raw JSON, pandas dataframe, polars dataframe, or struct conversion
- `ReturnType.Pandas`: Return a pandas DataFrame directly
- `ReturnType.Polars`: Return a polars DataFrame directly
- `ReturnType.Struct`: Return the response converted to the original struct type (or list of structs)

You can also pass string values (e.g., `return_type="wrapper"`) which will be automatically promoted to the enum.

The `ResponseWrapper` object contains additional type information which will create column names and utilize the correct data type for the constructed dataframes. It also provides an `as_struct()` method to convert JSON back to the original struct types.

### Bearer credentials

Use `bearer_token` for an existing bearer credential and configure an HTTPS hostname. Bearer credentials are sent in the
Authorization header for REST, ordinary WebSocket streaming and `stream_csp`; they are not appended to URL query strings.
Do not set both `bearer_token` and the legacy `api_key` field. The latter retains its existing query-key protocol.

Bearer clients do not follow REST redirects, and their WebSocket sessions reject redirects before following them. Configure
the canonical application endpoint rather than relying on a redirect to forward a credential. Server verification and
operation permissions remain the server's responsibility.

Bearer WebSocket connections require HTTPS for non-loopback hosts. Plain HTTP is retained only for localhost/numeric
loopback development endpoints. Construct a new client when replacing credentials; mutating the configured token is not
a coordinated refresh of existing REST or WebSocket connections.

### Environment variables

Fields not passed to `GatewayClientConfig` are read from environment variables named after the upper-cased field, following the convention of the server's `Settings` (`PORT`, `API_PREFIX`, ...): `PROTOCOL`, `HOST`, `PORT`, `API_PREFIX`, `API_VERSION`, `API_KEY`, `BEARER_TOKEN` and `RETURN_TYPE`. Explicit values take precedence, and passing either `api_key` or `bearer_token` stops both credentials being read from the environment. Subclasses of `GatewayClientConfig` read their extra fields the same way.

```bash
export HOST=gateway.example.org PORT=443 BEARER_TOKEN=...
```

```python
client = GatewayClient()  # connects to https://gateway.example.org with the bearer token
```

### API version

Requests go to `/{api_prefix}/{api_version}`, `/api/v1` by default. Point the client at a different
version with `api_version`:

```python
config = GatewayClientConfig(host="localhost", port=8000, api_version="v2")
```

`GET /api` on the server lists the versions it serves and where each is mounted.

`api_route` is deprecated in favour of `api_prefix` / `api_version`. Passing it to the constructor
still works — it is split into the two fields with a warning — and it remains readable as a derived
property. It is no longer a field, so it cannot be assigned, does not appear in `model_dump()`, and
is ignored by `model_copy(update=...)`; set `api_version` instead.

## Client Methods

A client as a small number of general-purpose methods. In alphabetical order:

- `controls`: management controls for monitoring/configuring the running server
- `last`: get the last ticked data value on a channel
- `lookup`: lookup a piece of data by `id`
- `next`: get the next ticked data value on a channel
- `send`: send some data onto a channel
- `stage`: raw staging API dispatcher (add/remove/release/list/lookup)
- `stage_add`: add a struct to staging area(s)
- `stage_new`: create a new empty staging area
- `stage_remove`: remove struct(s) from staging area(s)
- `stage_clear`: clear all structs from staging area(s) without releasing
- `stage_release`: release staged structs into the channel
- `stage_list`: list active staging areas with their contents
- `stage_lookup`: look up contents of all staging areas (including released)
- `state`: get the value of a given channel's state accumulator

Additionally, a client has some streaming methods available when websockets are configured:

- `stream`: stream data from channels (callback-based for sync client, async generator for async client)
- `subscribe`: subscribe to data on a channel (for use with manual streaming control)
- `unsubscribe`: unsubscribe from data on a channel
- `publish`: send data to a channel via websocket

> [!NOTE]
>
> For dict basket channels, streaming methods accept an optional `key` parameter to target specific basket keys.
> In `stream()`, you can pass tuples of `(channel, key)` to subscribe to specific keys.

Let's explore some of the functionality of the basic demo server. To start, we should run the demo server in another process:

```bash
python -m csp_gateway.server.demo
```

By default, this will run the server on `localhost:8000`.

## Imports

All the important objects are hoisted to the top level `csp_gateway`. Lets import and setup our client.

```python
from csp_gateway import GatewayClient, GatewayClientConfig, ReturnType
```

```python
config = GatewayClientConfig(host="localhost", port=8000, return_type=ReturnType.Wrapper)
client = GatewayClient(config)
```

The first time we use our client, it will take a little longer than usual as it tries to interrogate the running server's `openapi` specification for available methods. Once done, our request will go through, and subsequent requests will leverage this specification. Let's start with some simple status checks. If we're curious about available endpoints, we can navigate to [http://localhost:8000/redoc](http://localhost:8000/redoc) (or generally `http://<hostname>:<port>/redoc` if we're running on a different host)

```python
# heartbeat check
client.controls("heartbeat").as_json()
```

```
[{'id': '2319375449026723841',
  'timestamp': '2024-02-08T15:42:24.529000+00:00',
  'name': 'heartbeat',
  'status': 'ok',
  'data': {}}]
```

```python
# openapi spec
from IPython.display import JSON
JSON(client._openapi_spec)
```

```
<IPython.core.display.JSON object>
```

```python
# machine stats
client.controls("stats").as_json()
```

```
[{'id': '2319375449026723842',
  'timestamp': '2024-02-08T15:42:24.707000+00:00',
  'name': 'stats',
  'status': 'ok',
  'data': {'cpu': 9.5,
   'memory': 70.0,
   'memory-total': 29.98,
   'now': '2024-02-08T15:42:24.709000+00:00',
   'csp-now': '2024-02-08T15:42:24.707178+00:00',
   'host': 'devqtccrt06',
   'user': 'nk12433'}}]
```

## Last, State, Lookup, Send

Let's look at what channels we have available for `last`:

```python
client.last().as_json()
```

```
['never_ticks', 'example', 'example_list', 'str_basket', 'controls', 'basket']
```

```python
client.last("example").as_json()
```

```
[{'id': '2319375449093843665',
  'timestamp': '2024-02-08T15:42:24.674000+00:00',
  'x': 2740,
  'y': '274027402740',
  'internal_csp_struct': {'z': 12},
  'data': [0.04214403621123841,
   0.2777565518959145,
   0.8924844325909429,
   0.34476509440152614,
   0.20822638755894596,
   0.9031877679300264,
   0.6124216455541363,
   0.9848707643841728,
   0.618990569185841,
   0.5582898776824039],
  'mapping': {'2740': 2740}}]
```

```python
client.last("basket").as_json()
```

```
[{'id': '2319375449093843662',
  'timestamp': '2024-02-08T15:42:24.674000+00:00',
  'x': 2740,
  'y': '2740',
  'internal_csp_struct': {'z': 12},
  'data': [0.4358136168874479,
   0.9866855468623034,
   0.7370733232695977,
   0.2473537128693415,
   0.33386372679049414,
   0.855059230303771,
   0.23094109313426026,
   0.15447614788689634,
   0.028364551604262656,
   0.3461902446665106],
  'mapping': {'2740': 2740}},
 {'id': '2319375449093843663',
  'timestamp': '2024-02-08T15:42:24.674000+00:00',
  'x': 2740,
  'y': '27402740',
  'internal_csp_struct': {'z': 12},
  'data': [0.6377430109697712,
   0.9945325429350265,
   0.21250129814975605,
   0.7428201790683369,
   0.748495275897516,
   0.7495896160497952,
   0.052122337434189814,
   0.28571381888827774,
   0.15916263368074623,
   0.5859045937429175],
  'mapping': {'2740': 2740}},
 {'id': '2319375449093843664',
  'timestamp': '2024-02-08T15:42:24.674000+00:00',
  'x': 2740,
  'y': '274027402740',
  'internal_csp_struct': {'z': 12},
  'data': [0.09866777488177447,
   0.9338912139505706,
   0.4008220677833475,
   0.3970734597363782,
   0.5698499914906174,
   0.9409930883247017,
   0.40646346343477957,
   0.6625127227460902,
   0.6663193112635586,
   0.7144147693528888],
  'mapping': {'2740': 2740}}]
```

```python
client.last("basket").as_pandas_df()
```

<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

```
.dataframe tbody tr th {
    vertical-align: top;
}

.dataframe thead th {
    text-align: right;
}
```

</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>id</th>
      <th>timestamp</th>
      <th>x</th>
      <th>y</th>
      <th>data</th>
      <th>internal_csp_struct.z</th>
      <th>mapping.2740</th>
      <th>internal_csp_struct</th>
      <th>mapping</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>2319375449093843662</td>
      <td>2024-02-08T15:42:24.674000+00:00</td>
      <td>2740</td>
      <td>2740</td>
      <td>[0.4358136168874479, 0.9866855468623034, 0.737...</td>
      <td>12</td>
      <td>2740</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>1</th>
      <td>2319375449093843663</td>
      <td>2024-02-08T15:42:24.674000+00:00</td>
      <td>2740</td>
      <td>27402740</td>
      <td>[0.6377430109697712, 0.9945325429350265, 0.212...</td>
      <td>12</td>
      <td>2740</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>2</th>
      <td>2319375449093843664</td>
      <td>2024-02-08T15:42:24.674000+00:00</td>
      <td>2740</td>
      <td>274027402740</td>
      <td>[0.09866777488177447, 0.9338912139505706, 0.40...</td>
      <td>12</td>
      <td>2740</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
  </tbody>
</table>
</div>

State channels are used to perform state accumulation over a number of ticks. The example server doesn't do anything too interesting, but we can access these channels nevertheless.

```python
client.state().as_json()
```

```
['example', 'example_with_state', 'example_with_state_alternative', 'example_with_state_multiple']
```

```python
client.state("example_with_state").as_pandas_df().tail()

# We note that there are a large number of columns in the above dataframe.
# This is because `mapping` is a dict with different keys for eery row.
# To accommodate all of them, the returned pandas dataframe has a column for any key present in the `mapping` attribute of any `ExampleData` Struct
```

<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

```
.dataframe tbody tr th {
    vertical-align: top;
}

.dataframe thead th {
    text-align: right;
}
```

</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>id</th>
      <th>timestamp</th>
      <th>x</th>
      <th>y</th>
      <th>data</th>
      <th>internal_csp_struct.z</th>
      <th>mapping.1</th>
      <th>mapping.2</th>
      <th>mapping.3</th>
      <th>mapping.4</th>
      <th>...</th>
      <th>mapping.2733</th>
      <th>mapping.2734</th>
      <th>mapping.2735</th>
      <th>mapping.2736</th>
      <th>mapping.2737</th>
      <th>mapping.2738</th>
      <th>mapping.2739</th>
      <th>mapping.2740</th>
      <th>internal_csp_struct</th>
      <th>mapping</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>2737</th>
      <td>2319375449093843649</td>
      <td>2024-02-08T15:42:20.674000+00:00</td>
      <td>2736</td>
      <td>273627362736</td>
      <td>[0.49893600652720127, 0.853167719853599, 0.315...</td>
      <td>12</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>2736.0</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>2738</th>
      <td>2319375449093843653</td>
      <td>2024-02-08T15:42:21.674000+00:00</td>
      <td>2737</td>
      <td>273727372737</td>
      <td>[0.5454735801588998, 0.9131743196563596, 0.793...</td>
      <td>12</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>2737.0</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>2739</th>
      <td>2319375449093843657</td>
      <td>2024-02-08T15:42:22.674000+00:00</td>
      <td>2738</td>
      <td>273827382738</td>
      <td>[0.9647636482625623, 0.5143565076074796, 0.187...</td>
      <td>12</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>2738.0</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>2740</th>
      <td>2319375449093843661</td>
      <td>2024-02-08T15:42:23.674000+00:00</td>
      <td>2739</td>
      <td>273927392739</td>
      <td>[0.11711046455122953, 0.4766317339540975, 0.78...</td>
      <td>12</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>2739.0</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>2741</th>
      <td>2319375449093843665</td>
      <td>2024-02-08T15:42:24.674000+00:00</td>
      <td>2740</td>
      <td>274027402740</td>
      <td>[0.04214403621123841, 0.2777565518959145, 0.89...</td>
      <td>12</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>2740.0</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
  </tbody>
</table>
<p>5 rows × 2748 columns</p>
</div>

We can lookup individual data points using `lookup`. This is a bit of a silly example when we're just looking at a single channel, but can be valuable when you have lots of interconnected channels.

```python
# get the last tick, then lookup by id
last = client.last("example").as_json()[0]
last_id = last["id"]
client.lookup("example", last_id).as_json()
```

```
[{'id': '2319375449093843677',
  'timestamp': '2024-02-08T15:42:27.674000+00:00',
  'x': 2743,
  'y': '274327432743',
  'internal_csp_struct': {'z': 12},
  'data': [0.11397482092369415,
   0.8082756046612577,
   0.5269320054610495,
   0.09017303257799603,
   0.8346823428352325,
   0.12803545825097729,
   0.8563661560959381,
   0.8337489771318026,
   0.9665893466463059,
   0.7835381554236741],
  'mapping': {'2743': 2743}}]
```

Finally, we can send our own data into the API using `send`.

```python
client.send(
    "example",
    {
        "x": 12,
        "y": "HEY!",
        "internal_csp_struct": {"z": 13}
    }
)

client.state("example_with_state").as_pandas_df().tail()
```

<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

```
.dataframe tbody tr th {
    vertical-align: top;
}

.dataframe thead th {
    text-align: right;
}
```

</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>id</th>
      <th>timestamp</th>
      <th>x</th>
      <th>y</th>
      <th>data</th>
      <th>internal_csp_struct.z</th>
      <th>mapping.1</th>
      <th>mapping.2</th>
      <th>mapping.3</th>
      <th>mapping.4</th>
      <th>...</th>
      <th>mapping.2737</th>
      <th>mapping.2738</th>
      <th>mapping.2739</th>
      <th>mapping.2740</th>
      <th>mapping.2741</th>
      <th>mapping.2742</th>
      <th>mapping.2743</th>
      <th>mapping.2744</th>
      <th>internal_csp_struct</th>
      <th>mapping</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>2742</th>
      <td>2319375449093843669</td>
      <td>2024-02-08T15:42:25.674000+00:00</td>
      <td>2741</td>
      <td>274127412741</td>
      <td>[0.7755552349359216, 0.1125930704396867, 0.339...</td>
      <td>12</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>2741.0</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>2743</th>
      <td>2319375449093843673</td>
      <td>2024-02-08T15:42:26.674000+00:00</td>
      <td>2742</td>
      <td>274227422742</td>
      <td>[0.6067900468053619, 0.7816859434221093, 0.536...</td>
      <td>12</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>2742.0</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>2744</th>
      <td>2319375449093843677</td>
      <td>2024-02-08T15:42:27.674000+00:00</td>
      <td>2743</td>
      <td>274327432743</td>
      <td>[0.11397482092369415, 0.8082756046612577, 0.52...</td>
      <td>12</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>2743.0</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>2745</th>
      <td>2319375449093843681</td>
      <td>2024-02-08T15:42:28.674000+00:00</td>
      <td>2744</td>
      <td>274427442744</td>
      <td>[0.4131649893399658, 0.3784834347835063, 0.987...</td>
      <td>12</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>2744.0</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>2746</th>
      <td>2319375449093843682</td>
      <td>2024-02-08T15:42:28.846000+00:00</td>
      <td>12</td>
      <td>HEY!</td>
      <td>[]</td>
      <td>13</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>...</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
  </tbody>
</table>
<p>5 rows × 2752 columns</p>
</div>

The REST API uses pydantic validation for `send` requests. Since `ExampleData` has a `__validators__` attribute defined, the pydantic version of the GatewayStruct has those functions ran for validation before propagating the sent value through the graph. `ExampleData` has validation performed that asserts the value of `x` is not negative. When we try to pass a negative value in, we get an error on the send, but the graph does not crash. The details of the error are provided in the response.

```python
client.send("example", {"x": -12, "y": "HEY!"})
```

```
---------------------------------------------------------------------------

ServerUnprocessableException              Traceback (most recent call last)

Cell In[14], line 1
----> 1 client.send("example", {"x": -12, "y": "HEY!"})


File /isilon/home/nk12433/bitbucket/csp-gateway/csp_gateway/client/client.py:88, in _raiseIfNotMounted.<locals>._wrapped_foo(self, field, *args, **kwargs)
     86 if check_field and check_field not in self._mounted_apis[group]:
     87     raise ServerRouteNotMountedException("Route not mounted in group {}: {}".format(group, field))
---> 88 return foo(self, field, *args, **kwargs)


File /isilon/home/nk12433/bitbucket/csp-gateway/csp_gateway/client/client.py:550, in SyncGatewayClientMixin.send(self, field, data, timeout)
    548 @_raiseIfNotMounted
    549 def send(self, field: str = "", data: Any = None, timeout: float = _DEFAULT_TIMEOUT) -> ResponseType:
--> 550     return self._post("{}/{}".format("send", field), data=data, timeout=timeout)


File /isilon/home/nk12433/bitbucket/csp-gateway/csp_gateway/client/client.py:320, in BaseGatewayClient._post(self, route, params, data, timeout)
    313 def _post(
    314     self,
    315     route: str,
   (...)
    318     timeout: float = _DEFAULT_TIMEOUT,
    319 ) -> ResponseType:
--> 320     return self._handle_response(POST(self._buildroute(route), params=params, json=data), route=route)


File /isilon/home/nk12433/bitbucket/csp-gateway/csp_gateway/client/client.py:293, in BaseGatewayClient._handle_response(self, resp, route)
    291     raise ServerRouteNotFoundException(resp_json.get("detail"))
    292 elif resp.status_code == 422:
--> 293     raise ServerUnprocessableException(resp_json.get("detail"))
    294 raise ServerUnknownException(f"{resp.status_code}: {resp_json.get('detail')}")


ServerUnprocessableException: [{'loc': ['body'], 'msg': 'value is not a valid list', 'type': 'type_error.list'}, {'loc': ['body', 'x'], 'msg': 'value must be non-negative.', 'type': 'value_error'}]
```

## Staging

Channels with staging enabled allow you to accumulate structs into staging areas before releasing them into the graph. The client provides several convenience methods for this workflow.

```python
# Create a new empty staging area
result = client.stage_new("example_with_stage")
# Returns: {"<staging_id>": []}
staging_id = list(result.keys())[0]
```

```python
# Add a struct to a specific staging area
client.stage_add("example_with_stage", data={"x": 42, "y": "hello"}, staging_ids=[staging_id])
# Returns: {"<staging_id>": [{"x": 42, "y": "hello", "id": "...", ...}]}
```

```python
# List active staging areas with their contents
client.stage_list("example_with_stage")
# Returns: {"<staging_id>": [<items>]}
```

```python
# Look up contents of all staging areas (including previously released)
client.stage_lookup("example_with_stage")
# Returns: {"<staging_id>": [<items>], "<old_staging_id>": [<items>], ...}
```

```python
# Release staged structs into the channel (pushes them as ticks)
client.stage_release("example_with_stage", staging_ids=[staging_id])
# Returns: {"<staging_id>": [<released items>]}
```

```python
# Remove specific structs or clear entire staging areas
client.stage_remove("example_with_stage", data=item_dict, staging_ids=[staging_id])
client.stage_clear("example_with_stage", staging_ids=[staging_id])
```

The raw `stage()` method is also available for direct control:

```python
client.stage("example_with_stage", method="add", data={"x": 1}, staging_ids=None)
client.stage("example_with_stage", method="list")
client.stage("example_with_stage", method="lookup")
client.stage("example_with_stage", method="release", staging_ids=[staging_id])
```

## Next

The running `GatewayServer` is a synchronous system, and we're interacting it via asynchronous `REST` requests. However, we can still perform actions like "wait for the next tick". This can be dangerous and lead to race conditions, but it can still be useful in certain circumstances.

```python
client.next("example").as_json()
```

```
[{'id': '2319375449093843978',
  'timestamp': '2024-02-08T15:43:42.674000+00:00',
  'x': 2818,
  'y': '281828182818',
  'internal_csp_struct': {'z': 12},
  'data': [0.04177423824388882,
   0.9576947646141436,
   0.8797403395027252,
   0.07591623282958704,
   0.9012930744265685,
   0.18036455365706483,
   0.8368363380941581,
   0.2958674194835621,
   0.7139586435389245,
   0.7923286062539309],
  'mapping': {'2818': 2818}}]
```

Note that this call will **block** until the next value ticks.

## Streaming

If our webserver is configured with websockets, we can also stream data out of channels. A simple example that prints out channel data is provided.

```python
client.stream(channels=["example"], callback=print)
```

```
{'channel': 'example', 'data': [{'id': '2319375449093843998', 'timestamp': '2024-02-08T15:43:47.674000+00:00', 'x': 2823, 'y': '282328232823', 'internal_csp_struct': {'z': 12}, 'data': [0.7733188729889257, 0.3505657636995222, 0.37947167012560834, 0.5813803503480363, 0.4224356797080008, 0.7882237596018704, 0.7501837172662043, 0.3014755082030406, 0.11662082552665554, 0.1760084143205467], 'mapping': {'2823': 2823}}]}
{'channel': 'example', 'data': [{'id': '2319375449093844002', 'timestamp': '2024-02-08T15:43:48.674000+00:00', 'x': 2824, 'y': '282428242824', 'internal_csp_struct': {'z': 12}, 'data': [0.7935760696606141, 0.04502649843404605, 0.5772625402239133, 0.6083217755224994, 0.949351551805679, 0.2619775463100148, 0.6036207137382622, 0.0005275136962938909, 0.827541831606724, 0.88364890012582], 'mapping': {'2824': 2824}}]}
{'channel': 'example', 'data': [{'id': '2319375449093844006', 'timestamp': '2024-02-08T15:43:49.674000+00:00', 'x': 2825, 'y': '282528252825', 'internal_csp_struct': {'z': 12}, 'data': [0.94651479729033, 0.467475460176196, 0.9733450874656052, 0.9147464907192908, 0.38929946260272874, 0.1036030662184213, 0.4733157330556428, 0.8232663407131828, 0.13931853773352143, 0.6087557420151944], 'mapping': {'2825': 2825}}]}
```

## Asynchronous client

All of the above can also be used in an `async` fashion. Note that by default, the `GatewayClient` class is an alias for the `SyncGatewayClient` class. The only differences are:

- all methods are `async` instead of synchronous
- `stream` is an infinite generator, rather than callback-based (so takes no `callback` argument)

```python
from csp_gateway import AsyncGatewayClient
```

```python
async_client= AsyncGatewayClient(config)
```

```python
async def print_all():
    async for datum in async_client.stream(channels=["example", "example_list"]):
        print(datum)
```

```python
await print_all()
```

```
{'channel': 'example_list', 'data': [{'id': '2319375449093844034', 'timestamp': '2024-02-08T15:43:56.674000+00:00', 'x': 2832, 'y': '283228322832', 'internal_csp_struct': {'z': 12}, 'data': [0.6036805890478953, 0.6749444877468045, 0.5497958103280356, 0.7245526415750495, 0.8203822683954279, 0.7692240209863609, 0.6725744504378558, 0.7092152352091319, 0.22125780238809134, 0.8010351708291975], 'mapping': {'2832': 2832}}]}
{'channel': 'example', 'data': [{'id': '2319375449093844034', 'timestamp': '2024-02-08T15:43:56.674000+00:00', 'x': 2832, 'y': '283228322832', 'internal_csp_struct': {'z': 12}, 'data': [0.6036805890478953, 0.6749444877468045, 0.5497958103280356, 0.7245526415750495, 0.8203822683954279, 0.7692240209863609, 0.6725744504378558, 0.7092152352091319, 0.22125780238809134, 0.8010351708291975], 'mapping': {'2832': 2832}}]}
{'channel': 'example_list', 'data': [{'id': '2319375449093844038', 'timestamp': '2024-02-08T15:43:57.674000+00:00', 'x': 2833, 'y': '283328332833', 'internal_csp_struct': {'z': 12}, 'data': [0.6140667806797164, 0.30583287063145703, 0.4104660866032377, 0.2342635297957093, 0.675205453488038, 0.5500391636385289, 0.7266396287394276, 0.5642695215832931, 0.38469805427239556, 0.09133929703456811], 'mapping': {'2833': 2833}}]}
{'channel': 'example', 'data': [{'id': '2319375449093844038', 'timestamp': '2024-02-08T15:43:57.674000+00:00', 'x': 2833, 'y': '283328332833', 'internal_csp_struct': {'z': 12}, 'data': [0.6140667806797164, 0.30583287063145703, 0.4104660866032377, 0.2342635297957093, 0.675205453488038, 0.5500391636385289, 0.7266396287394276, 0.5642695215832931, 0.38469805427239556, 0.09133929703456811], 'mapping': {'2833': 2833}}]}
{'channel': 'example_list', 'data': [{'id': '2319375449093844042', 'timestamp': '2024-02-08T15:43:58.674000+00:00', 'x': 2834, 'y': '283428342834', 'internal_csp_struct': {'z': 12}, 'data': [0.5913608421402291, 0.8327500322981758, 0.7335846102808938, 0.019410934029975624, 0.5931185456840745, 0.6139373901871275, 0.22799843163499478, 0.9269009414380454, 0.18223248762349398, 0.15142314141377], 'mapping': {'2834': 2834}}]}
{'channel': 'example', 'data': [{'id': '2319375449093844042', 'timestamp': '2024-02-08T15:43:58.674000+00:00', 'x': 2834, 'y': '283428342834', 'internal_csp_struct': {'z': 12}, 'data': [0.5913608421402291, 0.8327500322981758, 0.7335846102808938, 0.019410934029975624, 0.5931185456840745, 0.6139373901871275, 0.22799843163499478, 0.9269009414380454, 0.18223248762349398, 0.15142314141377], 'mapping': {'2834': 2834}}]}
```

## Command line

`csp-gateway-client` wraps the synchronous client in a command line tool that prints responses as JSON, ready to pipe into `jq` or other tools. It can also be run as `python -m csp_gateway.client`.

```bash
csp-gateway-client --port 8000 last example
csp-gateway-client state example --filter x '>=' 5 | jq length
csp-gateway-client --pretty controls stats
csp-gateway-client send example '{"x": 1, "y": "1"}'
csp-gateway-client stream example basket/A -n 10 | jq '.data[].x'
```

The commands mirror the client methods:

| Command    | Description                                                                    |
| :--------- | :----------------------------------------------------------------------------- |
| `last`     | last ticked value of a channel; with no channel, lists channels                |
| `next`     | wait for the next ticked value of a channel                                    |
| `state`    | state of a channel, filtered with `--filter ATTR OP VALUE` or a JSON `--query` |
| `lookup`   | look up a value by `id`                                                        |
| `send`     | send a JSON object or list into a channel                                      |
| `controls` | run a management control such as `heartbeat`, `stats` or `shutdown`            |
| `stage`    | `list`, `lookup`, `new`, `add`, `remove`, `clear` or `release` staging areas   |
| `stream`   | stream channels over the websocket, one JSON message per line                  |
| `routes`   | fields mounted under each API group                                            |
| `openapi`  | the server's OpenAPI specification                                             |

Use `channel/key` to address one key of a dict basket. JSON arguments (`send` data, `--data`, `--query`) accept inline JSON, `@path` to a file, or `-` for stdin. Run `csp-gateway-client COMMAND --help` for the options of each command.

Connection options (`--host`, `--port`, `--protocol`, `--api-prefix`, `--api-version`, `--api-key`, `--bearer-token`) map to the `GatewayClientConfig` fields of the same name; unset options are read from the [environment](#environment-variables), then fall back to the defaults. Each JSON document is printed on a single line, which suits `jq`; `--pretty` indents the output and `--sort-keys` sorts keys. Global options may be given before or after the command.

Responses are written to stdout. Errors are written to stderr and exit with status 1; usage errors exit with status 2. `stream` filters out the server's heartbeat messages unless `--heartbeats` is given, and stops after `--limit` messages, after `--idle-timeout` seconds without a message, or on Ctrl-C.

### Building an application CLI

Applications built on csp-gateway can subclass `GatewayClientCLI` to get the same connection handling, output and built-in commands, and add their own. Commands are methods decorated with `@command`; `@argument` takes the same parameters as `ArgumentParser.add_argument`. A command receives the client and the parsed arguments and returns JSON-serializable data. Returning an iterator prints each item as its own JSON document, and returning `None` prints nothing.

```python
from csp_gateway.client import GatewayClient
from csp_gateway.client.cli import GatewayClientCLI, argument, command


class MyAppClient(GatewayClient):
    def orders_for(self, account: str):
        return [order for order in self.last("orders") if order["account"] == account]


class MyAppCLI(GatewayClientCLI):
    prog = "my-app"
    description = "Query a running my-app gateway."
    client_class = MyAppClient

    # Remove a built-in command
    openapi = None

    @command(aliases=["o"])
    @argument("account")
    def orders(self, client, args):
        """Orders on the last tick for one account."""
        return client.orders_for(args.account)


def main():
    return MyAppCLI.main()
```

Register `main` as a console script in the application's `pyproject.toml`:

```toml
[project.scripts]
my-app = "my_app.cli:main"
```

Other extension points:

- Redefine a built-in command method (such as `last`) with `@command` to replace it.
- Set `config_class` to a `GatewayClientConfig` subclass, and override `add_global_arguments` and `config_kwargs` (calling `super()`) to expose its extra fields as options.
- Override `make_client` for custom client construction, `emit` for a different output format, or `add_commands` to build subparsers directly.
- `client_class` must be a synchronous client, such as a `GatewayClient` subclass.
