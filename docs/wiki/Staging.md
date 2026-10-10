# Staging

Staging lets structs be accumulated into named **staging areas** and released into a channel as a
batch, rather than sent one at a time. A staging area is identified by a `staging_id` and holds a list
of structs that have been staged but not yet released.

Staging is available over REST, from Python, and from inside the csp graph.

## Enabling staging

Either declare it on the channel:

```python
from typing import Annotated
from csp_gateway.server.gateway.csp.stage import Stage

class MyChannels(GatewayChannels):
    orders: Annotated[ts[OrderStruct], Stage()] = None
```

or enable it in a module's `connect`:

```python
channels.set_stage("orders")
```

Both are equivalent, and enabling a channel twice is a no-op. `channels.staged_channels()` lists the
channels that have staging enabled.

## Operations

`struct` and `staging_ids` combine to select what is affected. The distinction between `None` (unset)
and `[]` (empty list) is meaningful for `staging_ids`.

Each struct passed to `stage_add` or `stage_remove` must have a non-null, hashable `id`.
A missing, null, or unhashable `id` raises `ValueError` without changing staging contents or emitting events.

### `stage_add(field, struct=None, staging_ids=None)`

| `struct` | `staging_ids`  | Effect                                                                                                         |
| -------- | -------------- | -------------------------------------------------------------------------------------------------------------- |
| `None`   | `None` or `[]` | Open a new empty staging area                                                                                  |
| `None`   | `[ids]`        | `ValueError` — nothing to add                                                                                  |
| struct   | `None`         | Add to the most recent staging, or open one if none exist                                                      |
| struct   | `[]`           | Add to every staging that does not already hold it; open one if none exist, or if it is already in all of them |
| struct   | `[ids]`        | Add to each named staging; `KeyError` if an id is unknown                                                      |

Returns the list of staging ids affected.

### `stage_remove(field, struct=None, staging_ids=None)`

| `struct` | `staging_ids` | Effect                                           |
| -------- | ------------- | ------------------------------------------------ |
| `None`   | `None`        | Drop the most recent staging area entirely       |
| `None`   | `[]`          | Drop every staging area                          |
| `None`   | `[ids]`       | Empty the named staging areas, leaving them open |
| struct   | `None`        | Remove from the most recent staging holding it   |
| struct   | `[]`          | Remove from every staging holding it             |
| struct   | `[ids]`       | Remove from each named staging                   |

Note the asymmetry: with no `struct`, an unset `staging_ids` **drops** a staging area, while naming
ids only **empties** them.

A struct is matched by its `id`, so a partial struct carrying just the right `id` is enough to remove
a record.

Returns the list of staging ids affected.

### `stage_release(field, staging_ids=None)`

Releases the staged structs into the channel — each is ticked individually. Passing no ids releases
every staging area. Returns `{staging_id: [structs]}`.

A released staging area is **dropped**, not archived: its contents have been delivered on the channel
and on the release event, so it no longer appears in `stage_list` or `stage_lookup`.

### `stage_list(field, staging_id=None)` and `stage_lookup(field, staging_id=None)`

`stage_list` returns the pending staging ids, or `[staging_id]` if that one is pending and `[]` if it
is not. `stage_lookup` returns `{staging_id: [structs]}` for the pending areas.

## REST API

Each staged channel is mounted under `/api/v1/stage/{channel}` by `MountRestRoutes`. The `id` query
parameter is a comma-separated list of staging ids; omitting it is the unset case above, and passing
it empty (`?id=`) is the empty-list case.

| Method   | Operation                                                    |
| -------- | ------------------------------------------------------------ |
| `POST`   | `stage_add` — body is the struct, or empty to open a staging |
| `DELETE` | `stage_remove` — body is the struct, or empty to empty/drop  |
| `PATCH`  | `stage_release`                                              |
| `GET`    | `stage_list`                                                 |
| `PUT`    | `stage_lookup`                                               |

A validator rejecting a staged struct surfaces as a `422`; see
[Develop](Develop#Custom-Struct-Validators).

An item with a missing, null, or unhashable `id` returns `400` without changing staging.

## Observing staging from the graph

Every staging mutation is published as a `ts[StagingEvent]` delta stream, one tick per affected
record:

```python
events = channels.get_stage_events("orders")   # ts[StagingEvent]
```

| Field        | Meaning                                                      |
| ------------ | ------------------------------------------------------------ |
| `channel`    | The staged channel                                           |
| `staging_id` | The staging area affected                                    |
| `action`     | `CREATED`, `ADDED`, `REMOVED` or `RELEASED`                  |
| `items`      | The record involved, or every released record for `RELEASED` |

`CREATED` carries no items, and a staging area that is dropped reports a `REMOVED` per record followed
by a `REMOVED` with no items for the area itself.

This makes staging composable. A module can watch one channel's staging, build its own on another
channel, and follow the upstream release:

```python
@csp.node
def mirror(events: ts[StagingEvent], channels: object, field: str) -> None:
    if csp.ticked(events):
        if events.action == StagingAction.ADDED:
            for item in events.items:
                channels.stage_add(field, hedge_for(item))
        elif events.action == StagingAction.RELEASED:
            channels.stage_release(field)
```

## Driving staging from the graph

Staging can also be mutated from a timeseries, as the graph-native counterpart to calling
`stage_add`/`stage_remove`/`stage_release` directly:

```python
channels.set_stage_requests("orders", requests)   # ts[StagingRequest]
```

A `StagingRequest` carries an `action` (the same four), the `items` to stage or unstage, and
`staging_ids`. Leaving `staging_ids` unset means the unset case above; setting it to an empty list
means the empty-list case. A `REMOVED` request with no items empties rather than unstaging a record.
