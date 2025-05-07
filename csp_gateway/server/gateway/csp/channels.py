import warnings
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime
from logging import getLogger
from typing import (
    TYPE_CHECKING,
    Any,
    DefaultDict,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    get_args,
    get_origin,
)

import csp
from csp import Enum, ts
from csp.impl.genericpushadapter import GenericPushAdapter
from csp.impl.types.container_type_normalizer import ContainerTypeNormalizer
from csp.impl.types.tstype import TsType, isTsType
from csp.impl.wiring.delayed_edge import DelayedEdge, _UnsetNodedef
from csp.impl.wiring.edge import Edge
from csp.impl.wiring.feedback import FeedbackInputDef, FeedbackOutputDef
from pydantic import BaseModel, ConfigDict, PrivateAttr, create_model
from pydantic._internal._model_construction import ModelMetaclass

from csp_gateway.utils import (
    GatewayStruct,
    NoProviderException,
    get_dict_basket_key_type,
    get_dict_basket_value_tstype,
    get_dict_basket_value_type,
    is_dict_basket,
    is_list_basket,
)

from .futures import (
    ConcurrentFutureAdapter,
    named_on_request_node,
    named_on_request_node_dict_basket,
    named_wait_for_next_node,
    named_wait_for_next_node_dict_basket,
)
from .state import State, build_track_state_node

if TYPE_CHECKING:
    from csp_gateway.utils import Query


# TODO: Python 3.10 reintroduces types.NoneType
_NONE_TYPE = type(None)
_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD = "csp_engine_timestamp"

log = getLogger(__name__)


class _SnapshotModelBaseClass(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid", coerce_numbers_to_str=True)


def _recursive_remove_enums(vals_dict):
    for k, v in list(vals_dict.items()):
        is_enum_key = isinstance(k, Enum)
        is_dict_value = isinstance(v, dict)
        if is_enum_key:
            v = vals_dict.pop(k)
            k = k.name
        if is_dict_value:
            v = _recursive_remove_enums(v)
        if is_enum_key or is_dict_value:
            vals_dict[k] = v
    return vals_dict


def _get_ts_pydantic_field_type(outer_type):
    # TODO: we only store Gateway Structs and Lists with Gateway Structs
    if is_dict_basket(outer_type):
        # dict baskets, ensure key is enum and then process value
        key_type = get_args(outer_type)[0]
        ts_type = get_args(outer_type)[1].typ
        normalized_type = ContainerTypeNormalizer.normalize_type(ts_type)
        is_list = get_origin(normalized_type) is list
        if is_list:
            ts_type = get_args(normalized_type)[0]

        if isinstance(ts_type, type) and issubclass(ts_type, GatewayStruct):
            if is_list:
                return (
                    Optional[Dict[key_type, List[ts_type]]],
                    None,
                )
            else:
                return (
                    Optional[Dict[key_type, ts_type]],
                    None,
                )

    # if origin_type is dict then its not a ts type
    elif isTsType(outer_type):
        ts_type = outer_type.typ
        normalized_type = ContainerTypeNormalizer.normalize_type(ts_type)
        is_list = get_origin(normalized_type) is list
        if is_list:
            ts_type = get_args(normalized_type)[0]
        if not isinstance(ts_type, type) or (not issubclass(ts_type, GatewayStruct) and not issubclass(ts_type, State)):
            # if not issubclass(ts_type, csp.Struct):
            #     raise Exception(
            #         "GatewayChannels instances can only contain timeseries of GatewayStruct, got: {}".format(
            #             ts_type
            #         )
            #     )
            warnings.warn(
                ("GatewayChannels received a type other than GatewayStruct, this channel will not be available via web APIs: {}".format(ts_type)),
                stacklevel=1,
            )
        if isinstance(ts_type, type) and issubclass(ts_type, GatewayStruct):
            if is_list:
                return (
                    Optional[List[ts_type]],
                    None,
                )
            else:
                return (
                    Optional[ts_type],
                    None,
                )


def _remove_field_attributes(cls, processed_classes: Set[Type[BaseModel]]) -> None:
    processed_classes.add(cls)

    if hasattr(cls, "model_fields"):
        for field_name in cls.model_fields:
            delattr(cls, field_name)

    if hasattr(cls, "__bases__"):
        for base in cls.__bases__:
            if base not in processed_classes:
                processed_classes.add(base)
                _remove_field_attributes(base, processed_classes)


def _add_field_attributes(cls):
    if hasattr(cls, "model_fields"):
        for field_name in cls.model_fields:
            setattr(cls, field_name, field_name)


class ChannelsMetaclass(ModelMetaclass):
    def __new__(mcs: Any, name: Any, bases: Any, namespace: Any, **kwargs: Any) -> Any:
        # pydantic 2 does not like when class level attributes shadow fields. It will use the class level attribute
        # values as default values for the child class, so we remove them first, then add them back later.
        modified_bases = set()
        for base in bases:
            _remove_field_attributes(base, modified_bases)

        cls = super().__new__(mcs, name, bases, namespace, **kwargs)
        for base in modified_bases:
            _add_field_attributes(base)

        _add_field_attributes(cls)
        ts_pydantic_field_types = {}
        for field_name, field_type in cls.model_fields.items():
            # Validate that timeseries types contain structs or list of structs
            outer_type = field_type.annotation
            ts_pydantic_field_type = _get_ts_pydantic_field_type(outer_type)
            if ts_pydantic_field_type is not None:
                ts_pydantic_field_types[field_name] = ts_pydantic_field_type

        ts_pydantic_field_types[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD] = (Optional[datetime], None)
        dynamic_pydantic_model = create_model("_snapshot_model", __base__=_SnapshotModelBaseClass, **ts_pydantic_field_types)
        cls._snapshot_model = dynamic_pydantic_model
        return cls


class Channels(BaseModel, metaclass=ChannelsMetaclass):
    """Collection of Channels that gateway modules and users use to communicate with each other.

    Each channel is a csp time series ``TsType`` of an underlying struct type which represents the type of data
    being streamed on that channel. The ``GatewayChannels`` object serves as a streaming data catalog.

    The names of the channels match the names that are used via the different APIs, i.e. REST, WebSockets, Perspective, etc.
    It is expected that developers interact with channels through these APIs (or via get_channel/set_channel in csp).

    Channels that begin with ``s_`` are "state" channels, meaning that they represent a collection of messages, typically
    the last message grouped by some key (i.e. security id). These are not meant to be interacted with directly, but rather
    through the "state" part of the REST API.
    """

    model_config = dict(arbitrary_types_allowed=True)  # (for FeedbackOutputDef)

    _finalized: bool = PrivateAttr(default=False)

    # we use a Dict with None as the value instead of a set for each channel
    # to preserve insertion order
    _dynamic_keys: DefaultDict[str, Dict[Any, _NONE_TYPE]] = PrivateAttr(default_factory=lambda: defaultdict(dict))
    _delayed_channels: Dict[str, DelayedEdge] = PrivateAttr(default_factory=dict)
    _delayed_edge_providers: Dict[str, List[Tuple[Any, Edge]]] = PrivateAttr(default_factory=lambda: defaultdict(list))
    _block_set_channels_until: Optional[datetime] = PrivateAttr(default=None)
    _override_blocks: Dict[Any, Optional[datetime]] = PrivateAttr(default_factory=dict)
    _feedbacks: Dict[int, FeedbackOutputDef] = PrivateAttr(default_factory=dict)

    _state_requests: Dict[Tuple[str, Optional[Union[str, int]]], Any] = PrivateAttr(default_factory=dict)
    _last_requests: Dict[Tuple[str, Optional[Union[str, int]]], Any] = PrivateAttr(default_factory=dict)
    _next_requests: Dict[Tuple[str, Optional[Union[str, int]]], Any] = PrivateAttr(default_factory=dict)
    _send_channels: Dict[Tuple[str, Optional[Union[str, int]]], Any] = PrivateAttr(default_factory=dict)

    # inside context, the module being attached
    _module_being_attached: Any = PrivateAttr(None)
    # inside context, the requirements of the module being attached
    _module_being_attached_required: Optional[Set[str]] = PrivateAttr(None)

    # all modules that are required by other modules
    _modules_require: List[Tuple[Any, str]] = PrivateAttr(default_factory=list)

    # all modules that are used, but not required, by other modules
    _modules_optional: List[Tuple[Any, str]] = PrivateAttr(default_factory=list)

    # graph of channel connections
    # maps channel name to {set: [providers], get: [consumers]}
    _modules_connections_graph: Dict[str, Dict[str, List[Any]]] = PrivateAttr(default_factory=dict)

    _feedback_count: int = PrivateAttr(default=0)

    def dynamic_keys(self) -> Optional[Dict[str, List[Any]]]:
        """Define dynamic dictionary keys by field, driven by data from the channels."""
        ...

    @contextmanager
    def _connection_context(self, module: Any) -> Any:
        """
        Context manager to track channel usage by modules.

        This context manager is used to keep track of which modules use which channels.
        The channel requirements can be specified using the 'requires' attribute of the module.

        Attributes:
            module (Any): The module for which the channel usage is being tracked.

        Usage:
            - If `requires` is None, all channels are assumed required
            - Else it must be of type ChannelSelection or a List and ONLY the channels
                specified by `requires` are required.
        """
        requires = getattr(module, "requires", None)
        if requires is not None:
            if isinstance(requires, list):
                self._module_being_attached_required = set(requires)
            else:
                self._module_being_attached_required = set(requires.select_from(self))

        override_block = getattr(module, "block_set_channels_until", None)
        if override_block is not None:
            self._override_blocks[module] = override_block

        # set module context to the module being attached
        self._module_being_attached = module

        # defer to context
        yield self

        # unset module context now that done with module
        self._module_being_attached = None

        # reset requirements now that done with module
        self._module_being_attached_required = None

    def _handle_module_requirements(self, field: str) -> None:
        module = self._module_being_attached
        if self._module_being_attached_required is None or field in self._module_being_attached_required:
            self._modules_require.append((module, field))
        else:
            self._modules_optional.append((module, field))

    def _add_field_to_graph(
        self,
        field: str,
        module: Any,
        setting: bool = False,
        indexer: Union[int, str] = None,
    ):
        # TODO handle indexer
        # add to graph
        if field not in self._modules_connections_graph:
            self._modules_connections_graph[field] = {"getters": [], "setters": []}

        if isinstance(module, str):
            name = f"{module}{f'<{indexer}>' if indexer else ''}"
        else:
            name = f"{module.__class__.__name__}{f'<{indexer}>' if indexer else ''}"

        if setting:
            if name not in self._modules_connections_graph[field]["setters"]:
                self._modules_connections_graph[field]["setters"].append(name)
        else:
            if name not in self._modules_connections_graph[field]["getters"]:
                self._modules_connections_graph[field]["getters"].append(name)

    def _validate_field_name(self, field: str) -> bool:
        return field in self.model_fields

    def keys_for_channel(self, field: str) -> Optional[Dict[Any, _NONE_TYPE]]:
        """Return the set of keys for the channel"""
        if not self._finalized:
            raise Exception("Must finalize graph first")
        return self._keys_for_channel(field)

    def _keys_for_channel(self, field: str) -> Optional[Dict[Any, _NONE_TYPE]]:
        tstype = self.get_outer_type(field)
        if is_dict_basket(tstype):
            # get type of key in basket
            basket_key_type = get_dict_basket_key_type(tstype)
            if issubclass(basket_key_type, Enum):
                return {e: None for e in basket_key_type}
            else:
                return self._dynamic_keys.get(field, {})
        return None

    def _finalize(self) -> None:
        all_required_channels = set(x[1] for x in self._modules_require)
        all_optional_channels = set(x[1] for x in self._modules_optional if x not in all_required_channels)
        who_requires: Dict[str, Any] = {x: [] for x in all_required_channels}
        who_requires_id: Dict[str, id] = {x: set() for x in all_required_channels}
        for module, requires in self._modules_require:
            # Avoid checking module equality here, because it may fail if modules contain numpy arrays, csp edges, etc,
            # or it may be non-performant; instead look at modules based on id.
            if id(module) not in who_requires_id[requires]:
                who_requires[requires].append(module)
                who_requires_id[requires].add(id(module))

        if not self._finalized:
            # first ensure everything is provided
            for (
                field,
                list_of_edges_and_modules,
            ) in self._delayed_edge_providers.items():
                # extract type
                tstype = self.get_outer_type(field)

                if len(list_of_edges_and_modules) == 0:
                    # Skip to next
                    continue

                if is_dict_basket(tstype):
                    # assemble by key type
                    list_of_channels_per_key: Dict[str, List[Edge]] = {k: [] for k in self._keys_for_channel(field)}

                    for module, key_to_edge_mapping in list_of_edges_and_modules:
                        # each thing in list_of_edges_and_modules has a key->edge mapping
                        for key, edge in key_to_edge_mapping.items():
                            # collect on a per-key basis
                            list_of_channels_per_key[key].append((module, edge))

                    # now finally bind on a per-key basis
                    for (
                        key,
                        list_of_edges_and_modules,
                    ) in list_of_channels_per_key.items():
                        if list_of_edges_and_modules:
                            self._bind_delayed_channel(field, list_of_edges_and_modules, indexer=key)
                        else:
                            self._delayed_channels[field][key].bind(csp.null_ts(get_dict_basket_value_type(tstype)))

                elif is_list_basket(tstype):
                    # TODO
                    raise NotImplementedError()

                else:
                    self._bind_delayed_channel(field, list_of_edges_and_modules)

        # some bound checks
        # TODO make nicer
        for k, v in self._delayed_channels.items():
            if isinstance(v, dict):
                # Dict basket
                tstype = self.get_outer_type(k)
                value_type = get_dict_basket_value_type(tstype)
                optional_field = k in all_optional_channels
                for key, value in ((x, y) for x, y in v.items() if y.nodedef is _UnsetNodedef):
                    if optional_field:
                        # bind to null ts since optional
                        value.bind(csp.null_ts(value_type))
                    else:
                        raise NoProviderException("Nothing provides required node: {}-{}".format(k, key))
            elif v.nodedef is _UnsetNodedef:
                if k in all_optional_channels:
                    # bind to null ts since optional
                    v.bind(csp.null_ts(v.tstype.typ))
                else:
                    raise NoProviderException("Nothing provides required node: {}, required by {}".format(k, who_requires[k]))

        for k, e_list in self._delayed_edge_providers.items():
            for _, v in e_list:
                if isinstance(v, dict):
                    for key, value in v.items():
                        if value.nodedef is _UnsetNodedef:
                            raise NoProviderException("Nothing provides required node: {}-{}".format(k, key))

                elif v.nodedef is _UnsetNodedef:
                    raise NoProviderException("Nothing provides required node: {}, required by {}".format(k, who_requires[k]))

        # rebuild graph for publishing
        for field in self._modules_connections_graph:
            self._modules_connections_graph[field]["getters"] = [module for module in self._modules_connections_graph[field]["getters"]]
            self._modules_connections_graph[field]["setters"] = [module for module in self._modules_connections_graph[field]["setters"]]
        self._finalized = True
        log.debug(f"Feedback count: {self._feedback_count}")

    def _bind_delayed_channel(self, field, list_of_edges_and_modules, indexer=None):
        tstype = self.get_outer_type(field)
        # Make sure a getter node exists first
        if field not in self._delayed_channels:
            self.get_channel(field)

        if is_dict_basket(tstype):
            # getter edge, should be a DelayedEdge
            getter_edge = self._delayed_channels[field][indexer]
        elif is_list_basket(tstype):
            # TODO
            raise NotImplementedError()
        else:
            # getter edge, should be a DelayedEdge
            getter_edge = self._delayed_channels[field]

        channels_with_blocks = []
        for module, raw_setter_edge in list_of_edges_and_modules:
            # Here, we perform a graph traversal to determine if this specific
            # setter edge forms a cycle if it reaches the getter edge. If it does,
            # we inject a feedback. This is done to break the cycle.
            setter_edge = self._add_feedback_if_setter_reaches_getter(raw_setter_edge, getter_edge)
            start_time = self._override_blocks.get(module)
            if start_time is not None:
                filter = csp.times(setter_edge) >= csp.const(start_time)
                edge = csp.filter(filter, setter_edge)
            elif self._block_set_channels_until is not None:
                filter = csp.times(setter_edge) >= csp.const(self._block_set_channels_until)
                edge = csp.filter(filter, setter_edge)
            else:
                edge = setter_edge
            channels_with_blocks.append(edge)

        getter_edge.bind(csp.flatten(channels_with_blocks))

    def _add_feedback_if_setter_reaches_getter(self, setter_edge: Edge, getter_edge: DelayedEdge) -> Edge:
        """We have a setter of an edge (channel or a key in a dict basket channel),
        and the corresponding getter_edge. We perform a graph traversal to determine
        if one of the ancestors of the setter edge requests the same edge we set.

        If so, then we have a cycle and need to introduce a feedback to break it.
        We must introduce a feedback somewhere along the path.
        To minimize affecting other parts of the graph, we introduce the feedback on the
        setter edge itself, namely, the feedback is bound to the setter edge, and the getter edge is bound to its output. Notably, since we could've introduced the feedback anywhere,
        there can be other possible solutions. This results in module ordering affecting
        where exactly we introduce feedbacks.
        """
        seen_edges = set()
        # BFS
        to_visit = deque([setter_edge])
        while to_visit:
            visiting_edge = to_visit.popleft()
            # We check that these are exactly the same object, since we care about the actual DelayedEdge
            # that is being passed around. This means that one of the ancestor nodes of our setter edge
            # requests the same channel we set. This is a cycle! Introduce a feedback to break it.
            if visiting_edge is getter_edge:
                # We have a cycle, delay!
                return self._replace_with_feedback(setter_edge)

            visiting_edge_id = id(visiting_edge)
            if visiting_edge_id in seen_edges:
                continue
            seen_edges.add(visiting_edge_id)
            visiting_node = visiting_edge.nodedef
            if not isinstance(visiting_node, FeedbackInputDef):
                # We recursively visit the inputs of the node to search for cycles.
                node_inputs = getattr(visiting_node, "_inputs", [])
                for edge_or_basket in node_inputs:
                    if isinstance(edge_or_basket, dict):
                        to_visit.extend(edge for edge in edge_or_basket.values() if id(edge) not in seen_edges)
                    elif isinstance(edge_or_basket, list):
                        to_visit.extend(edge for edge in edge_or_basket if id(edge) not in seen_edges)
                    elif id(edge_or_basket) not in seen_edges:
                        to_visit.append(edge_or_basket)
        return setter_edge

    def _replace_with_feedback(self, edge: Edge) -> Edge:
        feedback = self._feedbacks.get(id(edge))
        if feedback:
            # already exists as a feedback, get it
            return feedback.out()
        feedback = csp.feedback(edge.tstype.typ)
        self._feedback_count += 1

        # handle immediate or generic types
        if hasattr(edge.tstype.typ, "__name__"):
            # For types
            name = edge.tstype.typ.__name__
        elif hasattr(edge.tstype.typ, "_name"):
            # For generics
            name = "{}[{}]".format(
                edge.tstype.typ._name,
                ",".join(_.__name__ for _ in edge.tstype.typ.__args__),
            )
        else:
            # Give up easily
            name = None

        if name:
            # get name from arguments
            feedback.__name__ = "Feedback<{}>".format(name)
            feedback.out().nodedef.__name__ = "Feedback<{}>".format(name)

        # Bind and store feedback
        feedback.bind(edge)
        self._feedbacks[id(edge)] = feedback
        return feedback.out()

    def get_channel(
        self,
        field: str,
        indexer: Union[int, str] = None,
    ) -> Union[Edge, Dict[Any, Edge], List[Edge]]:
        # register as required
        self._handle_module_requirements(field)

        # add to graph
        self._add_field_to_graph(field, self._module_being_attached, False, indexer)

        # now try to get edge
        dep = getattr(self, field)

        # extract type
        tstype = self.get_outer_type(field)

        if dep is None:
            # Replace with a delayed edge to be filled in later

            # if dict basket, create for all keys
            if is_dict_basket(tstype):
                # get tstype of value in basket
                basket_value_type = get_dict_basket_value_tstype(tstype)

                # initialize to empty dict, map all keys to delayed channels
                self._delayed_channels[field] = {key: DelayedEdge(basket_value_type) for key in self._keys_for_channel(field)}

                for key, edge in self._delayed_channels[field].items():
                    # stash the name for later if we replace with a feedback
                    edge.__name__ = "{}{}".format(field, "[{}]".format(key.name) if hasattr(key, "name") else "")

            elif is_list_basket(tstype):
                # TODO
                raise NotImplementedError()
            else:
                # create delayed edge
                self._delayed_channels[field] = DelayedEdge(tstype)

                # stash the name for later if we replace with a feedback
                self._delayed_channels[field].__name__ = field

            # now set field to the delayed edge
            setattr(self, field, self._delayed_channels[field])

        if is_dict_basket(tstype) and indexer:
            # if using an indexer, return that edge (raise if not recognized)
            if indexer not in self._keys_for_channel(field):
                raise Exception(
                    "Unrecognized key for channel {}: {}. Keys must be Enum type or registered by a node using `dynamic_keys`".format(field, indexer)
                )
            return getattr(self, field)[indexer]

        elif is_list_basket(tstype):
            # TODO
            raise NotImplementedError()

        return getattr(self, field)

    @classmethod
    def is_state_field(cls, field):
        return field.startswith("s_")

    @classmethod
    def get_outer_type(cls, field):
        return cls.model_fields[field].annotation

    def set_channel(
        self,
        field: str,
        edge: Union[Edge, Dict[Any, Edge], List[Edge]],
        indexer: Union[int, str] = None,
    ) -> None:
        # add to graph
        self._add_field_to_graph(field, self._module_being_attached, True, indexer)

        # TODO fix ugly state field stuff
        is_state_field = self.is_state_field(field)

        tstype = self.get_outer_type(field)
        if is_dict_basket(tstype):
            _is_dict_basket = True
        elif is_list_basket(tstype):
            # TODO
            raise NotImplementedError()
        else:
            _is_dict_basket = False

        # get the registered ts type
        if _is_dict_basket:
            gateway_tstype = get_dict_basket_value_tstype(tstype)
        else:
            gateway_tstype = tstype

        # validate arguments
        if _is_dict_basket and isinstance(edge, Edge) and not indexer:
            # if its a dict basket and you set an edge, you need to provide an indexer
            raise Exception("Field `{}` refers to a dict basket, and you have provided an edge {} but not an indexer".format(field, edge))

        if _is_dict_basket and isinstance(edge, dict) and indexer:
            # if its a dict basket and you set a dict, you should not provide an indexer
            raise Exception(
                ("Field `{}` refers to a dict basket, and you have provided an edge basket but also an indexer {}".format(field, indexer))
            )

        if _is_dict_basket and isinstance(edge, dict) and not all(isinstance(edge_value, Edge) for edge_value in edge.values()):
            # must be flat dict->edge
            raise Exception("Edge basket for field `{}` contains non edge fields `{}`".format(field, edge))

        if not _is_dict_basket and not isinstance(edge, Edge):
            # must provide an edge type
            raise TypeError("Edge provided for field `{}` is not an `Edge` instance {}".format(field, edge))

        if not _is_dict_basket and indexer:
            # don't provide an indexer for non-dict basket
            raise Exception("Indexer provided for field `{}` but it is not a basket instance".format(field))

        # validate that its the right type
        edge_tstypes: List[TsType] = []
        if isinstance(edge, dict):
            # Dict Basket
            edge_tstypes = [v.tstype for v in edge.values()]
        else:
            edge_tstypes = [edge.tstype]  # type: ignore[union-attr]

        if not all(edge_tstype == gateway_tstype for edge_tstype in edge_tstypes) and not is_state_field:
            raise TypeError("Edge type incorrect for {}: should be {}, found {}".format(field, gateway_tstype, edge_tstypes[0]))

        module = self._module_being_attached
        # Add edge to list of edge providers if its not already there
        if _is_dict_basket:
            if isinstance(edge, dict):
                # Dict Basket
                self._delayed_edge_providers[field].append((module, edge.copy()))
            else:
                # NOTE: all bad cases should be handled with exceptions above
                self._delayed_edge_providers[field].append((module, {indexer: edge}))
        else:
            self._delayed_edge_providers[field].append((module, edge))

        # TODO setup for all fields?
        self._set_last(field)
        self._set_next(field)

    def _ensure_state_field(self, field: str) -> str:
        if not field.startswith("s_"):
            return "s_{}".format(field)
        return field

    def set_state(
        self,
        field: str,
        keyby: Union[str, Tuple[str, ...]],
        indexer: Union[str, int] = None,
    ) -> None:
        # grab state version of field
        state_field = self._ensure_state_field(field)

        # Bail if already setup
        if (state_field, indexer) in self._state_requests:
            return

        # First ensure edge is constructed
        edge = self.get_channel(field, indexer=indexer)

        # And ensure the state edge is constructed
        self.get_state(state_field, indexer=indexer)

        if isinstance(edge, Edge):
            # instantiate state node
            if get_origin(edge.tstype.typ) is list:
                edge_type_name = get_args(edge.tstype.typ)[0].__name__
                state_edge = build_track_state_node(csp.unroll(edge), keyby)
            else:
                edge_type_name = edge.tstype.typ.__name__
                state_edge = build_track_state_node(edge, keyby)

            state_edge.nodedef.__name__ = "State[{}]".format(edge_type_name)

            # register for use inside other csp nodes
            self.set_channel(state_field, state_edge, indexer=indexer)

            # setup ad-hoc querying
            trigger = ConcurrentFutureAdapter(name="RequestState<{}>".format(edge_type_name))

            named_on_request_node("QueryState<{}>".format(edge_type_name))(state_edge, trigger.out())

            # register the trigger
            self._state_requests[state_field, indexer] = trigger
        else:
            # TODO
            raise NotImplementedError()

    def get_state(self, field: str, indexer: Union[str, int] = None) -> Any:
        # grab state version of field
        state_field = self._ensure_state_field(field)

        return self.get_channel(state_field, indexer=indexer)

    def _set_last(self, field: str, indexer: Union[str, int] = None) -> None:
        # Bail if already setup
        if (field, indexer) in self._last_requests:
            return

        # get type of edge
        tstype = self.get_outer_type(field)

        # First ensure edge is constructed
        if indexer:
            edge = self.get_channel(field, indexer)
        else:
            edge = self.get_channel(field)

        if is_dict_basket(tstype):
            # get tstype of value in basket
            basket_value_type = get_dict_basket_value_tstype(tstype)
            if hasattr(basket_value_type.typ, "__name__"):
                edge_type_name = basket_value_type.typ.__name__
            else:
                edge_type_name = str(basket_value_type.typ)
        else:
            if hasattr(tstype.typ, "__name__"):
                # instantiate tracker node
                edge_type_name = tstype.typ.__name__
            else:
                edge_type_name = str(tstype.typ)

        # setup ad-hoc querying
        trigger = ConcurrentFutureAdapter(name="RequestLast<{}>".format(edge_type_name))

        if is_dict_basket(tstype):
            if indexer:
                named_on_request_node_dict_basket("QueryLast<Basket<{}>>".format(edge_type_name))({indexer: edge}, trigger.out())
            else:
                named_on_request_node_dict_basket("QueryLast<Basket<{}>>".format(edge_type_name))(edge, trigger.out())
        else:
            named_on_request_node("QueryLast<{}>".format(edge_type_name))(edge, trigger.out())

        # register the trigger
        self._last_requests[field, indexer] = trigger

    def _set_next(self, field: str, indexer: Union[str, int] = None) -> None:
        # Bail if already setup
        if (field, indexer) in self._next_requests:
            return

        # get type of edge
        tstype = self.get_outer_type(field)

        # First ensure edge is constructed
        if indexer:
            edge = self.get_channel(field, indexer)
        else:
            edge = self.get_channel(field)

        if is_dict_basket(tstype):
            # get tstype of value in basket
            basket_value_type = get_dict_basket_value_tstype(tstype)
            if hasattr(basket_value_type.typ, "__name__"):
                edge_type_name = basket_value_type.typ.__name__
            else:
                edge_type_name = str(basket_value_type.typ)
        else:
            if hasattr(tstype.typ, "__name__"):
                # instantiate tracker node
                edge_type_name = tstype.typ.__name__
            else:
                edge_type_name = str(tstype.typ)

        # setup ad-hoc querying
        trigger = ConcurrentFutureAdapter(name="RequestLast<{}>".format(edge_type_name))

        if is_dict_basket(tstype):
            if indexer:
                named_wait_for_next_node_dict_basket("QueryNext<Basket<{}>>".format(edge_type_name))({indexer: edge}, trigger.out())
            else:
                named_wait_for_next_node_dict_basket("QueryNext<Basket<{}>>".format(edge_type_name))(edge, trigger.out())
        else:
            named_wait_for_next_node("QueryNext<{}>".format(edge_type_name))(edge, trigger.out())

        # register the trigger
        self._next_requests[field, indexer] = trigger

    def add_send_channel(self, field: str, indexer: Union[str, int] = None) -> None:
        # TODO do we want this to happen automatically?
        # Do we want any edge to work with `send`, or only the ones
        # we explicitly opt-in to?

        # e.g. if i have a ManualOrderSubmitter, i can send
        # order requests. If i omit this, should i still be able
        # to send requests? What if i only want a readonly view?

        # ORIGINAL CODE

        # Put a send channel in for this field, later during
        # build time we will add the GenericPushAdapter to the
        # graph
        if not self._validate_field_name(field):
            raise AttributeError("{} has no send channel attribute: {}".format(self.__class__, field))

        # short circuit if already registered
        if (field, indexer) in self._send_channels:
            return

        # get type of edge
        tstype = self.get_outer_type(field)

        if is_dict_basket(tstype):
            if indexer:
                # wire in now
                tstype = get_dict_basket_value_type(tstype)
                self._send_channels[field, indexer] = GenericPushAdapter(tstype, name="manual_{}[{}]".format(field, indexer))
            else:
                # Put it into the _send_channels for later processing
                # as we might not know all the keys yet
                self._send_channels[field, indexer] = (field,)
        else:
            if indexer is not None:
                raise TypeError(f"{field} provided with indexer but is not dict basket")
            tstype = tstype.typ
            self._send_channels[field, indexer] = GenericPushAdapter(tstype, name="manual_{}".format(field))

    def _add_send_channel_dict_basket(self, field: str, keys: Union[List[str], Enum]) -> None:
        # NOTE: Do not call this directly, it is used in the factory finalization

        # get type of edge
        tstype = self.get_outer_type(field)

        # ensure its a dict basket, if this fails something
        # is dramatically wrong
        assert is_dict_basket(tstype)

        # extract inner type
        key_type = get_dict_basket_key_type(tstype)
        value_tstype = get_dict_basket_value_tstype(tstype)

        # replace with actual generic push adapter that will convert
        # GPA[dict] -> dict to keys + data -> send to dict basket channels
        gpa = GenericPushAdapter(object, name=f"manual_{field}")

        @csp.node
        def _dict_basket_synchronizer(data: ts[object]) -> csp.OutputBasket(Dict[key_type, value_tstype], shape=list(keys)):
            if csp.ticked(data):
                csp.output(data)

        self._send_channels[field, None] = (gpa, _dict_basket_synchronizer(gpa.out()))

    def last(self, field: str, indexer: Union[str, int] = None, *, timeout=None) -> None:
        self._check(field, self._last_requests, "last")

        # FIXME decide if we want to keep indexer
        # last_edge = self._last_requests[field, indexer]
        last_edge = self._last_requests[field, None]

        # trigger request for last into graph
        future = last_edge.push_tick()

        # wait for result
        result = future.result(timeout=timeout)
        if indexer:
            return result.get(indexer)
        return result

    def next(self, field: str, indexer: Union[str, int] = None, *, timeout=None) -> None:
        self._check(field, self._last_requests, "last")

        # FIXME decide if we want to keep indexer
        # next_edge = self._next_requests[field, indexer]
        next_edge = self._next_requests[field, None]

        # trigger request for next into graph
        future = next_edge.push_tick()

        # wait for result
        result = future.result(timeout=timeout)
        if indexer:
            return result.get(indexer)
        return result

    def state(self, field: str, indexer: Union[str, int] = None, *, timeout=None) -> Any:
        # grab state version of field
        state_field = self._ensure_state_field(field)

        self._check(state_field, self._state_requests, "state", indexer=indexer)

        # TODO checks for state tracking
        # TODO make sure not called from inside graph context
        state_edge = self._state_requests[state_field, indexer]

        # trigger request for state into graph
        future = state_edge.push_tick()

        # wait for result
        return future.result(timeout=timeout)

    def query(self, field: str, indexer: Union[str, int] = None, query: "Query" = None) -> Any:
        state = self.state(field=field, indexer=indexer)

        if state:
            return state.query(query)
        return []

    def send(self, field: str, value: Any, indexer: Union[str, int] = None) -> None:
        # TODO elaborate
        if not self._validate_field_name(field):
            raise AttributeError("{} has no send channel attribute: {}".format(self.__class__, field))

        self._check(field, self._send_channels, "send channel", indexer=indexer)
        send_channel = self._send_channels[field, indexer]

        if isinstance(send_channel, GenericPushAdapter):
            send_channel.push_tick(value)
        else:
            # basket, push into first item of tuple
            send_channel[0].push_tick(value)

    def _check(self, field: str, where: Dict, kind: str, indexer: Union[str, int] = None) -> None:
        if (field, indexer) not in where:
            # TODO should only be called once the graph is started
            raise NoProviderException("Nobody provides {}: {}{}".format(kind, field, "-{}".format(indexer) if indexer else ""))

    def override(self, field: str, value: Any) -> None:
        raise NotImplementedError()

    @classmethod
    def fields(cls) -> List[str]:
        return list(cls.model_fields.keys())

    def graph(self):
        if not self._finalized:
            raise Exception("Must finalize graph first")
        return self._modules_connections_graph


ChannelsType = TypeVar("ChannelsType", bound=Channels)
