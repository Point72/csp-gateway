"""Command line interface for querying a running gateway and printing the responses as JSON.

``GatewayClientCLI`` is designed to be subclassed by gateway applications. Commands are methods
decorated with :func:`command` (and optionally :func:`argument`); they receive the constructed
client and the parsed arguments, and return JSON-serializable data that the CLI prints.

Example:
    >>> from csp_gateway.client.cli import GatewayClientCLI, argument, command
    >>>
    >>> class MyAppCLI(GatewayClientCLI):
    ...     prog = "my-app"
    ...
    ...     @command(help="Last tick of the orders channel for one account")
    ...     @argument("account")
    ...     def orders(self, client, args):
    ...         return [order for order in client.last("orders") if order["account"] == args.account]
    >>>
    >>> def main():
    ...     return MyAppCLI().run()
"""

import argparse
import json
import logging
import os
import re
import sys
import traceback
from collections.abc import Callable, Generator, Iterator, Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from enum import Enum
from typing import Any, ClassVar, TextIO, get_args

from httpx2 import HTTPError
from pydantic import ValidationError

from ..utils import Filter, FilterCondition, FilterWhere, GatewayException, Query
from .client import BaseGatewayClient, GatewayClientConfig, ReturnType, SyncGatewayClient

__all__ = (
    "CommandSpec",
    "GatewayClientCLI",
    "argument",
    "command",
    "json_argument",
    "main",
)

log = logging.getLogger(__name__)

_COMMAND_ATTR = "__csp_gateway_cli_command__"
_ARGUMENTS_ATTR = "__csp_gateway_cli_arguments__"


@dataclass(frozen=True)
class CommandSpec:
    """Metadata attached to a method by :func:`command`."""

    name: str
    help: str | None = None
    description: str | None = None
    aliases: tuple[str, ...] = ()


def command(
    name: str | Callable | None = None,
    *,
    help: str | None = None,
    description: str | None = None,
    aliases: Sequence[str] = (),
) -> Callable:
    """Register a ``GatewayClientCLI`` method as a subcommand.

    The method is called as ``method(client, args)`` and its return value is printed as JSON.
    Returning an iterator prints each item as its own JSON document; returning ``None`` prints nothing.

    Args:
        name: Subcommand name. Defaults to the method name with underscores replaced by dashes.
        help: One-line summary shown in the top-level ``--help``. Defaults to the docstring's first line.
        description: Text shown in the subcommand's ``--help``. Defaults to the full docstring.
        aliases: Alternative names for the subcommand.

    Can be used bare (``@command``) or called (``@command(...)``).
    """
    if callable(name):
        return command()(name)

    def decorator(func: Callable) -> Callable:
        doc = (func.__doc__ or "").strip()
        spec = CommandSpec(
            name=name or getattr(func, "__name__", "").replace("_", "-"),
            help=help if help is not None else (doc.splitlines()[0] if doc else None),
            description=description if description is not None else (doc or None),
            aliases=tuple(aliases),
        )
        setattr(func, _COMMAND_ATTR, spec)
        return func

    return decorator


def argument(*flags: str, **kwargs: Any) -> Callable:
    """Declare an ``argparse`` argument for a :func:`command` method.

    Accepts the same parameters as ``ArgumentParser.add_argument``. Stacked decorators are added
    in top-to-bottom order.
    """

    def decorator(func: Callable) -> Callable:
        setattr(func, _ARGUMENTS_ATTR, ((flags, kwargs), *getattr(func, _ARGUMENTS_ATTR, ())))
        return func

    return decorator


def json_argument(value: str) -> Any:
    """``argparse`` type parsing inline JSON, ``@path`` to a JSON file, or ``-`` for stdin."""
    try:
        if value == "-":
            text = sys.stdin.read()
        elif value.startswith("@"):
            with open(value[1:]) as file:
                text = file.read()
        else:
            text = value
        return json.loads(text)
    except OSError as error:
        raise argparse.ArgumentTypeError(f"cannot read {value[1:]!r}: {error.strerror}") from error
    except json.JSONDecodeError as error:
        raise argparse.ArgumentTypeError(f"invalid JSON: {error}") from error


_TOKEN_PARAMETER = re.compile(r"(token=)[^&\s'\"]+")


def _handled_errors() -> tuple[type[BaseException], ...]:
    errors: tuple[type[BaseException], ...] = (GatewayException, HTTPError, OSError, TimeoutError, ValueError)
    try:
        from aiohttp import ClientError
    except ImportError:
        return errors
    return (*errors, ClientError)


def _describe_error(error: BaseException) -> str:
    if isinstance(error, ValidationError):
        # The default message echoes the input values, which can include credentials
        details = "; ".join(
            f"{'.'.join(map(str, detail['loc']))}: {detail['msg']}" if detail["loc"] else detail["msg"]
            for detail in error.errors(include_url=False, include_input=False, include_context=False)
        )
        return f"invalid configuration: {details}"
    return f"{type(error).__name__}: {error}" if str(error) else type(error).__name__


def _filter_value(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _channel_and_key(channel: str) -> str | tuple[str, str]:
    name, _, key = channel.partition("/")
    return (name, key) if key else name


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date, time)):
        return obj.isoformat()
    if isinstance(obj, timedelta):
        return obj.total_seconds()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (set, frozenset, tuple)):
        return list(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


_STAGING_ACTIONS = ("list", "lookup", "new", "add", "remove", "clear", "release")


class GatewayClientCLI:
    """Extensible command line client for a running gateway.

    Subclass to build an application specific CLI:

    - set ``prog`` and ``description`` to rebrand the tool,
    - set ``client_class`` / ``config_class`` to use a custom (synchronous) client or config,
    - add commands with :func:`command` and :func:`argument`,
    - override a built-in command by redefining the method, or remove it by assigning ``None`` to its name,
    - override :meth:`add_global_arguments` and :meth:`config_kwargs` to expose extra config fields.
    """

    prog: ClassVar[str | None] = "csp-gateway-client"
    description: ClassVar[str | None] = "Query a running csp-gateway server and print the responses as JSON."
    epilog: ClassVar[str | None] = None
    client_class: ClassVar[type[BaseGatewayClient]] = SyncGatewayClient
    config_class: ClassVar[type[GatewayClientConfig]] = GatewayClientConfig

    # (config field, flag, argparse kwargs) for the connection options
    connection_options: ClassVar[tuple[tuple[str, str, dict[str, Any]], ...]] = (
        ("host", "--host", {"help": "Gateway host, optionally including the scheme (default: localhost)"}),
        ("port", "--port", {"type": int, "help": "Gateway port (default: 8000)"}),
        ("protocol", "--protocol", {"choices": ("http", "https"), "help": "Protocol (default: http)"}),
        ("api_prefix", "--api-prefix", {"help": "Top level API path segment (default: api)"}),
        ("api_version", "--api-version", {"help": "API version (default: v1)"}),
        ("api_key", "--api-key", {"help": "API key, sent as the token query parameter"}),
        ("bearer_token", "--bearer-token", {"help": "Bearer token, sent in the Authorization header"}),
    )

    def __init__(self, stdout: TextIO | None = None, stderr: TextIO | None = None) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._pretty = False
        self._secrets: set[str] = set()
        self._sort_keys = False

    @property
    def stdout(self) -> TextIO:
        return self._stdout or sys.stdout

    @property
    def stderr(self) -> TextIO:
        return self._stderr or sys.stderr

    # Parser construction

    @classmethod
    def commands(cls) -> dict[str, tuple[CommandSpec, str]]:
        """Registered commands as ``{name: (spec, method name)}``, resolved through the MRO."""
        by_attr: dict[str, CommandSpec] = {}
        for klass in reversed(cls.__mro__):
            for attr, value in vars(klass).items():
                spec = getattr(value, _COMMAND_ATTR, None)
                if isinstance(spec, CommandSpec):
                    by_attr[attr] = spec
                else:
                    # A subclass shadowing a command method with a non-command removes it
                    by_attr.pop(attr, None)
        return {spec.name: (spec, attr) for attr, spec in sorted(by_attr.items(), key=lambda item: item[1].name)}

    def build_parser(self) -> argparse.ArgumentParser:
        from csp_gateway import __version__

        parser = argparse.ArgumentParser(
            prog=self.prog,
            description=self.description,
            epilog=self.epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
        self.add_global_arguments(parser)

        # Global options are also accepted after the command name. Suppressed defaults keep a value
        # given before the command from being reset when it is not repeated after it.
        shared = argparse.ArgumentParser(add_help=False)
        self.add_global_arguments(shared)
        for action in shared._actions:
            action.default = argparse.SUPPRESS

        subparsers = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
        self.add_commands(subparsers, parents=[shared])
        return parser

    def add_global_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add options shared by every command. Override (calling ``super()``) to add more."""
        connection = parser.add_argument_group("connection", "GatewayClientConfig reads unset options from the listed environment variables.")
        for field, flag, kwargs in self.connection_options:
            options: dict[str, Any] = {**kwargs, "help": f"{kwargs.get('help', '')} [env: {field.upper()}]".strip()}
            connection.add_argument(flag, dest=field, default=None, **options)
        connection.add_argument(
            "--timeout",
            type=float,
            default=None,
            help="Request timeout in seconds (default: 10, or no timeout for next)",
        )

        output = parser.add_argument_group("output")
        output.add_argument("--pretty", action="store_true", help="Indent JSON output instead of printing one document per line")
        output.add_argument("--sort-keys", action="store_true", help="Sort keys in JSON output")
        output.add_argument(
            "-v", "--verbose", action="count", default=0, help="Log more detail from csp-gateway (repeat for debug logs and tracebacks)"
        )

    def add_commands(self, subparsers: "argparse._SubParsersAction", parents: Sequence[argparse.ArgumentParser] = ()) -> None:
        """Add a subparser for every registered command. Override to customize parsers directly.

        Pass ``parents`` on to ``subparsers.add_parser`` so the command also accepts the global options.
        """
        for spec, attr in self.commands().values():
            sub = subparsers.add_parser(
                spec.name,
                help=spec.help,
                description=spec.description,
                aliases=list(spec.aliases),
                parents=list(parents),
                conflict_handler="resolve",
                formatter_class=argparse.RawDescriptionHelpFormatter,
            )
            for flags, kwargs in getattr(getattr(self, attr), _ARGUMENTS_ATTR, ()):
                sub.add_argument(*flags, **kwargs)
            sub.set_defaults(_handler=getattr(self, attr))

    # Client construction

    def config_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        """Config fields given on the command line. Unset fields are left to the config defaults."""
        return {field: value for field, _, _ in self.connection_options if (value := getattr(args, field, None)) is not None}

    def make_config(self, args: argparse.Namespace) -> GatewayClientConfig:
        return self.config_class(**{**self.config_kwargs(args), "return_type": ReturnType.Raw})

    def make_client(self, args: argparse.Namespace) -> BaseGatewayClient:
        return self.client_class(self.make_config(args))

    @staticmethod
    def request_kwargs(args: argparse.Namespace) -> dict[str, Any]:
        """Keyword arguments for client request methods, e.g. the ``--timeout`` override."""
        return {} if args.timeout is None else {"timeout": args.timeout}

    # Output

    def emit(self, data: Any) -> None:
        """Print ``data`` as JSON: one line per document, or indented with ``--pretty``."""
        indent, separators = (2, None) if self._pretty else (None, (",", ":"))
        self.stdout.write(json.dumps(data, indent=indent, separators=separators, sort_keys=self._sort_keys, default=_json_default) + "\n")
        self.stdout.flush()

    def error(self, message: str) -> None:
        self.stderr.write(f"{self.prog or 'error'}: error: {self.redact(message)}\n")
        self.stderr.flush()

    def redact(self, text: str) -> str:
        """Mask credentials in ``text``: token query parameters and the configured api key / bearer token."""
        text = _TOKEN_PARAMETER.sub(r"\1***", text)
        for secret in sorted(self._secrets, key=len, reverse=True):
            # Match whole tokens only, so a short credential does not mangle ordinary words
            text = re.sub(rf"(?<![\w.~-]){re.escape(secret)}(?![\w.~-])", "***", text)
        return text

    # Execution

    def run(self, argv: Sequence[str] | None = None) -> int:
        """Parse ``argv`` (default ``sys.argv[1:]``), run the command and return the exit code."""
        parser = self.build_parser()
        try:
            with redirect_stdout(self.stdout), redirect_stderr(self.stderr):
                args = parser.parse_args(argv)
        except SystemExit as exit:
            return exit.code if isinstance(exit.code, int) else 1

        if args.verbose:
            # Only csp-gateway loggers are made verbose: HTTP libraries log request URLs, which carry api keys
            logging.basicConfig(level=logging.WARNING)
            logging.getLogger("csp_gateway").setLevel(logging.DEBUG if args.verbose > 1 else logging.INFO)
        self._secrets = {value for value in (getattr(args, "api_key", None), getattr(args, "bearer_token", None)) if value}
        self._pretty = args.pretty
        self._sort_keys = args.sort_keys

        result = None
        try:
            client = self.make_client(args)
            self._secrets |= {value for value in (client.config.api_key, client.config.bearer_token) if value}
            result = args._handler(client, args)
            if isinstance(result, Iterator):
                for item in result:
                    self.emit(item)
            elif result is not None:
                self.emit(result)
        except KeyboardInterrupt:
            return 130
        except BrokenPipeError:
            # Downstream consumer (e.g. `head`) closed the pipe; silence the flush at interpreter exit
            try:
                os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            except (OSError, ValueError):
                pass
            return 0
        except _handled_errors() as error:
            if args.verbose > 1 and not isinstance(error, ValidationError):
                log.debug(self.redact("".join(traceback.format_exception(error))))
            self.error(_describe_error(error))
            return 1
        finally:
            if hasattr(result, "close"):
                result.close()
        return 0

    @classmethod
    def main(cls, argv: Sequence[str] | None = None) -> int:
        """Console script entry point: ``sys.exit(MyCLI.main())``."""
        return cls().run(argv)

    # Built-in commands

    @command(help="Print the server's OpenAPI specification")
    def openapi(self, client: BaseGatewayClient, args: argparse.Namespace) -> Any:
        return client.openapi_spec

    @command(help="List the fields mounted under each API group")
    def routes(self, client: BaseGatewayClient, args: argparse.Namespace) -> Any:
        return client.mounted_apis

    @command(help="Get the last ticked value of a channel")
    @argument("channel", nargs="?", default="", help="Channel name, or channel/key for a dict basket. Omit to list channels.")
    def last(self, client: BaseGatewayClient, args: argparse.Namespace) -> Any:
        return client.last(args.channel, **self.request_kwargs(args))

    @command(help="Wait for and get the next ticked value of a channel")
    @argument("channel", nargs="?", default="", help="Channel name, or channel/key for a dict basket. Omit to list channels.")
    def next(self, client: BaseGatewayClient, args: argparse.Namespace) -> Any:
        return client.next(args.channel, **self.request_kwargs(args))

    @command(
        help="Get the state of a channel, optionally filtered",
        description=(
            "Get the state of a channel, optionally filtered.\n\n"
            "Filters compare an attribute against a value, e.g. --filter x '>=' 5 --filter y == '\"abc\"'.\n"
            "Values are parsed as JSON when possible and otherwise used as strings."
        ),
    )
    @argument("channel", nargs="?", default="", help="Channel name. Omit to list channels with state.")
    @argument(
        "--filter",
        dest="filters",
        nargs=3,
        action="append",
        default=[],
        metavar=("ATTR", "OP", "VALUE"),
        help=f"Filter by ATTR OP VALUE, where OP is one of {', '.join(get_args(FilterWhere))}. Repeatable.",
    )
    @argument("--query", type=json_argument, default=None, help="Full Query as JSON, @file or - for stdin")
    def state(self, client: BaseGatewayClient, args: argparse.Namespace) -> Any:
        query = Query.model_validate(args.query) if args.query is not None else None
        if args.filters:
            ops = get_args(FilterWhere)
            filters = []
            for attr, op, value in args.filters:
                if op not in ops:
                    raise ValueError(f"invalid filter operator {op!r}, expected one of {', '.join(ops)}")
                filters.append(Filter(attr=attr, by=FilterCondition(value=_filter_value(value), where=op)))
            query = Query(filters=[*(query.filters if query else []), *filters])
        return client.state(args.channel, query=query, **self.request_kwargs(args))

    @command(help="Look up a value of a channel by id")
    @argument("channel", help="Channel name")
    @argument("id", help="Id of the value")
    def lookup(self, client: BaseGatewayClient, args: argparse.Namespace) -> Any:
        return client.lookup(args.channel, args.id, **self.request_kwargs(args))

    @command(help="Send data into a channel")
    @argument("channel", help="Channel name, or channel/key for a dict basket")
    @argument("data", type=json_argument, help="A JSON object or list of objects, @file or - for stdin")
    def send(self, client: BaseGatewayClient, args: argparse.Namespace) -> Any:
        return client.send(args.channel, args.data, **self.request_kwargs(args))

    @command(help="Run a management control, e.g. heartbeat, stats or shutdown")
    @argument("control", nargs="?", default="", help="Control name. Omit to list controls.")
    @argument("--data", type=json_argument, default=None, help="JSON payload, @file or - for stdin")
    def controls(self, client: BaseGatewayClient, args: argparse.Namespace) -> Any:
        return client.controls(args.control, data=args.data, **self.request_kwargs(args))

    @command(
        help="Manage staging areas of a channel",
        description=(
            "Manage staging areas of a channel.\n\n"
            "  list     active staging areas with their contents (--id selects one)\n"
            "  lookup   contents of staging areas, including released ones (--id selects one)\n"
            "  new      create an empty staging area\n"
            "  add      add DATA to staging areas (default: the latest, or a new one)\n"
            "  remove   remove DATA from staging areas (default: the latest)\n"
            "  clear    empty staging areas without releasing (default: the latest)\n"
            "  release  release staged values into the channel (default: all)"
        ),
    )
    @argument("action", choices=_STAGING_ACTIONS, help="Staging action")
    @argument("channel", help="Channel name")
    @argument("data", nargs="?", type=json_argument, default=None, help="JSON payload for add/remove, @file or - for stdin")
    @argument("--id", dest="staging_ids", action="append", default=None, help="Target staging id. Repeatable.")
    @argument("--all", dest="all_stagings", action="store_true", help="Target every staging area")
    def stage(self, client: BaseGatewayClient, args: argparse.Namespace) -> Any:
        action = args.action
        if args.data is not None and action not in ("add", "remove"):
            raise ValueError(f"stage {action} does not take data")
        if args.all_stagings and args.staging_ids:
            raise ValueError("--all and --id are mutually exclusive")
        staging_ids = [] if args.all_stagings else args.staging_ids
        kwargs = self.request_kwargs(args)

        if action in ("list", "lookup"):
            if args.all_stagings or (staging_ids is not None and len(staging_ids) > 1):
                raise ValueError(f"stage {action} takes at most one --id and no --all")
            staging_id = staging_ids[0] if staging_ids else None
            method = client.stage_list if action == "list" else client.stage_lookup
            return method(args.channel, staging_id=staging_id, **kwargs)
        if action == "new":
            if staging_ids is not None:
                raise ValueError("stage new does not take --id or --all")
            return client.stage_new(args.channel, **kwargs)
        if action == "add":
            return client.stage_add(args.channel, data=args.data, staging_ids=staging_ids, **kwargs)
        if action == "remove":
            return client.stage_remove(args.channel, data=args.data, staging_ids=staging_ids, **kwargs)
        if action == "clear":
            return client.stage_clear(args.channel, staging_ids=staging_ids, **kwargs)
        return client.stage_release(args.channel, staging_ids=staging_ids, **kwargs)

    @command(
        help="Stream channel ticks over the websocket as newline-delimited JSON",
        description=(
            "Stream channel ticks over the websocket, printing one JSON message per line until interrupted.\n\n"
            "Requires the server to mount websocket routes and the aiohttp and aiostream packages."
        ),
    )
    @argument("channels", nargs="+", metavar="CHANNEL", help="Channel name, or channel/key for one key of a dict basket")
    @argument("-n", "--limit", type=int, default=None, help="Stop after this many messages")
    @argument("--idle-timeout", type=float, default=None, help="Fail if no message arrives within this many seconds")
    @argument("--heartbeats", action="store_true", help="Include the server's heartbeat messages")
    def stream(self, client: BaseGatewayClient, args: argparse.Namespace) -> Generator[Any, None, None]:
        if args.limit is not None and args.limit <= 0:
            return
        messages = self.iter_stream(client, [_channel_and_key(channel) for channel in args.channels], idle_timeout=args.idle_timeout)
        try:
            count = 0
            for message in messages:
                if not args.heartbeats and _is_heartbeat(message):
                    continue
                yield message
                count += 1
                if args.limit is not None and count >= args.limit:
                    return
        finally:
            messages.close()

    @staticmethod
    def iter_stream(
        client: BaseGatewayClient,
        channels: list[str | tuple[str, str]],
        idle_timeout: float | None = None,
    ) -> Generator[Any, None, None]:
        """Synchronously iterate the websocket stream of ``channels``, closing the connection when done."""
        from asyncio import wait_for

        loop = client._event_loop
        if loop is None:
            raise RuntimeError("client has no event loop")
        messages = client._streamAsync(channels=channels)

        async def receive():
            if idle_timeout is None:
                return await anext(messages)
            try:
                return await wait_for(anext(messages), timeout=idle_timeout)
            except TimeoutError:
                raise TimeoutError(f"no message received within {idle_timeout:g}s") from None

        try:
            while True:
                try:
                    message = loop.run_until_complete(receive())
                except StopAsyncIteration:
                    return
                yield message
        finally:
            try:
                loop.run_until_complete(messages.aclose())
            except Exception:
                log.debug("Error closing stream", exc_info=True)


def _is_heartbeat(message: Any) -> bool:
    return isinstance(message, dict) and message.get("channel") == "heartbeat" and message.get("data") == "PING"


def main(argv: Sequence[str] | None = None) -> int:
    return GatewayClientCLI.main(argv)


if __name__ == "__main__":
    sys.exit(main())
