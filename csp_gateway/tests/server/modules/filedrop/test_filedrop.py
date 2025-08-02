import csv
import logging
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Dict, List, Tuple

import csp
import orjson
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("Skipping Linux-specific tests on macOS platforms", allow_module_level=True)

from csp import ts

from csp_gateway import AddChannelsToGraphOutput, FileDropType, GatewayChannels, GatewayModule, GatewayStruct, ReadFileDrop, ReadFileDropConfiguration
from csp_gateway.testing.shared_helpful_classes import (
    MyGateway,
)


class FDStruct(GatewayStruct):
    i: int
    s: str
    b: bool
    f: float
    l_i: List[int]


class NotFDStruct(GatewayStruct):
    i: str
    s: int


class FDGatewayChannels(GatewayChannels):
    fd_channel: ts[FDStruct] = None
    fd_list_channel: ts[List[FDStruct]] = None
    fd_list_channel_2: ts[List[FDStruct]] = None
    fd_dict_channel: ts[Dict[str, FDStruct]] = None
    fd_dict_basket_channel: Dict[str, ts[FDStruct]] = None

    def dynamic_keys(self):
        return {FDGatewayChannels.fd_dict_basket_channel: ["a", "b", "c"]}


def convert_to_dict(data):
    new_data = []
    for d in data:
        if isinstance(d, list):
            new_data.append(convert_to_dict(d))
        elif isinstance(d, dict):
            new_data.append({k: v.to_dict() for k, v in d.items()})
        else:
            new_data.append(d.to_dict())
    return new_data


def csv_writer(path, data):
    dict_data = convert_to_dict(data)
    fieldnames = []
    for d in dict_data:
        fieldnames.extend(list(d.keys()))
    fieldnames = list(set(fieldnames))
    with open(path, "w") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(dict_data)


def json_writer(path, data, write_bad_file=False):
    dict_data = convert_to_dict(data)
    with open(path, "wb") as f:
        data_bytes = orjson.dumps(dict_data)
        if write_bad_file:
            data_bytes = data_bytes[: -1 * int(len(data_bytes) / 3)]
        f.write(data_bytes)


def json_writer_bad(path, data):
    json_writer(path, data, True)


def parquet_writer(path, data):
    table = pa.Table.from_pylist(convert_to_dict(data))
    pq.write_table(table, path)


def get_all_writers():
    return [(csv_writer, FileDropType.CSV), (json_writer, FileDropType.JSON), (parquet_writer, FileDropType.PARQUET)]


class Writer(GatewayModule):
    data: List[Tuple[float, object, str, object]]

    def connect(self, channels):
        self.execute()

    @csp.node
    def execute(self):
        with csp.alarms():
            alarm = csp.alarm(int)

        with csp.start():
            csp.schedule_alarm(alarm, timedelta(seconds=self.data[0][0]), 0)

        if csp.ticked(alarm):
            cur_idx = alarm
            next_idx = cur_idx + 1
            if next_idx < len(self.data):
                csp.schedule_alarm(alarm, timedelta(seconds=self.data[next_idx][0]), next_idx)
            _, write_fn, filename, structs = self.data[cur_idx]
            write_fn(filename, structs)


def match_data(data1, data2, exact=False):
    assert len(data1) == len(data2)
    for d1, d2 in zip(data1, data2):
        dict1 = d1.to_dict()
        dict2 = d2.to_dict()
        if not exact:
            dict1.pop("id")
            dict1.pop("timestamp")
            dict2.pop("id")
            dict2.pop("timestamp")
        assert dict1 == dict2


def match_lists(lists_data, data2, exact=False):
    for data1 in lists_data:
        match_data(data1, data2, exact)


@pytest.mark.parametrize(
    "structs",
    [
        [FDStruct(i=i) for i in range(1)],
        [FDStruct(i=i) for i in range(10)],
        [FDStruct(i=i) for i in range(100)],
    ],
)
def test_basic(structs):
    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, json_writer, str(dirpath / "json_file1.json"), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_channel", filedrop_type=FileDropType.JSON),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        match_data([d[1] for d in out["fd_channel"]], structs)


@pytest.mark.parametrize(
    "structs",
    [
        [[FDStruct(i=i) for i in range(1)]],
        [[FDStruct(i=i) for i in range(10)]],
        [[FDStruct(i=i) for i in range(100)]],
    ],
)
def test_list_of_structs(structs):
    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, json_writer, str(dirpath / "json_file1.json"), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_list_channel", filedrop_type=FileDropType.JSON),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        out_data = [d[1] for d in out["fd_list_channel"]]
        assert len(out_data) == 1
        match_lists(out_data, structs[0])


@pytest.mark.parametrize("structs", [[[FDStruct(i=i) for i in range(10)]]])
@pytest.mark.parametrize("no_readers", [1, 2, 5])
def test_multi_readers_single_channel_single_dir(structs, no_readers):
    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, json_writer, str(dirpath / "json_file1.json"), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_list_channel", filedrop_type=FileDropType.JSON),
                ]
                * no_readers,
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        out_data = [d[1] for d in out["fd_list_channel"]]
        assert len(out_data) == no_readers
        match_lists(out_data, structs[0])


@pytest.mark.parametrize("structs", [[[FDStruct(i=i) for i in range(10)]]])
def test_multi_readers_multi_channel_single_directory(structs):
    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, json_writer, str(dirpath / "json_file1.json"), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_list_channel", filedrop_type=FileDropType.JSON),
                    ReadFileDropConfiguration(channel_name="fd_list_channel_2", filedrop_type=FileDropType.JSON),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        out_data_1 = [d[1] for d in out["fd_list_channel"]]
        out_data_2 = [d[1] for d in out["fd_list_channel_2"]]
        assert len(out_data_1) == 1
        assert len(out_data_2) == 1
        match_lists(out_data_1, structs[0])
        match_lists(out_data_2, structs[0])


@pytest.mark.parametrize(
    "structs",
    [
        [[FDStruct(i=i) for i in range(1)]],
        [[FDStruct(i=i) for i in range(10)]],
        [[FDStruct(i=i) for i in range(100)]],
    ],
)
def test_single_channel_multi_dir(structs):
    with tempfile.TemporaryDirectory(dir=".") as dir1:
        with tempfile.TemporaryDirectory(dir=".") as dir2:
            dirpath1 = Path(dir1)
            dirpath2 = Path(dir2)
            writer = Writer(
                data=[[1, json_writer, str(dirpath1 / "json_file1.json"), structs], [0, json_writer, str(dirpath2 / "json_file2.json"), structs]]
            )
            fd_module = ReadFileDrop(
                directory_configs={
                    str(dirpath1): [
                        ReadFileDropConfiguration(channel_name="fd_list_channel", filedrop_type=FileDropType.JSON),
                    ],
                    str(dirpath2): [
                        ReadFileDropConfiguration(channel_name="fd_list_channel", filedrop_type=FileDropType.JSON),
                    ],
                }
            )
            gateway = MyGateway(
                modules=[writer, fd_module, AddChannelsToGraphOutput()],
                channels=FDGatewayChannels(),
            )
            out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
            out_data = [d[1] for d in out["fd_list_channel"]]
            assert len(out_data) == 2
            match_lists(out_data, structs[0])


@pytest.mark.parametrize(
    "structs",
    [
        [[FDStruct(i=i) for i in range(1)]],
        [[FDStruct(i=i) for i in range(10)]],
        [[FDStruct(i=i) for i in range(100)]],
    ],
)
def test_multi_channel_multi_dir(structs):
    with tempfile.TemporaryDirectory(dir=".") as dir1:
        with tempfile.TemporaryDirectory(dir=".") as dir2:
            dirpath1 = Path(dir1)
            dirpath2 = Path(dir2)
            writer = Writer(
                data=[[1, json_writer, str(dirpath1 / "json_file1.json"), structs], [0, json_writer, str(dirpath2 / "json_file2.json"), structs]]
            )
            fd_module = ReadFileDrop(
                directory_configs={
                    str(dirpath1): [
                        ReadFileDropConfiguration(channel_name="fd_list_channel", filedrop_type=FileDropType.JSON),
                    ],
                    str(dirpath2): [
                        ReadFileDropConfiguration(channel_name="fd_list_channel_2", filedrop_type=FileDropType.JSON),
                    ],
                }
            )
            gateway = MyGateway(
                modules=[writer, fd_module, AddChannelsToGraphOutput()],
                channels=FDGatewayChannels(),
            )
            out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
            out_data_1 = [d[1] for d in out["fd_list_channel"]]
            out_data_2 = [d[1] for d in out["fd_list_channel_2"]]
            assert len(out_data_1) == 1
            assert len(out_data_2) == 1
            match_lists(out_data_1, structs[0])
            match_lists(out_data_2, structs[0])


@pytest.mark.parametrize(
    "structs",
    [
        [FDStruct(i=i) for i in range(1)],
        [FDStruct(i=i) for i in range(10)],
    ],
)
@pytest.mark.parametrize(
    "filetype_data",
    [
        [json_writer, "file1.json", FileDropType.JSON],
        [parquet_writer, "file1.parquet", FileDropType.PARQUET],
    ],
)
def test_filetypes(structs, filetype_data):
    writer = filetype_data[0]
    filename = filetype_data[1]
    filedrop_type = filetype_data[2]
    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, writer, str(dirpath / filename), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_channel", filedrop_type=filedrop_type),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        match_data([d[1] for d in out["fd_channel"]], structs)


def test_invalid_data(caplog):
    structs = [FDStruct(i=i) for i in range(1)]
    with caplog.at_level(logging.ERROR):
        with tempfile.TemporaryDirectory(dir=".") as dir:
            dirpath = Path(dir)
            writer = Writer(data=[[1, json_writer_bad, str(dirpath / "file.json"), structs]])
            fd_module = ReadFileDrop(
                directory_configs={
                    str(dirpath): [
                        ReadFileDropConfiguration(channel_name="fd_channel", filedrop_type=FileDropType.JSON),
                    ],
                }
            )
            gateway = MyGateway(
                modules=[writer, fd_module, AddChannelsToGraphOutput()],
                channels=FDGatewayChannels(),
            )
            _ = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
    assert len(caplog.text) > 0
    assert "Failed to read data" in caplog.text


def test_invalid_struct(caplog):
    structs = [NotFDStruct(i="a") for i in range(1)]
    with caplog.at_level(logging.ERROR):
        with tempfile.TemporaryDirectory(dir=".") as dir:
            dirpath = Path(dir)
            writer = Writer(data=[[1, json_writer, str(dirpath / "file.json"), structs]])
            fd_module = ReadFileDrop(
                directory_configs={
                    str(dirpath): [
                        ReadFileDropConfiguration(channel_name="fd_channel", filedrop_type=FileDropType.JSON),
                    ],
                }
            )
            gateway = MyGateway(
                modules=[writer, fd_module, AddChannelsToGraphOutput()],
                channels=FDGatewayChannels(),
            )
            _ = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
    assert len(caplog.text) > 0
    assert "Failed to read data" in caplog.text


@pytest.mark.parametrize("writer_data", get_all_writers())
@pytest.mark.parametrize(
    "filedata",
    [
        [[0.1, f"file{idx}", [FDStruct(i=val) for val in range(idx + 1)]] for idx in range(2)],
        [[0.01, f"file{idx}", [FDStruct(i=val) for val in range(idx + 1)]] for idx in range(10)],
        [[0.01, f"file{idx}", [FDStruct(i=val) for val in range(idx + 1)]] for idx in range(100)],
    ],
)
def test_multiple_files(writer_data, filedata):
    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[fdata[0], writer_data[0], str(dirpath / fdata[1]), fdata[2]] for fdata in filedata])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_channel", filedrop_type=writer_data[1]),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        s = sum([len(fd[2]) for fd in filedata])
        assert len(out["fd_channel"]) == s
        csp_data = [d[1] for d in out["fd_channel"]]
        fd = []
        for fd_data in filedata:
            fd.extend(fd_data[2])
        match_data(csp_data, fd)


@pytest.mark.parametrize(
    "structs",
    [
        [FDStruct(i=i, s=chr(ord("a") + i % 26)) for i in range(1)],
        [FDStruct(i=i, s=chr(ord("a") + i % 26)) for i in range(10)],
        [FDStruct(i=i, s=chr(ord("a") + i % 26)) for i in range(100)],
    ],
)
def test_config_options(structs):
    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, json_writer, str(dirpath / "json_file1.json"), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(
                        channel_name="fd_channel",
                        filedrop_type=FileDropType.JSON,
                        subscribe_with_struct_timestamp=True,
                        subscribe_with_struct_id=True,
                    ),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        match_data([d[1] for d in out["fd_channel"]], structs, exact=True)


def test_extensions():
    structs_1 = [[FDStruct(i=i) for i in range(10)]]
    structs_2 = [[FDStruct(i=i) for i in range(20)]]
    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(
            data=[[0.1, json_writer, str(dirpath / "json_file1.js1"), structs_1], [1, json_writer, str(dirpath / "json_file1.js2"), structs_2]]
        )
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_list_channel", filedrop_type=FileDropType.JSON, extensions=[".js1"]),
                    ReadFileDropConfiguration(channel_name="fd_list_channel_2", filedrop_type=FileDropType.JSON, extensions=[".js2"]),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        out_data_1 = [d[1] for d in out["fd_list_channel"]]
        out_data_2 = [d[1] for d in out["fd_list_channel_2"]]
        assert len(out_data_1) == 1
        assert len(out_data_2) == 1
        match_lists(out_data_1, structs_1[0])
        match_lists(out_data_2, structs_2[0])


@pytest.mark.parametrize(
    "structs",
    [
        [{"a": FDStruct(i=i)} for i in range(1)],
        [{"a": FDStruct(i=i)} for i in range(10)],
        [{"a": FDStruct(i=i)} for i in range(100)],
    ],
)
def test_dict(structs):
    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, json_writer, str(dirpath / "json_file1.json"), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_dict_channel", filedrop_type=FileDropType.JSON),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        csp_data = [d[1] for d in out["fd_dict_channel"]]
        for d in csp_data:
            assert "a" in d
        csp_data = [d["a"] for d in csp_data]
        data = [d["a"] for d in structs]
        match_data(csp_data, data)

    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, json_writer, str(dirpath / "json_file1.json"), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_dict_basket_channel", filedrop_type=FileDropType.JSON),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        csp_data = [d[1] for d in out["fd_dict_basket_channel[a]"]]
        data = [d["a"] for d in structs]
        match_data(csp_data, data)


@pytest.mark.parametrize(
    "structs",
    [
        [FDStruct(i=i) for i in range(1)],
        [FDStruct(i=i) for i in range(10)],
    ],
)
def test_filedrop_type_custom(structs):
    def custom_writer(path, data):
        dict_data = convert_to_dict(data)
        new_dict_data = []
        for d in dict_data:
            new_d = {}
            for k, v in d.items():
                new_d[k.upper()] = v
            new_dict_data.append(new_d)
        with open(path, "wb") as f:
            data_bytes = orjson.dumps(new_dict_data)
            f.write(data_bytes)

    def custom_loader(path):
        with open(path, "rb") as f:
            dict_data = orjson.loads(f.read())
        dict_data = [{k.lower(): v for k, v in d.items()} for d in dict_data]
        return dict_data

    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, custom_writer, str(dirpath / "json_file1.json"), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_channel", filedrop_type=FileDropType.CUSTOM, loader=custom_loader),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        match_data([d[1] for d in out["fd_channel"]], structs)


@pytest.mark.parametrize(
    "structs",
    [
        [FDStruct(i=i) for i in range(1)],
        [FDStruct(i=i) for i in range(10)],
    ],
)
def test_deserializer(structs):
    def custom_writer(path, data):
        dict_data = convert_to_dict(data)
        new_dict_data = []
        for d in dict_data:
            new_d = {}
            for k, v in d.items():
                new_d[k.upper()] = v
            new_dict_data.append(new_d)
        with open(path, "wb") as f:
            data_bytes = orjson.dumps(new_dict_data)
            f.write(data_bytes)

    def deserializer(data):
        new_data = {k.lower(): v for k, v in data.items()}
        new_data.pop("id")
        new_data.pop("timestamp")
        return FDStruct(**new_data)

    with tempfile.TemporaryDirectory(dir=".") as dir:
        dirpath = Path(dir)
        writer = Writer(data=[[1, custom_writer, str(dirpath / "json_file1.json"), structs]])
        fd_module = ReadFileDrop(
            directory_configs={
                str(dirpath): [
                    ReadFileDropConfiguration(channel_name="fd_channel", filedrop_type=FileDropType.JSON, deserializer=deserializer),
                ],
            }
        )
        gateway = MyGateway(
            modules=[writer, fd_module, AddChannelsToGraphOutput()],
            channels=FDGatewayChannels(),
        )
        out = csp.run(gateway.graph, realtime=True, endtime=timedelta(seconds=2))
        match_data([d[1] for d in out["fd_channel"]], structs)
