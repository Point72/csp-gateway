import os
from datetime import datetime, timedelta
from typing import List

import csp
import sqlalchemy as db
from csp import ts
from sqlalchemy import MetaData, create_engine

from csp_gateway import Gateway, GatewayChannels, GatewayStruct
from csp_gateway.server.modules.sql import (
    ChannelSchemaConfig,
    PublishSQLA,
    SQLACnxDetails,
)
from csp_gateway.testing.harness import GatewayTestHarness


class MyTestStruct(GatewayStruct):
    a: str
    b: int


class MyTestStruct2(GatewayStruct):
    t: MyTestStruct


class GWC(GatewayChannels):
    test_channel: ts[MyTestStruct] = None
    test_channel_2d: ts[List[MyTestStruct]] = None
    test_channel_struct2: ts[MyTestStruct2] = None


def test_sqla_writer():
    open("db.sqlite", "w")  # create a fresh db to mess with
    cnx_details = SQLACnxDetails(engine="sqlite", host="db.sqlite")
    engine = create_engine(cnx_details.get_cnx_string())
    metadata = MetaData()
    test_table = db.Table(
        "test_struct_table",
        metadata,
        db.Column("not_a", db.String(255), nullable=True),
        db.Column("b", db.Integer, nullable=True),
        db.Column("c", db.String(255), nullable=True),
    )
    schema_configs = [
        ChannelSchemaConfig(
            channel_name="test_channel",
            table="test_struct_table",
            fields=["a", "b"],
            rename_fields={"a": "not_a"},
            augmentation_fields={"c": "I AM TESTOR"},
        )
    ]
    sqla_writer = PublishSQLA(cnx_details=cnx_details, schema_configs=schema_configs)
    metadata.create_all(engine)

    h = GatewayTestHarness(test_channels=[GWC.test_channel])

    t = MyTestStruct(timestamp=datetime(2023, 1, 1), a="a", b=1)
    h.send(GWC.test_channel, t)
    h.assert_ticked(GWC.test_channel, 1)

    gateway = Gateway(modules=[h, sqla_writer], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(1))

    # kind of tricky but this works
    with engine.connect() as connection:
        res = connection.execute(test_table.select()).fetchone()
        assert res
    assert res.not_a == t.a
    assert res.b == t.b
    assert res.c == "I AM TESTOR"

    os.remove("db.sqlite")


def test_struct_of_struct():
    open("db.sqlite", "w")  # create a fresh db to mess with
    cnx_details = SQLACnxDetails(engine="sqlite", host="db.sqlite")
    engine = create_engine(cnx_details.get_cnx_string())
    metadata = MetaData()
    test_table = db.Table(
        "test_struct_table",
        metadata,
        db.Column("t", db.String(255), nullable=True),
    )
    schema_configs = [
        ChannelSchemaConfig(
            channel_name="test_channel_struct2",
            table="test_struct_table",
            fields=["t"],
        )
    ]
    sqla_writer = PublishSQLA(cnx_details=cnx_details, schema_configs=schema_configs)
    metadata.create_all(engine)

    h = GatewayTestHarness(test_channels=[GWC.test_channel_struct2])

    t = MyTestStruct(timestamp=datetime(2023, 1, 1), a="a", b=1)
    t2 = MyTestStruct2(t=t)
    h.send(GWC.test_channel_struct2, t2)
    h.assert_ticked(GWC.test_channel_struct2, 1)

    gateway = Gateway(modules=[h, sqla_writer], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(1))

    # kind of tricky but this works
    with engine.connect() as connection:
        res = connection.execute(test_table.select()).fetchone()
    assert res is not None

    os.remove("db.sqlite")


def test_sqla_writer_2d():
    open("db.sqlite", "w")  # create a fresh db to mess with
    cnx_details = SQLACnxDetails(engine="sqlite", host="db.sqlite")
    engine = create_engine(cnx_details.get_cnx_string())
    metadata = MetaData()
    test_table = db.Table(
        "test_struct_table",
        metadata,
        db.Column("not_a", db.String(255), nullable=True),
        db.Column("b", db.Integer, nullable=True),
        db.Column("c", db.String(255), nullable=True),
    )
    schema_configs = [
        ChannelSchemaConfig(
            channel_name="test_channel_2d",
            table="test_struct_table",
            fields=["a", "b"],
            rename_fields={"a": "not_a"},
            augmentation_fields={"c": "I AM TESTOR"},
        )
    ]
    sqla_writer = PublishSQLA(cnx_details=cnx_details, schema_configs=schema_configs)
    metadata.create_all(engine)

    h = GatewayTestHarness(test_channels=[GWC.test_channel_2d])

    t1 = MyTestStruct(timestamp=datetime(2023, 1, 1), a="a", b=1)
    t2 = MyTestStruct(timestamp=datetime(2023, 1, 1), a="a", b=2)
    h.send(GWC.test_channel_2d, [t1, t2])
    h.assert_ticked(GWC.test_channel_2d, 1)

    gateway = Gateway(modules=[h, sqla_writer], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(1))

    # kind of tricky but this works
    with engine.connect() as connection:
        res = connection.execute(test_table.select()).fetchall()
    assert res[0].not_a == t1.a
    assert res[0].b == t1.b
    assert res[0].c == "I AM TESTOR"
    assert res[1].not_a == t2.a
    assert res[1].b == t2.b
    assert res[1].c == "I AM TESTOR"

    os.remove("db.sqlite")
