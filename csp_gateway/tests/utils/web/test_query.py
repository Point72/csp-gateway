import json
from datetime import datetime

from csp_gateway.server.demo import ExampleData
from csp_gateway.utils.web import (
    Filter,
    FilterCondition,
    FilterWhere,
    FilterWhereLambdaMap,
    Query,
)

DUMMY_STATE_DATA = [
    {
        "id": "2319519293118611459",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:20.395000+00:00"),
        "x": 1,
        "y": "111",
    },
    {
        "id": "2319519293118611463",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:21.396000+00:00"),
        "x": 2,
        "y": "222",
    },
    {
        "id": "2319519293118611467",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:22.394000+00:00"),
        "x": 3,
        "y": "333",
    },
    {
        "id": "2319519293118611471",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:23.394000+00:00"),
        "x": 4,
        "y": "444",
    },
    {
        "id": "2319519293118611475",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:24.394000+00:00"),
        "x": 5,
        "y": "555",
    },
    {
        "id": "2319519293118611479",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:25.394000+00:00"),
        "x": 6,
        "y": "666",
    },
    {
        "id": "2319519293118611483",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:26.394000+00:00"),
        "x": 7,
        "y": "777",
    },
    {
        "id": "2319519293118611487",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:27.394000+00:00"),
        "x": 8,
        "y": "888",
    },
    {
        "id": "2319519293118611491",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:28.394000+00:00"),
        "x": 9,
        "y": "999",
    },
    {
        "id": "2319519293118611495",
        "timestamp": datetime.fromisoformat("2023-03-30T14:45:29.394000+00:00"),
        "x": 0,
        "y": "101010",
    },
]

DUMMY_STATE_DATA = [ExampleData(**d) for d in DUMMY_STATE_DATA]


class TestQuery:
    def test_serialize_deserialize(self):
        filters = [
            Filter(attr="f1", by=FilterCondition(value="123", where="==")),
            Filter(attr="timestamp", by=FilterCondition(when=datetime(2000, 1, 1), where="==")),
        ]
        for f in filters:
            assert f.model_dump_json() == Filter.model_validate_json(f.model_dump_json()).model_dump_json()

    def test_lambda_map(self):
        for key in FilterWhere.__args__:
            assert key in FilterWhereLambdaMap

    def test_query_null(self):
        q = Query()
        assert q.calculate(DUMMY_STATE_DATA) == DUMMY_STATE_DATA
        q = Query(filters=[])
        assert q.calculate(DUMMY_STATE_DATA) == DUMMY_STATE_DATA

    def test_query_bad(self):
        q = Query(filters=[Filter(attr="", by=FilterCondition(value="", where="=="))])
        assert q.calculate(DUMMY_STATE_DATA) == []

        # TODO more

    def test_query_simple(self):
        q = Query(filters=[Filter(attr="x", by=FilterCondition(value=1, where="=="))])
        assert q.calculate(DUMMY_STATE_DATA) == [d for d in DUMMY_STATE_DATA if d.x == 1]

        q = Query(filters=[Filter(attr="x", by=FilterCondition(value=5, where="<="))])
        assert q.calculate(DUMMY_STATE_DATA) == [d for d in DUMMY_STATE_DATA if d.x <= 5]

        q = Query(
            filters=[
                Filter(attr="x", by=FilterCondition(value=5, where="<=")),
                Filter(attr="x", by=FilterCondition(value=2, where=">=")),
            ]
        )
        assert q.calculate(DUMMY_STATE_DATA) == [d for d in DUMMY_STATE_DATA if d.x <= 5 and d.x >= 2]

        q = Query(filters=[Filter(attr="x", by=FilterCondition(value=0, where="=="))])
        assert q.calculate(DUMMY_STATE_DATA) == [d for d in DUMMY_STATE_DATA if d.x == 0]

    def test_query_attr(self):
        q = Query(filters=[Filter(attr="id", by=FilterCondition(attr="y", where=">="))])
        assert q.calculate(DUMMY_STATE_DATA) == [d for d in DUMMY_STATE_DATA if d.id >= d.y]

    def test_query_when(self):
        when = datetime.fromisoformat("2023-03-30T14:45:24.394000+00:00")
        q = Query(filters=[Filter(attr="timestamp", by=FilterCondition(when=when, where="=="))])
        assert q.calculate(DUMMY_STATE_DATA) == [d for d in DUMMY_STATE_DATA if d.timestamp == when]


class TestFilterCondition:
    def test_query_loading(self):
        filter_str = json.dumps({"value": 123, "where": "=="})
        f = FilterCondition.model_validate_json(filter_str)
        assert isinstance(f.value, int)
        assert f.value == 123

        filter_str = json.dumps({"value": 123.0, "where": "=="})
        f = FilterCondition.model_validate_json(filter_str)
        assert isinstance(f.value, float)
        assert f.value == 123.0

        filter_str = json.dumps({"value": 123.5, "where": "=="})
        f = FilterCondition.model_validate_json(filter_str)
        assert isinstance(f.value, float)
        assert f.value == 123.5

        filter_str = json.dumps({"value": "123.5", "where": "=="})
        f = FilterCondition.model_validate_json(filter_str)
        assert isinstance(f.value, str)
        assert f.value == "123.5"
