from csp_gateway import GatewayStruct as Base


class LookupModel(Base):
    foo: int = 9


class NoLookupModel(Base):
    foo: int = 10


NoLookupModel.omit_from_lookup(True)


def test_automatic_id_generation():
    for Model in [LookupModel, NoLookupModel]:
        o1 = Model()
        value1 = str(Model.id_generator.current())
        assert o1.id == value1

        o2 = Model()
        value2 = str(Model.id_generator.current())
        assert o2.id == value2
        assert o2.id == str(int(o1.id) + 1)

        if Model == LookupModel:
            assert Model.lookup(value1) == o1
            assert Model.lookup(value2) == o2


def test_lookup_fails():
    o1 = LookupModel()
    value1 = str(LookupModel.id_generator.current())
    assert o1.id == value1

    o2 = LookupModel()
    value2 = str(LookupModel.id_generator.current())
    assert o2.id == value2
    assert o2.id == str(int(o1.id) + 1)

    assert LookupModel.lookup(value1) == o1
    assert LookupModel.lookup(value2) == o2

    o1 = NoLookupModel()
    value1 = str(NoLookupModel.id_generator.current())
    assert o1.id == value1

    o2 = NoLookupModel()
    value2 = str(NoLookupModel.id_generator.current())
    assert o2.id == value2
    assert o2.id == str(int(o1.id) + 1)

    assert NoLookupModel.lookup(value1) is None
    assert NoLookupModel.lookup(value2) is None
