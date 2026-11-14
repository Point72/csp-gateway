import pickle
from queue import Full

import pytest

from csp_gateway.utils.picklable_queue import PickleableQueue


def test_queue_pickling():
    queue = PickleableQueue()
    unpickled_queue = pickle.loads(pickle.dumps(queue))

    assert queue.queue == unpickled_queue.queue
    assert queue.maxsize == unpickled_queue.maxsize


@pytest.mark.parametrize("maxsize", [0, 1, 3])
@pytest.mark.parametrize("protocol", [0, pickle.HIGHEST_PROTOCOL])
def test_queue_pickling_preserves_capacity(maxsize, protocol):
    queue = PickleableQueue(maxsize=maxsize)

    restored = pickle.loads(pickle.dumps(queue, protocol=protocol))

    assert restored.maxsize == maxsize
    assert restored.empty()


def test_queue_pickling_discards_items_and_task_count():
    queue = PickleableQueue(maxsize=2)
    queue.put_nowait("first")
    queue.put_nowait("second")

    restored = pickle.loads(pickle.dumps(queue))

    assert restored.maxsize == 2
    assert restored.empty()
    assert restored.unfinished_tasks == 0
    assert queue.qsize() == 2
    assert queue.unfinished_tasks == 2
    assert restored.mutex is not queue.mutex


def test_unpickled_queue_enforces_capacity():
    restored = pickle.loads(pickle.dumps(PickleableQueue(maxsize=1)))
    restored.put_nowait("first")

    with pytest.raises(Full):
        restored.put_nowait("second")

    assert restored.get_nowait() == "first"
    restored.task_done()
    assert restored.unfinished_tasks == 0
    restored.put_nowait("third")
    assert restored.get_nowait() == "third"
    restored.task_done()


def test_queue_restores_legacy_empty_state():
    restored = PickleableQueue.__new__(PickleableQueue)
    restored.__setstate__({})

    assert restored.maxsize == 0
    assert restored.empty()
    restored.put_nowait("first")
    assert restored.get_nowait() == "first"
    restored.task_done()
