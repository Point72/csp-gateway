import pickle

from csp_gateway.utils.picklable_queue import PickleableQueue


def test_queue_pickling():
    queue = PickleableQueue()
    unpickled_queue = pickle.loads(pickle.dumps(queue))

    assert queue.queue == unpickled_queue.queue
    assert queue.maxsize == unpickled_queue.maxsize
