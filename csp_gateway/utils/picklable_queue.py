from queue import Queue


class PickleableQueue(Queue):
    """
    An extension of the base Queue to allow it to be pickled

    NOTE: Pickled queues retain their maxsize, but not their contents or unfinished tasks.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __getstate__(self):
        return {"maxsize": self.maxsize}

    def __setstate__(self, state):
        self.__dict__.update(Queue(maxsize=state.get("maxsize", 0)).__dict__)
