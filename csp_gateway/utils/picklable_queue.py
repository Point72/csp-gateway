from queue import Queue


class PickleableQueue(Queue):
    """
    An extension of the base Queue to allow it to be pickled

    NOTE: Pickled queues will not retain the contents of their queues
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __getstate__(self):
        return {}

    def __setstate__(self, state):
        self.__dict__.update(Queue().__dict__)
