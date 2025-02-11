from csp_gateway import GatewayModule, get_counter


class MyGatewayModule(GatewayModule):
    def connect(self, channels):
        pass

    def shutdown(self):
        pass


class IDGenerator:
    def time_get_counter(self):
        _ = get_counter(MyGatewayModule())


class Counter:
    def setup(self):
        self.counter = get_counter(MyGatewayModule())

    def time_counter_next(self):
        self.counter.next()
