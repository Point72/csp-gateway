import csp
import os

from datetime import datetime, timedelta

from csp_gateway import (
    GatewayChannels,
    GatewayStruct,
    ChannelSelection,
    GatewayModule,
    Gateway,
    ReadWriteMode,
    ReplayEngineKafka,
    KafkaConfiguration,
    ReadWriteKafka,
    AddChannelsToGraphOutput,
)


def create_kafka_config():
    group_id = "foo"
    broker = "kafka-broker:9093"
    auth = True

    user_lower = os.environ.get("USER").lower()
    user_principal = os.environ.get("USER_PRINCIPAL_NAME")

    # NOTE: This file is used for verifying the Kafka broker
    ssl_ca_location = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"

    # NOTE: This will have to be set up by the user.
    kerberos_keytab = (
        f'/home/{user_lower}/.keytab/{user_principal.split("@")[0]}.keytab.rc4-hmac'
    )
    return KafkaConfiguration(
        group_id=group_id,
        broker=broker,
        sasl_kerberos_keytab=kerberos_keytab,
        sasl_kerberos_principal=user_principal,
        ssl_ca_location=ssl_ca_location,
        auth=auth,
    )


class MyStruct(GatewayStruct):
    foo: str


class GWC(GatewayChannels):
    my_proclamation: csp.ts[MyStruct] = None


class MyCallToTheWorld(GatewayModule):
    my_data: csp.ts[MyStruct]

    def connect(self, channels: GWC):
        channels.set_channel(GWC.my_proclamation, self.my_data)


if __name__ == "__main__":
    # In this example, the read and write functionalities for the
    # ReadWriteKafka GatewayModule are shown. This allows users
    # to use Kafka to send and receive Gateway channel ticks on
    # Gateway Strcuts.

    # When ran, this file will print a struct called MyStruct,
    # with foo="HELLO WORLD!!" many times. One ReadWriteKafka instance
    # writes the struct to Kafka from the channel, and the other reads it
    # from Kafka and populates the channel.
    encoding_with_engine_timestamps = True

    set_module = MyCallToTheWorld(my_data=csp.const(MyStruct(foo="HELLO WORLD!!")))
    channels = [GWC.my_proclamation]
    kafka_write_module = ReadWriteKafka(
        config=create_kafka_config(),
        publish_channel_to_topic_and_key={
            GWC.my_proclamation: {"kafka_test": "kafka_read_write_example"}
        },
        encoding_with_engine_timestamps=encoding_with_engine_timestamps,
    )
    kafka_read_module = ReadWriteKafka(
        config=create_kafka_config(),
        subscribe_channel_to_topic_and_key={
            GWC.my_proclamation: {"kafka_test": "kafka_read_write_example"}
        },
        encoding_with_engine_timestamps=encoding_with_engine_timestamps,
    )

    gateway = Gateway(
        modules=[
            set_module,
            kafka_read_module,
            kafka_write_module,
            AddChannelsToGraphOutput(),
        ],
        channels=GWC(),
        channels_model=GWC,
    )

    out = csp.run(
        gateway.graph,
        starttime=datetime.utcnow(),
        endtime=timedelta(seconds=2),
        realtime=True,
    )
    print(f"{out[GWC.my_proclamation] = }")
