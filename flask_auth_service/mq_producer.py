# flask_auth_service/mq_producer.py
import os
import json
import pika

_exchangeName = "rent-hub.exchange"

def get_connection():
    host = os.getenv("RABBITMQ_HOST", "rabbitmq")
    port = int(os.getenv("RABBITMQ_PORT", "5672"))
    user = os.getenv("RABBITMQ_USER", "guest")
    password = os.getenv("RABBITMQ_PASS", "guest")
    _exchangeName = os.getenv("RABBITMQ_EXCHANGE", "rent-hub.exchange")

    credentials = pika.PlainCredentials(user, password)
    params = pika.ConnectionParameters(host=host, port=port, credentials=credentials)
    return pika.BlockingConnection(params)


def publish_event(routing_key: str, message: dict):
    body = json.dumps(message).encode("utf-8")
    conn = get_connection()
    ch = conn.channel()
    # ch.queue_declare(queue=routing_key, durable=True)
    # Declare exchange if not exists
    ch.exchange_declare(
        exchange=_exchangeName, exchange_type="direct"
    )
    ch.basic_publish(
        exchange=_exchangeName,
        routing_key=routing_key,
        body=body,
        properties=pika.BasicProperties(delivery_mode=2),
    )
    conn.close()
