# flask_auth_service/mq_producer.py
import os
import json
import pika


def get_connection():
    host = os.getenv("RABBITMQ_HOST", "rabbitmq")
    port = int(os.getenv("RABBITMQ_PORT", "5672"))
    user = os.getenv("RABBITMQ_USER", "guest")
    password = os.getenv("RABBITMQ_PASS", "guest")

    credentials = pika.PlainCredentials(user, password)
    params = pika.ConnectionParameters(host=host, port=port, credentials=credentials)
    return pika.BlockingConnection(params)


def publish_event(queue_name: str, event: dict):
    body = json.dumps(event).encode("utf-8")
    conn = get_connection()
    ch = conn.channel()
    ch.queue_declare(queue=queue_name, durable=True)
    ch.basic_publish(
        exchange="",
        routing_key=queue_name,
        body=body,
        properties=pika.BasicProperties(delivery_mode=2),
    )
    conn.close()
