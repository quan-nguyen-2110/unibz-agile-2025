import os
import json
import time
import pika


def get_connection():
    host = os.getenv("RABBITMQ_HOST", "rabbitmq")
    port = int(os.getenv("RABBITMQ_PORT", "5672"))
    user = os.getenv("RABBITMQ_USER", "guest")
    password = os.getenv("RABBITMQ_PASS", "guest")

    credentials = pika.PlainCredentials(user, password)
    params = pika.ConnectionParameters(host=host, port=port, credentials=credentials)
    return pika.BlockingConnection(params)


def publish_json(queue_name: str, message: dict):
    """Publish a JSON message to a queue."""
    body = json.dumps(message).encode("utf-8")
    connection = get_connection()
    channel = connection.channel()
    channel.queue_declare(queue=queue_name, durable=True)
    channel.basic_publish(
        exchange="",
        routing_key=queue_name,
        body=body,
        properties=pika.BasicProperties(
            delivery_mode=2  # make message persistent
        ),
    )
    connection.close()


def consume(queue_name: str, handler):
    """
    Consume JSON messages from a queue and call handler(message_dict).
    Runs in a blocking loop (use in a background thread).
    """
    while True:
        try:
            connection = get_connection()
            channel = connection.channel()
            channel.queue_declare(queue=queue_name, durable=True)

            def on_message(ch, method, properties, body):
                try:
                    data = json.loads(body.decode("utf-8"))
                except json.JSONDecodeError:
                    print(f"[x] Invalid JSON message: {body!r}")
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                    return

                try:
                    handler(data)
                except Exception as e:
                    print(f"[x] Error in handler: {e}")

                ch.basic_ack(delivery_tag=method.delivery_tag)

            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(
                queue=queue_name,
                on_message_callback=on_message
            )

            print(f" [*] Starting consumer on queue '{queue_name}'")
            channel.start_consuming()
        except Exception as e:
            print(f"[!] Consumer error: {e}. Retrying in 5 seconds...")
            time.sleep(5)
