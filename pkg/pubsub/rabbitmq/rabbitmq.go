package rabbitmq

import (
	"encoding/json"
	"fmt"
    "flag"

	
	"github.com/streadway/amqp"
)

const Name = "rabbitmq"

var (
    exchange = flag.String("rabbitmq-topic", "rabbitmq-channel", "Name of the exchange where rabbitmq can publish messages")
)

type RabbitMQ struct {
    conn *amqp.Connection
    ch   *amqp.Channel
}

func (r *RabbitMQ) Publish(data interface{}) error {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return fmt.Errorf("error marshalling data: %s", err)
    }

    err = r.ch.Publish(
        *exchange,     // exchange
        "", // routing key
        false,  // mandatory
        false,  // immediate
        amqp.Publishing{
            ContentType: "text/plain",
            Body:        jsonData,
        })
    if err != nil {
        return fmt.Errorf("error publishing message to rabbitmq: %s", err)
    }

    return nil
}

func (r *RabbitMQ) NewClient() error {
    var err error
	r.conn, err = amqp.Dial("amqp://guest:guest@localhost:5672/")
    if err != nil {
        return err
    }
    r.ch, err = r.conn.Channel()
    return err
}
