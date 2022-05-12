import base64
from this import d
import paho.mqtt.client as mqtt
import hashlib
import json
import time

class QueryAT:
    def __init__(self, host: str = "localhost", port: int = 1883) -> None:
        self.client = mqtt.Client()
        self.client.connect(host, port, 60)
        self.client.on_message = self.on_message
        self.client.loop_start()
        self.start_tests()

    def start_tests(self):
        self.client.subscribe("revocation-service/AT-status")
        self.client.subscribe("certificate-service/rootca")
        self.client.subscribe("certificate-service/authorizationca")
        self.query_at()
        self.request_rootca()
        self.request_aa()
        time.sleep(30)
    
    def __del__(self):
        print("Ending Query AT test")
        self.client.disconnect()


    def query_at(self):
        hash = hashlib.sha256(b'12312341234').digest()[0:8]
        print(hash)
        at =base64.b64encode(hash).decode()
        request = {"transaction_id": 40, "at": at}
        self.client.publish("revocation-service/AT-query", json.dumps(request))

    def response_query(self, response):
        print("Response received")
    
    def request_rootca(self):
        request = {"transaction_id": 41}
        self.client.publish("certificate-service/rootca-request", json.dumps(request))

    def request_aa(self):
        request = {"transaction_id": 42 }
        self.client.publish("certificate-service/authorizationca-request", json.dumps(request))

    def on_message(self, client, userdata, msg):
        print(msg.topic+" "+str(msg.payload))
        if msg.payload == "revocation-service/AT-status":
            self.response_query(json.loads(msg.payload))
        elif msg.payload == "certificate-service/rootca":
            print("hola rootca")
        elif msg.payload == "certificate-service/authorizationca":
            print("hola authorizationca")