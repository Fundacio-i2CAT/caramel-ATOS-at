from urllib import request, response
import paho.mqtt.client as mqtt
import json
import asn1tools
from ecdsa import SigningKey, NIST256p
import base64
import time



class BootstrapAT:
    """
    Class that certifies the process of requesting the bootstrap certificate from ATOS.
    """
    def __init__(self, host: str = "localhost", port: int = 1883) -> None:
        self.client = mqtt.Client()
        self.client.connect(host, port, 60)
        self.id = 34
        self.client.on_message = self.on_message
        self.encoder = asn1tools.compile_files('/src/asn1/Ieee1609Dot2BaseTypes.asn')
        self.keys = dict()
        self.key_index = 0
        self.client.loop_start()
        self.start_tests()
        print("****************END BOOTSTRAP AT***********************")
        self.client.loop_stop()
        self.client.disconnect()

    #def __del__(self):   
    
    def start_tests(self):
        print("**************START BOOTSTRAP AT***********************")
        self.client.subscribe("keygen-service/request-public-key")
        self.client.subscribe("signature-service/request-signature")
        self.client.subscribe("bootstrap-service/BC")
        time.sleep(10)
        self.request_bootstrap()
        time.sleep(30)
    
    def request_bootstrap(self):
        request = {"transaction_id": self.id}
        payload = json.dumps(request)
        print("Publishing to:")
        print("bootstrap-service/request")
        print(payload)
        self.client.publish("bootstrap-service/request", payload)
    
    def request_public_key(self, request):
        print("REQUEST PUBLIC KEY")
        ecdsa_private_key = SigningKey.generate(curve=NIST256p)
        pk_str = ecdsa_private_key.verifying_key.to_string()
        #storing the key
        self.keys[self.key_index] = ecdsa_private_key
        self.key_index += 1
        
        encoded_pk = self.encoder.encode('EccP256CurvePoint', ('uncompressedP256',
        {
            "x": pk_str[0:32],
            "y": pk_str[32:64]
        }))
        base64_pk = base64.b64encode(encoded_pk).decode()
        response = {"transaction_id": request["transaction_id"], "key_id": (self.key_index-1), "data": base64_pk, "type": "verification" }
        payload = json.dumps(response)
        print("Publishing to:")
        print("keygen-service/public-key")
        print(payload)
        self.client.publish("keygen-service/public-key", payload)

    def request_signature(self, request):
        print("Signature Requested")
        # request signature {"transaction_id": <transaction_id 1>, "key_id": <id>, "tbs": <B64urlsafeToBeSigned COER>, "signer": <self/signer_certificate_bytes> }
        tbs = base64.b64decode(request["tbs"])
        signature = self.keys[request["key_id"]].sign(tbs)
        response_decoded = {
            "hashId" : 'sha256',
            "tbsData" : tbs,
            "signer" : (
                "self", None
            ), 
            "signature" : ('ecdsaNistP256Signature',
            {
                "rSig" : ("x-only", signature[0:32]),
                "sSig" : signature[32:64]
            })
        }
        response_encoded = self.encoder.encode('SignedData', response_decoded)
        response_encoded = base64.b64encode(response_encoded)
        final_response = {
            "transaction_id" : request["transaction_id"],
            "signed": response_encoded
        }
        self.client.publish("signature-service/signature", json.dumps(final_response))
    
    def on_message(self, client, userdata, msg):
        print("Received from MQTT")
        print(msg.topic)
        print(msg.payload)
        print("******************")
        if msg.topic == "keygen-service/request-public-key":
            request = json.loads(msg.payload)
            print(request)
            self.request_public_key(request)
        elif msg.topic == "signature-service/request-signature":
            self.request_signature(json.loads(msg.payload))
        elif msg.topic == "bootstrap-service/BC":
            self.bootstrap_service_BC(json.loads(msg.payload))
    
    def bootstrap_service_BC(self, request):
        print(request)
        print("**************AT RIGHT***********************")

