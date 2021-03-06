from urllib import request, response
import paho.mqtt.client as mqtt
import json
import asn1tools
from ecdsa import SigningKey, NIST256p
import base64



class AuthorizationTicketAT:
    """
    Class that certifies the process of requesting the bootstrap certificate from ATOS.
    """
    def __init__(self, host: str = "localhost", port: int = 1883) -> None:
        self.client = mqtt.Client()
        self.client.connect(host, port, 60)
        self.id = 36
        self.client.on_message = self.on_message
        self.encoder = asn1tools.compile_files('/src/asn1/Ieee1609Dot2BaseTypes.asn', codec = 'oer')
        self.keys = dict()
        self.key_index = 0
        self.client.loop_start()
        self.start_tests()

    def start_tests(self):
        self.client.subscribe("keygen-service/request-public-key")
        self.client.subscribe("signature-service/request-signature")
        self.client.subscribe("authorization-service/AT")
        self.request_at()
    
    def request_at(self):
        request = {"transaction_id": self.id}
        self.client.publish("authorization-service/request", json.dumps(request))
    
    def request_public_key(self, request):
        ecdsa_private_key = SigningKey.generate(curve=NIST256p)

        pk_str = ecdsa_private_key.verifying_key.to_string()
        #storing the key
        self.keys[self.key_index] = ecdsa_private_key
        self.key_index += 1

        public_key = ("ecdsaNistP256", ('uncompressedP256',
        {
            "x": pk_str[0:32],
            "y": pk_str[32:64]
        }))
        encoded_pk = self.encoder.encode('PublicVerificationKey', public_key)
        base64_pk = base64.b64encode(encoded_pk).decode()
        response = {"transaction_id": request["transaction_id"], "key_id": (self.key_index-1), "data": base64_pk, "type": "verification" }
        self.client.publish("keygen-service/public-key", json.dumps(response))

    def request_signature(self, request):
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
        print(msg.topic+" "+str(msg.payload))
        if msg.payload == "keygen-service/request-public-key":
            self.request_public_key(json.loads(msg.payload))
        elif msg.payload == "signature-service/request-signature":
            self.request_signature(json.loads(msg.payload))
        elif msg.payload == "authorization-service/AT":
            self.authorization_service_at(json.loads(msg.payload))
    
    def authorization_service_at(self, request):
        print("Everything ok!")
