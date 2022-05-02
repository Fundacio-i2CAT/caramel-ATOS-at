import asn1tools
import argparse
import json
from bootstrap_at import BootstrapAT
from enrolment_at import EnrolmentAT
from authorization_ticket_at import AuthorizationTicketAT
from query_at_at import QueryAT

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Runs the Acceptance Tests ATOS')
    parser.add_argument('--host', dest='host', type=str, action='store', default='localhost', help='Broker host (Default: "localhost")')
    parser.add_argument('--port', dest='port', type=int, action='store', default=1883, help='Broker port (By default: 1883)')
    args = parser.parse_args()
    BootstrapAT(args.host, args.port)
    EnrolmentAT(args.host, args.port)
    AuthorizationTicketAT(args.host, args.port)
    QueryAT(args.host, args.port)

