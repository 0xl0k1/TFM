#!/usr/bin/env python3

class Port:
    def __init__(self, number, protocol, state, service, version):
        self.number = number
        self.protocol = protocol
        self.state = state
        self.service = service
        self.version = version