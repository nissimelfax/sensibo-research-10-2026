import os, ssl
import paho.mqtt.client as mqtt

# Credentials come from the environment — never hard-code the device
# identifier or the token. Set them before running, e.g.:
#   export SENSIBO_DEVICE="<device-id>"
#   export SENSIBO_TOKEN="<token>"
DEVICE = os.environ.get("SENSIBO_DEVICE", "<device-id>")
TOKEN  = os.environ.get("SENSIBO_TOKEN", "<token>")

def on_connect(cl, u, f, rc):
    print("rc =", rc)
    cl.subscribe(f"things/1/{DEVICE}/#")

def on_message(cl, u, m):
    print(f"[{m.topic}]  {m.payload[:300]}")

c = mqtt.Client(client_id=f"sky3-{DEVICE}", protocol=mqtt.MQTTv311)
c.username_pw_set(DEVICE, TOKEN)
c.tls_set(cert_reqs=ssl.CERT_NONE)
c.tls_insecure_set(True)
c.on_connect = on_connect
c.on_message = on_message

c.connect("new-emq.sensibo.com", 443, keepalive=60)
c.loop_forever()
