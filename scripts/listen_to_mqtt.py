import os, ssl
import paho.mqtt.client as mqtt

# Credentials come from the environment — never hard-code the device id or token.
#   set SENSIBO_DEVICE=<device-id>
#   set SENSIBO_TOKEN=<token>
DEVICE   = os.environ.get("SENSIBO_DEVICE", "<device-id>")
TOKEN    = os.environ.get("SENSIBO_TOKEN", "<token>")
USERNAME = f"things/{DEVICE}"          # the broker expects the "things/" prefix

def on_connect(cl, u, f, rc):
    print("rc =", rc)                  # rc = 0 -> connected
    cl.subscribe(f"things/1/{DEVICE}/#")

def on_message(cl, u, m):
    print(f"[{m.topic}]  {m.payload[:300]}")

# distinct client_id so we don't disconnect the real device
# (MQTT kicks off any existing client that shares an id)
c = mqtt.Client(client_id=f"listener-{DEVICE}", protocol=mqtt.MQTTv311)
c.username_pw_set(USERNAME, TOKEN)
c.tls_set(cert_reqs=ssl.CERT_NONE)
c.tls_insecure_set(True)
c.on_connect = on_connect
c.on_message = on_message

print(f"Connecting as {USERNAME} ...")
c.connect("new-emq.sensibo.com", 443, keepalive=60)
c.loop_forever()
