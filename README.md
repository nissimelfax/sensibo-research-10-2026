# Improper TLS Certificate Validation in a Sensibo Smart AC Controller

|                |                                                                                              |
| -------------- | -------------------------------------------------------------------------------------------- |
| **Researcher** | Nissim Elfaks                                                                                |
| **Date**       | October 2026                                                                                 |
| **Target**     | Sensibo smart AC controller (IoT)                                                            |
| **Category**   | Improper Certificate Validation - [CWE-295](https://cwe.mitre.org/data/definitions/295.html) |
| **Severity**   | Low–Medium (Adjacent network; confidentiality impact)                                        |
| **Status**     | Responsibly disclosed to Sensibo on 2026-10-09                                               |
| **Scope**      | Researcher-owned device, account, and network only                                           |

---

## TL;DR

The Sensibo controller **does not validate the server's TLS certificate at the TLS layer** and relies solely on application-layer certificate pinning that is enforced *after* the handshake completes. Because the check runs too late, the MQTT client transmits the device's credentials (username + token) to an on-path attacker **before** the pinning detects the rogue server and disconnects.

With the leaked credentials, an attacker can connect to the broker and **eavesdrop on the device's activity** - observing when the AC turns on and off, which reveals usage and occupancy patterns (a confidentiality breach). Crucially, this did **not** extend to control: the broker enforces a **subscribe-only ACL** on the command topics, and the late pinning blocks a sustained impersonating proxy - so command injection was not possible. The demonstrated impact is therefore limited to **eavesdropping**.

---

## 1. Scope & Authorization

- All testing was performed **exclusively on a device, account, and network owned by the researcher.**
- No access was made to any third-party device, account, or data.
- No intrusion was performed against Sensibo's cloud infrastructure.
- Purpose: security assessment and responsible disclosure.

---

## 2. Reconnaissance

A network scan identified the Sensibo controller on the local network:

```
nmap -sn 192.168.0.1/24        # host discovery
nmap -T4 -A -p- <device-ip>    # full port / service scan
```

| Item        | Value                                       |
| ----------- | ------------------------------------------- |
| Device IP   | `192.168.1.121` (private)                   |
| MAC         | `<redacted>`                                |
| Open ports  | **None** (no externally reachable services) |
| Fingerprint | embedded `lwIP` TCP/IP stack                |

**Observation:** the device's **DNS query IDs do not appear to be randomized**, which makes DNS spoofing trivial - a useful precondition for the attack below.

Because the device exposes no listening services, the research pivoted from "attack the device" to **analyzing its outbound communication.**

---

## 3. Communication Architecture

Traffic analysis (after ARP spoofing) showed the device uses two channels:

| Domain | Protocol | Role |
|---|---|---|
| `new-config.sensibo.com` | HTTPS | Initial configuration pull |
| `new-emq.sensibo.com` | **MQTT over TLS** | Registration + receiving commands/updates (broker) |

The device **subscribes** to its MQTT topic and receives updates that originate from the Sensibo cloud. (User-initiated control from the web app is issued to a REST API, which in turn updates the broker - i.e., the device is the *consumer* of commands, not the publisher.)

The server certificate presented by both domains is signed by a **private Sensibo CA**, which initially suggested the device might enforce certificate pinning:

```
Signature Algorithm: sha1WithRSAEncryption
Issuer : C=IL, O=Sensibo Ltd.
Subject: C=US, ST=Some-State, O=Sensibo, CN=*.sensibo.com
Validity: 2018 → 3017
```

---

## 4. Lab Setup (MITM)

To intercept the TLS traffic, a rogue server and certificate chain were built:

1. **Rogue CA** - self-generated root certificate + private key.
2. **Rogue server certificate** - `CN=*.sensibo.com` (matching the original wildcard) plus a SAN containing the local proxy IP, signed by the rogue CA. Key + cert combined into `server.pem`.
3. **stunnel** - terminates TLS on `:443` and forwards plaintext to a local **mosquitto** broker.
4. **Redirection** - the device was forced to re-resolve DNS and was pointed at the local proxy via **ARP + DNS spoofing**.

---

## 5. Baseline - Normal Operation

Observed during unmodified operation (reference for comparison):

- On boot, the device **first pulls configuration** from `new-config`, then connects to `new-emq` and **subscribes** to its topic to receive updates.
- The device will **not** proceed to `new-emq` until the configuration pull has succeeded.
- Each session terminates with `FIN` followed by `RST`.

---

## 6. Main Finding - No TLS Certificate Validation (CWE-295)

Three **controlled** tests were run, varying only the certificate presented by the rogue server:

| #   | Certificate presented                              | TLS handshake | Result                                 |
| --- | -------------------------------------------------- | ------------- | -------------------------------------- |
| 1   | `CN=*.sensibo.com`, `O=Sensibo` (matches original) | **Completed** | MQTT CONNECT sent → credentials leaked |
| 2   | **Random CN**, `O=Sensibo`                         | **Completed** | credentials leaked                     |
| 3   | **Random CN** *and* **unrelated O**                | **Completed** | credentials leaked                     |

**Conclusion:** the TLS layer accepts **any** certificate - no chain validation and no field (CN/O) validation. Had the device validated or pinned at the TLS layer, it would have sent a `bad_certificate` alert mid-handshake and never reached `Finished`. Instead, the device relies **solely on application-layer certificate pinning, enforced only after the handshake completes.**

---

## 7. Impact - Credential Leakage on the Network

The two channels behave differently, which pinpoints the flaw:

| Channel | Observed sequence | Explanation |
|---|---|---|
| **new-emq** (MQTT) | TLS completes → device sends **MQTT CONNECT (credentials)** → then disconnects | The MQTT client sends CONNECT immediately, *before* the app-layer pin check tears down the connection |
| **new-config** (HTTPS) | TLS completes → connection closes **immediately, no content** | The HTTP client runs the pin check *before* sending its request → nothing leaks |

On `new-emq`, the MQTT `CONNECT` exposed the device's **username and token** (both redacted from this report). The token is a long-lived, per-device secret.

**Real-world impact of the leak:** with the credentials, an attacker can connect to the broker and **eavesdrop** on the device's traffic (IR commands / state), which reveals usage and **occupancy patterns** (when the AC is on/off).

### 7.1 Proof of Impact - Eavesdropping with the Leaked Credentials

To verify that the leaked credentials are actually usable, I connected to the **real** Sensibo broker with them, as an ordinary client (no MITM involved):

1. **Authentication succeeded.** The broker accepted the credentials (`CONNECT rc = 0`), confirming they are valid against the production broker - not just inside my lab.
2. **Eavesdropping works.** Subscribing to the device's topic tree (`things/1/<device-id>/#`) returned the **live stream of the device's traffic** - the IR command waveforms.
3. Operating the AC from the app produced a continuous series of messages received in real time, i.e. I could observe exactly **when the AC turned on/off and with what settings.**
4. **Command injection is blocked.** Attempting to publish to the command topics (`.../cmd`, `.../ir/...`) had no effect. A two-client test (one subscriber and one publisher, both using the device credentials) showed that messages published under the device identity were **never routed**, while genuine cloud traffic was received normally. The device identity is therefore **subscribe-only** on the command topics (broker-side ACL).

**Conclusion:** the leaked credentials are **not inert**. They grant real **eavesdropping** capability over the victim device - a confidentiality breach exposing usage and occupancy patterns - but **not control**, since the ACL blocks publishing commands.

---

## 8. Why a Sustained Intercepting Proxy Is Not Viable

An attempt to run a stable proxy between the device and the real Sensibo server was ruled out. The device completes the TLS handshake with any certificate, but the **application-layer pinning** then inspects the certificate and **closes the connection** if it is not Sensibo's genuine certificate. Without Sensibo's private key, a stable intermediary cannot be maintained.

**The only exposure window is the brief moment in which credentials are sent before the pinning disconnects.** Command injection into the device through such a proxy is therefore **not possible.**

---

## 9. Ruled-Out Directions (negative results)

- **Latency/timeout hypothesis** - initially I suspected the disconnect was caused by proxy-induced latency triggering a client timeout. Ruled out: tests ran on a local network with no significant delay, and the disconnect occurs at the **application layer** (after `Finished`), not as a connection timeout. This supports the pinning thesis.
- **Port-80 downgrade** - blocking port 443 (`iptables DROP`) to force cleartext produced **no** fallback to port 80 or any alternate port. The device does **not** downgrade to cleartext - a security strength.

---

## 10. Impact Assessment & Strengths

| Dimension           | Impact                                        | Status        |
| ------------------- | --------------------------------------------- | ------------- |
| **Confidentiality** | Credential harvest + eavesdropping            | **Confirmed** |
| **Integrity**       | Command injection **blocked** (ACL + pinning) | Protected     |
| **Availability**    | Not meaningfully affected                     | ---           |

**Estimated vector:** `AV:A/AC:H/PR:N/UI:N` - adjacent network, no privileges, no user interaction; confidentiality impact only.

**Defenses that held (worth noting):**
- Per-device token (not a shared secret).
- TLS encryption on all traffic.
- Broker-side **ACL** (device identity is subscribe-only → cannot publish commands).
- **No cleartext fallback.**
- **Late pinning** blocks server impersonation for sustained interception.

---

## 11. Recommendations

1. **Enforce proper certificate-chain validation and/or pinning at the TLS layer** - fixes the root cause.
2. **Gate credential transmission on successful server authentication** - never send the MQTT `CONNECT` before the server's identity is verified.
3. **Randomize DNS query IDs** to harden against DNS spoofing.
4. Consider **token rotation/revocation** available to the user after a suspected leak.

---

## 12. Responsible Disclosure

This issue was reported to Sensibo on **2026-10-09** via their security contact. The repository is kept private pending a reasonable remediation window; public disclosure will follow a coordinated-disclosure timeline. All device credentials and identifiers are **redacted**, and no exploit code enabling trivial reuse is included.

---

## Appendix - Evidence

| #        | Type       | Description                                                                                                                                                       |
| -------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E0       | screenshot | flow diagram that describe the device communication method                                                                                                        |
| E1       | screenshot | Server certificate details (private Sensibo CA, CN=*.sensibo.com)                                                                                                 |
| E2       | screenshot | altered Server certificate details (private Sensibo CA, CN=*.sensi**g**o.com)                                                                                     |
| E3       | screenshot | Cert-variation tests (random CN / O) - handshake still completes                                                                                                  |
| E4       | screenshot | MQTT CONNECT leaking username + token (both redacted)                                                                                                             |
| E5 + E51 | screenshot | TLS handshake completes on `new-emq`, immediately followed by the MQTT `CONNECT` packet leaking the username + token.                                             |
| E6       | screenshot | On `new-config`, the device completes the handshake against the forged cert but returns no data and retries - showing its dependency on a successful config pull. |
| E7       | screenshot | PoC: CONNECT rc=0 + AC on/off commands received (client id redacted)                                                                                              |


---

*All testing was conducted on equipment, accounts, and networks owned by the researcher. Credentials are redacted and will not be disclosed. This write-up is published for educational and defensive purposes.*
