# Intelligent-IoT-Honeypot

An Intelligent Honeypot for Heterogeneous IoT Devices using Reinforcement Learning

Report of my BTP Final Report can be found [here](https://www.dropbox.com/s/f9hqo3zd8lptqhr/BTP_Final_Report.pdf?dl=0).

This project is based on the paper [IoTCandyJar: Towards an Intelligent-Interaction Honeypot
for IoT Devices](https://paper.seebug.org/papers/Security%20Conf/Blackhat/2017_us/us-17-Luo-Iotcandyjar-Towards-An-Intelligent-Interaction-Honeypot-For-IoT-Devices-wp.pdf).

### Requirements

* Python3
* socket
* netaddr (`pip3 install netaddr`)
* requests (`pip3 install requests`)

### Files Summary

* `iot_ip_addr_collector.ipynb`
* `server_template_for_request_response.py`
* `send_request_to_all_iot.py`
* `print_requests.py`
* `*_addr.dat`
* `port_*.dat`
* `response_from_iot.dat`

### Code/Files explained

* `iot_ip_addr_collector.ipynb` file contains the IoT Scanner. This works like a IoT crawler/search engine scanning random public IP addresses. If an IoT device is found then its IP:port is temporarily stored in a python set and later stored in the files `*_addr.dat` using python pickle. All the IPs scanned till now are stored in the file `ips_checked.dat` so that same IP is not scanned twice.

* `server_template_for_request_response.py` is the honeyoot listener instances
  that should be run on a public IP to attract the attackers. The requests sent
by the attackers are stored in the files `port_*.dat` where * depends on the
port on which the server is listening for attacks.

* `send_request_to_all_iot.py` sends all the requests stored in files
  `port_*.dat` to all the IoT devices through their IP addresses stored in the
files `*_addr.dat`. All the responses received from the IoT devices are stored
in the file `response_from_iot.dat`.

* Just for an example of the working of the honeypot, if the attacker requests
  us for the fiee `login.cgi`, a random response from `response_from_iot.dat`
is sent to the attacker. This part will be the part where the RL can come inoo
picture. Using a good learning model, the honeypot can learn which response
should be sent to the attacker instead of random responses.

* `print_requests.py` file just prints all the requests received on some port
  till now.

---

All the code is super easy to understand, though I would like to refactor it.
