# DNS-Rogue-Server

This is a DNS rogue server developed for ethical purposes and pestesting.

## Starting

### Pre-requisites

```
sudo apt install python3
sudo apt install python3-pip
```

### Installation
```
git clone https://github.com/juanga333/DNS-Rogue-Server.git
cd DNS-Rogue-Server
pip3 install -r requirements.txt
```

### Usage
_This is the basic usage example_
```
sudo python3 dnsserver.py
```

_In order to specify a different location of the list of spoof domains_
```
sudo python3 dnsserver.py -l <location>
```

_The domains.txt need to be a JSON. An example could be:_
```
{
    "domain": "ip",
    "github.com": "192.168.0.103"
}
```

