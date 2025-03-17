### Setup Instructions

1. nav to 'basic' directory
```sh
cd /basic
```


### option 1: run using 'make'
1. follow the virtual env setup
```sh
cat p4setup.bash
```
2. run mininet with the topology
```sh
make run
```
### option 2: run manually
1. clean mininet
```sh
sudo mn -c
```
2. compile p4 program
```sh
p4c --target bmv2 --arch v1model --std p4-16 basic.p4
```
3. run mininet with the topology
```sh
sudo python3 topo.py --behavioral-exe simple_switch --json basic.json
```
### ***

4. in the mininet terminal, xterm the hosts and switches
```sh
xterm h1 h2 h3 s1 s2 s3
```
5. in terminal h2, listen for packets coming in
```sh
tcpdump -i eth0
```
6. in terminal s2, open s2's CLI
```sh
simple_switch_CLI --thrift-port-9091
```
7. in terminal s2, clone packets traversing s2 and send to egress port 2: serves h2
```sh
mirroring_add 100 2
```
8. In terminal h3, start sniffing
```sh
./receive.py
```
9. In terminal h1, send a packet to h3
```sh
./send.py 10.0.3.3 "hi h3 from h1"
```


### Makefile relative path bug
```sh
code ~/tutorials/utils/Makefile
```
Make this change
```python
RUN_SCRIPT = ~/tutorials/utils/run_exercise.py
```
