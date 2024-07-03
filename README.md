# Pycket Drill

This is a simple reimplementation (with a lot of missing features) of
Google's [packetdrill](https://github.com/google/packetdrill) tool.
The purpose of the tool is to allow exercising OS syscalls on one end
and reading/writing raw packets on the other end. Compared to the original
packetdrill which uses custom DSL, this version is implemented in pure python
and uses [ScaPy](https://scapy.net) to manipulate the packets' contents.

Under the hood, the tool creates a TUN device for simulating a pipe
between the local address (this is the side the OS syscalls operate on)
and the remote address (this is the side which is supposed to generate
and verify raw packets).

## Missing Features

- Tracking timing
- Connecting to real, non-TUN, remotes
- More?
