# xdp-mon
But what is it doing?
- attaches an XDP program to all local interfaces 
- captures UDP & TCP packets
- writes packet metadata to a BPF ringbuffer 
- exposes them using a TCP socket listening on port 35.

Needs libbpf.

```bash
make all
make run
```