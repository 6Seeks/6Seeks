
# 6Seeks: IPv6 Periphery Scanning System

It aims to scan the Internet-wide IPv6 network periphery. It is an asynchronous scanning system that incrementally adjusts search directions, automatically prioritising the scanning of IPv6 address spaces with a higher concentration of IPv6 peripherals. Its network periphery model is inspired by [Xmap]{https://github.com/idealeer/xmap}.


## QuickStart

You should prepare a file consisting of unique and equal IPv6 prefixes, such as [global /37 prefixes](37blocks), one prefix per line.

Then run the shell script `run.sh

```bash
bash run <interface>
```

Note that the `<interface>' should be set up with the global IPv6 access. In this case, `run.sh` can automatically configure the _source address_, _MAC address_, _gateway MAC address_ of the probes.

## Customisation
In 6Seeks' source code, both the decay rate _r_ and the increment _K_ can be adjusted. They are set to 1 and 10000 by default.

## What is the underlying algorithm?

Its capabilities include randomly exploring multiple IPv6 prefixes with different weights, i.e. the IPv6 prefixes with high historical rewards will be explored more, like reinformant learning.

More detail will be seen in our paper.


## Disclaimer

6Seeks system is not very complete yet, please don't use it directly for production scenes. We only publish it here to facilitate research on IPv6 network measurements.


