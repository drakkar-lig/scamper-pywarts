# About pywarts

`pywarts` is a pure-python parsing library for the Warts format.
Warts is an extensible binary format produced by
[Scamper](http://www.caida.org/tools/measurement/scamper/), an
Internet measurement tool from CAIDA, to store measurement results
such as traceroutes and pings.

This library started off from the [Python implementation from
CMAND](https://github.com/cmand/scamper), by Robert Beverly, but has
now vastly diverged.  The parsing architecture is loosely inspired
from the [Ryu](https://osrg.github.io/ryu/) packet parser, although it
is less complex because the requirements are less stringent.

## Installation

```shell
pip install scamper-pywarts
```

## Features

- pure-Python, no dependency, works with both python2 and python3
- can read all basic Warts data types (ping, traceroute)
- easily extensible for other Warts data types (patches are welcome)
- nice class-based interface
- reasonably good performance (a few minutes to parse a 80 MiB warts file with traceroute data)
- streaming-like interface: no more than one record is pulled in
  memory at any given time, so it should handle very large Warts file
  with a limited amount of memory.  You can probably even consume data
  directly from the output of a running Scamper process.

## Using pywarts

For now, the only public API is very low-level: it simply reads from a
stream (for instance a file) and returns Warts records as Python objects.

To read records, call `warts.parse_record` repeatedly until it returns
`None`.  Remember to open your input Warts files in binary mode!

The returned value of `warts.parse_record` is an instance of an
appropriate subclass (e.g. `Traceroute`), depending on the record type.
Be aware that all optional attributes are set to None if not present in
the input file.  You should always check for this possibility in your user
code.

Here is an example that opens a file, and repeatedly parses records
until it finds a Traceroute record (warts files usually have a few
initial records with mostly uninteresting data).

```python
import warts
from warts.traceroute import Traceroute

with open('my_file.warts', 'rb') as f:
    record = warts.parse_record(f)
    while not isinstance(record, Traceroute):
        record = warts.parse_record(f)
    if record.src_address:
        print("Traceroute source address:", record.src_address)
    if record.dst_address:
        print("Traceroute destination address:", record.dst_address)
    print("Number of hops:", len(record.hops))
    print(record.hops)
```

To know which attributes are available, look at the definition of the
relevant class (there will be real documentation at some point).  For
instance, for `Traceroute`, almost all attributes are optional and defined
here:
[traceroute.py](https://github.com/drakkar-lig/scamper-pywarts/blob/master/warts/traceroute.py#L34).
Some attributes are not optional and are defined in the `parse()` method
of the class.  For instance, a traceroute object `t` always provides a
list of `TracerouteHop` objects in `t.hops`.

If parsing fails, an instance of `errors.ParseError` is thrown.
`pywarts` generally tries to clean up after itself, so the file
descriptor should point to the next record even after a parsing error.
Of course, this is not always possible, especially if the input file
is incorrectly formatted.


## Difference with the implementation from CMAND

Here is some points on which `pywarts` improves from the code from
<https://github.com/cmand/scamper>:

- fully python3-compatible
- nicer class-based interface, instead of huge dicts with all flags
- properly handles unknown flags and options, by ignoring them
- attribute names have been generally made more readable (although
  that often means longer names)
- possibly quite a bit faster (it would need proper benchmarks), because
  of the way we parse flags and strings.  Also, we read a whole record
  into memory before parsing it, which is a bit faster than calling
  `read()` repeatedly on very small amount of data.

However, there are some areas where the CMAND code does more things:

- `pywarts` does not implement the deprecated address format (it is
  quite complex and has been deprecated for several years)
- there are some nice scripts in <https://github.com/cmand/scamper>,
  for instance a script to attach to and control a running Scamper
  process

# Developement

## High-level

Some currently unanswered questions:

- What should the high-level API look like, and is there even a need
  for a higher-level API?  Just an iterator of records?  Allow to
  filter by record type?  Try to parse further, for instance decode
  flags or produce different objects for UDP, TCP and ICMP
  traceroutes?
- Should we try to normalise values when parsing?  For instance,
  should we use `ipaddr` objects for addresses?  Some times are
  expressed in centiseconds, some in microseconds, some in seconds.
  Should we normalize that to a common base?  Are floats acceptable
  for time values?
- What should we do when there is a parsing error?  How can the user
  continue parsing the next record if he/she wants to?

Please open issues if you have ideas and thoughts on these questions.
