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

## Features

- pure-Python, very few dependencies

- can read all basic Warts data types (ping, traceroute)

- nice class-based interface

- streaming-like interface: no more than one record is pulled in
  memory at any given time, so it should handle very large Warts file
  with a limited amount of memory.  You can probably even consume data
  directly from the output of a running Scamper process.

- easily extensible for other Warts data types (patches are welcome)


## Difference with the implementation from CMAND

Here is some points on which `pywarts` improves from the code from
CMAND:

- fully python3-compatible

- nicer class-based interface, instead of huge dicts with all flags

- attribute names have been generally made more readable (although
  that often means longer names)

- probably a bit faster (→ benchmark), because we rely on (built-in) C
  functions to parse strings and flags

- properly handles unknown flags and options, by ignoring them

However, there are some areas where the CMAND code does more things:

- `pywarts` does not implement the deprecated address format (it is
  quite complex and has been deprecated for several years)

# Documentation

Unit tests and proper documentation will come in time.

Low-level API: pretty simple, `base.WartsRecord.parse` takes a
BufferedReader object and reads a record from it.  Please make sure to
open your input Warts files in binary mode.

The returned object is an instance of an appropriate subclass
(e.g. `Traceroute`), depending on the record type.  Be aware that all
optional attributes are set to None if not present in the input file.
You should always check for this possibility in your user code.

If parsing fails, an instance of `errors.ParseError` is thrown.
`pywarts` generally tries to clean up after itself, so the file
descriptor should point to the next record even after a parsing error.
Of course, this is not always possible, especially if the input file
is incorrectly formatted.

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

## Low-level

These are planned improvements, mostly invisible to users of the library:

- introduce some state in the basic parsing functions.  This would
  avoid the cumbersome and manual book-keeping of the number of bytes
  read.  It would also allow to parse referenced address, which is
  necessary for correctness.

- check for EOF in all places reading data from the input, so that we
  avoid throwing unexpected exceptions around.
