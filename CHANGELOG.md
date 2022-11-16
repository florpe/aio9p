# Changelog

## 0.3.0 - 2022-11-16

Client support.

## Added

* Implementations of the client side of 9P2000 and 9P2000.u
    ** Found in aio9p.dialect.client
* Some integration testing using the new client support
* Unix domain socket support.

## Changed

* The inheritance tree has grown in order to enable code reuse between
    client and server classes.

## 0.2.0 - 2022-11-05

Support for 9P2000.u .

## Added

* 9P2000.u protocol and example
* Stat objects support the update logic described in the 9P2000 spec

## 0.1.0 - 2022-10-22

Initial release.

### Added

* `asyncio` protocol interface
* Base 9P2000 protocol
* Base 9P2000 Stat class
* Base 9P2000 example
