Information
------------

Hardware Bitcoin Wallet

Initially created by [someone42]
(https://github.com/someone42/hardware-bitcoin-wallet) and modified
for the juno-r2 board making use of the TrustZone.

>A minimal Bitcoin (see http://bitcoin.org/ ) wallet for embedded devices. The
wallet is responsible for parsing transactions, prompting the user and signing
transactions. In order to do this, the wallet also stores and manages private
keys, but it does not store anything else. The wallet is not aware of the
blockchain and communicates with a BitCoin client ("the host" from the point
of view of the code here) via. a point-to-point stream-based link.
