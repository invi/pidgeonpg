## Pidgeon Privacy Guard

JavaScript implementation of the OpenPGP protocol [RFC4880](http://tools.ietf.org/html/rfc4880) for Mozilla Firefox. 

### Requirements

* Mozilla Firefox 14.0 or newer.

### Features

#### Key pair generation

* RSA (1024/2048/4096 bits)
* DSA (1024 bits)
* ElGamal (1024 bits)

#### Supported asymmetric algorithms

* RSA encryption and signatures (1024/2048/4096 bits)
* DSA signatures (1024/2028/3072 bits)
* ElGamal encryption (1024/2048/3072 bits)

#### Tested symmetric algorithms

* Cast5
* AES-256

#### Compression algorightms (used for decompression)

* Zip
* Zlib
* Bzip2

### Build instructions

1. Clone the Addon-SDK for Mozilla Firefox repository:
 
>  git clone https://github.com/mozilla/addon-sdk.git

2. Clone the PidgeonPG repository:

> git clone git://github.com/invi/pidgeonpg.git
>
> git submodule init
>
> git submodule update

3. Load the Addon-SDK environment from it's path:

> cd addon-sdk
>
> source bin/activate
>
> cd ..

4. Enter the PidgeonPG path and run:

> cd pidgeonpg
>
> cfx xpi

This steps will create the file `pidgeonpg.xpi` inside the `pidgeonpg` path, ready to install with Mozilla Firefox.
