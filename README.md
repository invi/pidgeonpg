## Pidgeon Privacy Guard

Consists in JavaScript implementation of the OpenPGP protocol [RFC4880]. 

### Requirements

Mozilla Firefox >= 9.0 and the  Network Security Services (NSS) library.

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

#### Compression algorightms (so far, only used for decompression)

* Zip
* Zlib
* Bzip2

#### Limitations

Certificate revocation signatures.

### Building instructions

By now there is only instructions to run from the addon-sdk. Building
the xpi package from the addon-sdk is broken.

1. Clone the Addon-SDK environment for Mozilla Firefox:
 
  `$ git clone https://github.com/mozilla/addon-sdk.git`


2. Load the Addon-SDK environment from it's path:

  `addon-sdk$ source bin/activate`


3. Clone the latest PidgeonPG code:

  `$git clone git://github.com/invi/pidgeonpg.git`


4. Enter the PidgeonPG path and run:

  `pidgeonpg$ cfx xpi`

This steps will create the file `pidgeonpg.xpi` inside the PidgeonPG path, ready to install.

### Documentation
