# IoTKit Demo Nix

To demonstrate Virgil IoTKit in action we developed Demo based on [Virgil IoTKit](https://github.com/VirgilSecurity/virgil-iotkit) and its dev tools. The Demo contains samples for UNIX-like OS.

## Content
- [Run Tests](#run-tests)
- [Reference](#reference)
- [License](#license)
- [Support](#support)

## Demo Features

## Run Tests
To make sure that everything goes in the right way, we also provide a set of ready code-snippets for testing the necessary features:
- Crypto: crypto algorithms (e. g. hash, RNG, AES) and crypto operations (key pair, sign/verify etc.).
- Firmware related functionality: create firmware, save/load/install.
- Security Box (test storage module): read write for signed or/and encrypted data.
- SNAP (Secure Network Adjustable Protocol tests): send, receive etc.
Navigate to the [tests folder](/tests) of the repository to find preferred tests and start working with them.

To run the preferred test go through the following steps:
- Clone the Demo repository (if you haven't done that before)
```shell
$ git clone --recursive https://github.com/VirgilSecurity/demo-iotkit-nix
```
- Build tests project
```shell
$ mkdir build
$ cd build
$ cmake ..
$ make rpi-tests
```
- Run tests

## Reference
- [Virgil IoTKit repository](https://github.com/VirgilSecurity/virgil-iotkit/tree/release/v0.1.0-alpha)


## License

This library is released under the [3-clause BSD License](LICENSE).

<div id='support'/>

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
