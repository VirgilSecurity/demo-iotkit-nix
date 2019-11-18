# Virgil IoTKit Demo
The Demo is based on [Virgil IoTKit](https://github.com/VirgilSecurity/virgil-iotkit) and its dev tools to demonstrate secure IoT devices development in action. The IoTKit Demo is conditionally divided into 3 actors (Vendor, Factory, and End-user) to easily understand the whole development process.

## Content
- [Functions](#functions)
- [Download Demo](#download-demo)
- [Configure and Run Demo](#configure-and-run-demo)
- [Explore Demo](#explore-demo)
- [Reference](#reference)
- [Support](#support)

## Functions
The IoTKit Demo allows you to:
- Generate trusted provisioning package
- Emulate IoT devices
- Securely perform IoT device provisioning
- Register IoT devices on the security platform
- Sign and publish new Firmware and TrustList
- Manage a user's IoT devices

## Download Demo
Download the latest IoTKit Demo version via the following links:
- for [Unix-like OS](https://github.com/VirgilSecurity/virgil-iotkit/blob/release/v0.1.0-alpha/scripts/run-demo.sh).
- for [Windows OS](https://github.com/VirgilSecurity/virgil-iotkit/blob/release/v0.1.0-alpha/scripts/run-simulator.bat)

## Configure and Run Demo
To launch the IoTKit Demo you will need to run the Docker and generate Virgil application token (`App Token`).

### Prerequisites
Before you start, you need to install the following:
- **Virgil CLI** is a unified tool to manage your Virgil Cloud services and perform all required commands to configure the Demo. Follow this guide to [install the Virgil CLI](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/install) on your platform.
- **Docker** is a tool designed to make it easier to create, deploy, and run applications by using containers. Follow this guide to [install the Docker](https://docs.docker.com/install/) for your platform.

### Generate App Token
To start working with the Demo, you need to specify your `App Token`. In case you don't have App Token you need to generate it using Virgil CLI.

To generate an `App Token` go through the following steps:
- Launch the Virgil CLI
```shell
$ virgil
# or virgil.exe for Windows OS
```
- Register Virgil Account (omit this step, in case you have it). Find examples [here](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/manage-account).
```shell
$ virgil register <email>
```
- Login you Virgil Account:
```shell
$ virgil login
```
- Create Virgil Application. Find examples [here](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/manage-applications)
```shell
$ virgil app create <App Name>
```
As a result, you'll get `App_ID`.
- Generate App Token specifying `App_ID` and App name. Find examples [here](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/manage-apptokens)
```shell
$ virgil app token create --app-id <App ID> --name <Name>
```
As a result, you'll get `Token`.

> Store the App Token in a secure place and use it to initialize the Demo.

### Run Demo
Now, you can run the Demo.

- Firs of all, check whether the Docker is launched.
- Navigate to your CLI terminal and run the Demo script (Unix-like OS: `run-demo.sh` and Windows:`run-simulator.bat`) from the scripts folder of the downloaded Demo package.
```shell
# for MacOS
$ ./run-demo.sh
```
- Specify your `App_Token` in the appeared window to run the Demo

If you did everything correctly, you would see the following Demo window:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/virgil_demo_iotkit_nix.png" align="left" hspace="0" vspace="6"> &nbsp;



on the step 4, and then specify your App Token obtained in the previous step.


## Explore Demo



## Reference
- [Virgil IoTKit](https://github.com/VirgilSecurity/virgil-iotkit)
- [Virgil Dev Docs](https://developer.virgilsecurity.com/)

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
