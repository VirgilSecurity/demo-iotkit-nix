# Virgil IoTKit Demo
The Demo is based on [Virgil IoTKit](https://github.com/VirgilSecurity/virgil-iotkit) and its dev tools to demonstrate secure IoT devices development in action. The IoTKit Demo is conditionally divided into 3 actors (Vendor, Factory, and End-user) to easily understand the whole development process.

## Content
- [Functions](#functions)
- [Download Demo](#download-demo)
- [Configure and Run Demo](#configure-and-run-demo)
  - [Prerequisites](#prerequisites)
  - [Generate App Token](#generate-app-token)
  - [Run Demo](#run-demo)
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

Also, while working with Demo you can:
- View logs of all operations using integrated logs viewer
- View devices information using integrated device manager (Virgil SnapD)

## Download Demo
The IoTKit Demo is a part of the [IoTKit package](https://github.com/VirgilSecurity/virgil-iotkit/tree/release/v0.1.0-alpha/scripts), so you will run the Demo from the IoTKit repository.

Clone the IoTKit package via the following link:
```shell
$ git clone https://github.com/VirgilSecurity/virgil-iotkit.git
```

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
- Create Virgil Application. Find examples [here](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/manage-applications).
```shell
$ virgil app create <App Name>
```
As a result, you'll get `App_ID`.
- Generate `App Key` specifying `App_ID` and `App Name`. Find examples [here](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/manage-app-keys)
```shell
$ virgil app key create --app_id <App ID> <App Key Name>
```
As a result, you'll get `App Key` and `App Key ID`.

- Generate App Token specifying `App_ID` and `App Name`. Find examples [here](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/manage-apptokens).
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

&nbsp;

### Run Logs Viewer
While working with Demo you can:
- View logs of all operations using integrated logs viewer that can be run in browser under http://localhost:8080/:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/logs-viewer.png" align="left" hspace="0" vspace="6">
&nbsp;

- View devices information using integrated device manager (Virgil SnapD) that can be run in browser under http://localhost:8081/:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/device_manager.png" align="left" hspace="0" vspace="6">
&nbsp;

## Explore Demo
The IoTKit Demo is conditionally divided into 3 actors (Vendor, Factory and End-user) and shows secure lifecycle of IoT devices. The IoTKit Demo allows you to:
- **Step #1. Generate trusted provisioning package**.

To start working with emulated IoT infrastructure you have to generate a trusted provisioning package that includes such as private keys (e.g. for factory, firmware) and a distributed trust list that contains public keys and signatures of trusted services providers (e.g. factory, cloud).

<img width="320" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/generate_files.png" align="left" hspace="0" vspace="6">  

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

Demo uses [Virgil Trust Provisioner](https://github.com/VirgilSecurity/virgil-iotkit/tree/release/v0.1.0-alpha/tools/virgil-trust-provisioner) utility under the hood for this purpose.

- **Step #2. Emulate IoT devices**.

Now, you have to emulate IoT devices. There are two types of devices:
  - IoT Gateway - an internet-capable smart device that communicates with other IoT devices and Clouds;
  - and IoT Device - end-device, like smart bulb, that can be controlled remotely through the IoT Gateway.

Generate both of them. The information about generated devices can be found in the Demo window:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/emulated_device.png" align="left" hspace="0" vspace="6">

&nbsp;

- **Step #3. Securely perform IoT device provisioning**.

To make each IoT device identifiable, verifiable and trusted by each party of IoT solution you have to make device provisioning.

Demo uses the [Virgil Device Initializer](https://github.com/VirgilSecurity/virgil-iotkit/tree/release/v0.1.0-alpha/tools/virgil-device-initializer) for IoT devices provisioning to securely integrate trust list and crypto library on IoT devices, then generate key pairs and create digital cards, and sign digital cards with the Factory Key.

The information about initialized (provisioned) devices can be found in the Demo window:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/initialized_devices.png" align="left" hspace="0" vspace="6"> &nbsp;

or in browser under http://localhost:8080/ in the Device Initializer section.

- **Step #4. Register IoT devices on the security platform**.

At this step the Virgil Device Registrar is used to register digital cards of IoT devices at Virgil Cloud for further device authentication and management.

After the IoT devices were registered at Virgil they are conditionally shipped to end-user for further operations:

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/shipped_devices.png" align="left" hspace="0" vspace="6">
&nbsp;

The information about registered IoT devices can be also found or in browser under http://localhost:8080/ in the Device Registrar section.

- **Sign and publish new Firmware and TrustList**. Also, you can emulate process of creating and publishing new Firmware or TrustList to Virgil Cloud. Demo uses Virgil Firmware Signer to sign a firmware before its distributing.
- **Manage IoT devices**. Demo allows to manage IoT devices and get information about their state. Demo uses Virgil services to notify IoT devices about new updates and then securely verify incoming firmware or trust lists before updating them.

## Reference
- [Virgil IoTKit](https://github.com/VirgilSecurity/virgil-iotkit)
- [Virgil Dev Docs](https://developer.virgilsecurity.com/)

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
