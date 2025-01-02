# A62 NotIST Project Read Me

## Team

| Number | Name              | User                             | E-mail                              |
| -------|-------------------|----------------------------------| ------------------------------------|
| 99970  | João Maçãs     | <https://github.com/joaodrmacas>   | <mailto:joaomacas02@tecnico.ulisboa.pt>   |
| 103369  | Miguel Parece      | <https://github.com/BobUser>     | <mailto:miguelparece.ulisboa.pt>     |
| 103708  | Duarte Sao Jose  | <https://github.com/DuarteSJ> | <duarte.s.jose@tecnico.ulisboa.pt> |

![João](img/joaomacas.png) ![Miguel](img/miguelparece.jpeg) ![Duarte](img/duartesaojose.jpeg)


## Contents

This repository contains documentation and source code for the *Network and Computer Security (SIRS)* project.

The [REPORT](REPORT.md) document provides a detailed overview of the key technical decisions and various components of the implemented project.
It offers insights into the rationale behind these choices, the project's architecture, and the impact of these decisions on the overall functionality and performance of the system.

This document presents installation and demonstration instructions.

## Installation

To see the project in action, it is necessary to setup a virtual environment, with 2 networks and 4 machines.  

The following diagram shows the networks and machines:

![Diagrama](img/diagrama.png)

*(include a text-based or an image-based diagram)*

### Prerequisites

[Install Vagrant](https://developer.hashicorp.com/vagrant/downloads) on your system.

### Machine configurations

1. Start the virtual machines:
```sh
$ vagrant up
```

2. Check available machines:
```sh
$ vagrant status
```

3. Connect to the desired machine:
```sh
$ vagrant ssh <machine-name>
```

For each machine, there is an initialization script inside of the `scripts` folder with the machine name (prefix `setup_`, suffix `.sh`) that installs necessary packages and configures the clean machine.
**These scripts are run automatically by executing vagrant up**

The Vagrantfile in the repository manages the VM configurations and provisioning.

#### DB Server Machine

This machine runs a [MongoDB](https://www.mongodb.com/) server that provides data storage for the application.

To verify:
```sh
$ mongod --version
$ systemctl status mongod
```

To test:
```sh
$ mongosh --tls \
    --host 192.168.56.17 \
    --tlsCertificateKeyFile /home/vagrant/certs/mongodb/mongodb-server.pem \
    --tlsCAFile /home/vagrant/certs/ca.crt
> use secure_document_db
> db.runCommand({ ping: 1 })
```

The expected results are a successful connection to MongoDB with status code 1.

If you receive the following message "Failed to connect to MongoDB", then:
```sh
$ sudo systemctl start mongod
$ sudo systemctl enable mongod
```


TODO acho que deviamos falar do que a app faz em concreto quando falamos do client dizer o que ele faz e qnd falamos do server dizer o que ele faz mas not sure

#### App Server Machine

This machine runs a server with a Python socket. It is responsible for handling client requests in a secure manner and ensures network communications with both users and the database.

To verify:
```sh
$ python3 -V
```

To test:
```sh
$ cd app
$ python3 server.py
```

The expected results are the server starting and listening for incoming connections on the 5000 port.

If you receive the message "Address already in use", then:
```sh
$ sudo lsof -i :5000
$ sudo kill <process_id>
```

#### Client Machine

This machine runs a Text User Interface (TUI) application built in Python that allows users to interact with our application.

To verify:
```sh
$ python3 -V  # Verify Python installation
```

To test:
```sh
$ notist-client #start the TUI
```

The expected results are a TUI appearing in your terminal where it will tell you that no user was found and ask if you want to create a new account.

If you get a message that looks like `ModuleNotFoundError`, then ensure you have all required Python packages installed by reinstalling all the requirements:
```sh
$ cd /home/vagrant/client/notist_client
$ pip install -r requirements.txt
```
TODO:
## Demonstration

Now that all the networks and machines are up and running, ...

*(give a tour of the best features of the application; add screenshots when relevant)*

```sh
$ demo command
```

*(replace with actual commands)*

*(IMPORTANT: show evidence of the security mechanisms in action; show message payloads, print relevant messages, perform simulated attacks to show the defenses in action, etc.)*

This concludes the demonstration.

## Additional Information

### Links to Used Tools and Libraries
#### Python Packages

##### Core Python Package/Version Management
- **pip (≥23.0.0)**
  - Documentation: [**pip docs**](https://pip.pypa.io/en/stable/)
  - Repository: [**pypa/pip**](https://github.com/pypa/pip)
  - Package Index: [**pip on PyPI**](https://pypi.org/project/pip/)

- **setuptools (≥65.5.1)**

  - Documentation: [**setuptools docs**](https://setuptools.pypa.io/en/latest/)
  - Repository: [**pypa/setuptools**](https://github.com/pypa/setuptools)
  - Package Index: [**setuptools on PyPI**](https://pypi.org/project/setuptools/)

- **wheel (≥0.40.0)**  TODO acho que esta ta nos requirements mas nao é required. tentar tira-la de la e ver se o client funciona

  - Documentation: [**wheel docs**](https://wheel.readthedocs.io/en/stable/)
  - Repository: [**pypa/wheel**](https://github.com/pypa/wheel)
  - Package Index: [**wheel on PyPI**](https://pypi.org/project/wheel/)

##### Security and Cryptography
- **cryptography (==3.4.7)**
  - Documentation: [**cryptography docs**](https://cryptography.io/en/3.4.7/)
  - Repository: [**pyca/cryptography**](https://github.com/pyca/cryptography)
  - Package Index: [**cryptography on PyPI**](https://pypi.org/project/cryptography/3.4.7/)

- **pycryptodome (==3.21.0)** TODO de certeza que o Crypto que usamos no secure-documents vem daqui? Acho que sim, mas tamos a usar uma old version no secure-document. temos de ver isto
  - Documentation: [**pycryptodome docs**](https://pycryptodome.readthedocs.io/)
  - Repository: [**Legrandin/pycryptodome**](https://github.com/Legrandin/pycryptodome)
  - Package Index: [**pycryptodome on PyPI**](https://pypi.org/project/pycryptodome/3.21.0/)

##### Data Validation and Metadata
- **pydantic (==2.10.4)**
  - Documentation: [**pydantic docs**](https://docs.pydantic.dev/2.10/)
  - Repository: [**pydantic/pydantic**](https://github.com/pydantic/pydantic)
  - Package Index: [**pydantic on PyPI**](https://pypi.org/project/pydantic/2.10.4/)

- **importlib_metadata (≥4.13.0)**  TODO acho que esta ta nos requirements mas nao é required. tentar tira-la de la e ver se o client funciona
  - Documentation: [**importlib_metadata docs**](https://importlib-metadata.readthedocs.io/)
  - Repository: [**python/importlib_metadata**](https://github.com/python/importlib_metadata)
  - Package Index: [**importlib_metadata on PyPI**](https://pypi.org/project/importlib-metadata/)

#### Development and Virtual Environments
- **vagrant**
  - Documentation: [**vagrant docs**](https://developer.hashicorp.com/vagrant/docs)
  - Repository: [**hashicorp/vagrant**](https://github.com/hashicorp/vagrant)
  - Download: [**vagrant downloads**](https://developer.hashicorp.com/vagrant/downloads)

### License
TODO ya n sei acho que é só deixar essa
This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) for details.

*(switch to another license, or no license, as you see fit)*

----
END OF README
