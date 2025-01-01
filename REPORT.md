# A62 Notist Project Report

# 1. Introduction

NotIST is a secure note-taking application designed with a "local-first" architecture, prioritizing user privacy and data security while enabling collaborative features. The application allows users to create, manage, and share notes with other users, with all data being encrypted both locally and during synchronization with the backup server without ever exposing sensitive information.

## Business Scenario
The project addresses the growing need for secure, private note-taking solutions in an increasingly interconnected digital world. Users require a platform that maintains the convenience of modern note-taking apps while ensuring their personal data remains protected and private. NotIST achieves this by implementing strong encryption mechanisms that ensure notes are only accessible to their rightful owners and authorized collaborators.

## Main Components

### 1. Secure Documents
- Notes are stored as JSON documents containing metadata and content
- Sens
- Document structure includes ownership information, access controls, and version tracking
- Support for different access levels (owners, editors, viewers)

### 2. Infrastructure
The system consists of three main components:
- Client Application: A Python-based TUI (Terminal User Interface) for user interactions
- Application Server: A Python socket server handling communication and business logic
- Database Server: A MongoDB instance storing encrypted notes and user data

### 3. Security Challenge
The primary security challenge involves implementing secure note sharing while maintaining:
- End-to-end encryption for personal and shared notes
- Access control mechanisms for different user roles
- Version control with integrity verification
- Authentication and authorization systems

<!-- ## System Architecture

<antArtifact identifier="system-diagram" type="application/vnd.ant.mermaid" title="NotIST System Architecture">
classDiagram
    class Client {
        +createNote()
        +editNote()
        +shareNote()
        +syncNotes()
        -encryptNote()
        -decryptNote()
    }
    
    class AppServer {
        +handleConnections()
        +authenticateUser()
        +manageSharing()
        -validateRequest()
    }
    
    class DBServer {
        +storeNote()
        +retrieveNote()
        +updateNote()
        -backupData()
    }
    
    class Note {
        +id: int
        +title: string
        +content: string
        +owner: User
        +editors: User[]
        +viewers: User[]
        +version: int
    }
    
    <!-- Client --> AppServer: Encrypted Communication
    AppServer --> DBServer: Secure Storage
    Client ..> Note: Creates/Modifies
    AppServer ..> Note: Manages
    DBServer ..> Note: Stores --> -->

(_Include a structural diagram, in UML or other standard notation._)

## 2. Project Development

### 2.1. Secure Document Format

#### 2.1.1. Design

(_Outline the design of your custom cryptographic library and the rationale behind your design choices, focusing on how it addresses the specific needs of your chosen business scenario._)

(_Include a complete example of your data format, with the designed protections._)

#### 2.1.2. Implementation

(_Detail the implementation process, including the programming language and cryptographic libraries used._)

(_Include challenges faced and how they were overcome._)

### 2.2. Infrastructure

#### 2.2.1. Network and Machine Setup

For machine provisioning we decided to use **vagrant** as it help us easily deploy all our virtual machines at once. We can also set them to automaticaly run their setups scripts essentially enabling us to have all our vms plus our stack deployed with a single **"vagrant up"** command.

In the Vagrantfile we can configure network interfaces and shared host folders with a single line.

* ##### AppServer :
    * Running **Ubuntu 20.04 LTS**
    * Network Interfaces:
        * Public: **192.168.1.228 (accessible from internet)**
        * Private: **192.168.56.14 (for database communication)**
        * FireWall Rull

#### 2.2.2. Server Communication Security

(_Discuss how server communications were secured, including the secure channel solutions implemented and any challenges encountered._)

(_Explain what keys exist at the start and how are they distributed?_)

### 2.3. Security Challenge

#### 2.3.1. Challenge Overview

(_Describe the new requirements introduced in the security challenge and how they impacted your original design._)

#### 2.3.2. Attacker Model

(_Define who is fully trusted, partially trusted, or untrusted._)

(_Define how powerful the attacker is, with capabilities and limitations, i.e., what can he do and what he cannot do_)

#### 2.3.3. Solution Design and Implementation

(_Explain how your team redesigned and extended the solution to meet the security challenge, including key distribution and other security measures._)

(_Identify communication entities and the messages they exchange with a UML sequence or collaboration diagram._)  

## 3. Conclusion

(_State the main achievements of your work._)

(_Describe which requirements were satisfied, partially satisfied, or not satisfied; with a brief justification for each one._)

(_Identify possible enhancements in the future._)

(_Offer a concluding statement, emphasizing the value of the project experience._)

## 4. Bibliography

(_Present bibliographic references, with clickable links. Always include at least the authors, title, "where published", and year._)

----
END OF REPORT
