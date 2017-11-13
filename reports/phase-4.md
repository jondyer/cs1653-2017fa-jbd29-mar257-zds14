# CS 1653: Applied Cryptography and Network Security -- Phase 4 #
## Overview ##

This phase of the project is the second stage of hardening our Galactic File-Hosting Service (GFHS). We are still operating under the general assumption that the group server is entirely trustworthy- however, the group server is not assumed to share secrets with the file servers in the system. We accounted for this in our previous phase, having assumed no previous sharing between servers and establishing secure lines of communication before proceeding.  

We use a variety of techniques and protocols to address the given threat models and keep our system secure. These are specified herewith, along with reasoning and justification for each. We also implemented a trusted public key infrastructure, called Trent. This server provides public keys for registered file servers. Trent's public key serves as a trust anchor.

*   Protocols:

*   Tools and Algorithms:

*   Bonus:  

## Threat Models ##
### T5: Message Reorder, Replay, Modification ###
### T6: File Leakage ###
This threat has to do with a file server unintentionally leaking files to a third party, who may be unauthorized to view the file contents. This is obviously quite problematic and not desirable, because we don't want unauthorized person(s) being able to see file contents of a group they do not belong to.

To address this threat, we chose to encrypt every file on the file server using symmetric 128-bit AES keys. Keys will exist on a group-basis, meaning every group has a single key to decrypt its files. This key will be shared among members of the group only, so that only an authorized member of the group can access a file. The file server will not store said key or know about each group's key, since they are largely untrusted. If a file server were to store these keys, all files could be compromised if the file server leaked these keys. Should a group change - i.e. a member is added or removed, the symmetric key will be rotated to a fresh one and be available to all current members. This is to ensure that a new member may access files once he/she joins and that no previous member can still access group files.
### T7: Token Theft ###

## Summary ##
