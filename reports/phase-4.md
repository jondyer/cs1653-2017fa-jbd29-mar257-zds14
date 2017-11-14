# CS 1653: Applied Cryptography and Network Security -- Phase 4 #
## Overview ##

This phase of the project is the second stage of hardening our Galactic File-Hosting Service (GFHS). We are still operating under the general assumption that the group server is entirely trustworthy--however, the group server is not assumed to share secrets with the file servers in the system. We accounted for this in our previous phase, having assumed no previous sharing between servers and establishing secure lines of communication before proceeding.  

We use a variety of techniques and protocols to address the given threat models and keep our system secure. These are specified herewith, along with reasoning and justification for each. We also implemented a trusted public key infrastructure, called Trent. This server provides public keys for registered file servers. Trent's public key serves as a trust anchor.

*   Protocols:


*   Tools and Algorithms:
  <!-- RSA-2048
  AES-128
  GCM & GMAC -->
*   Bonus:  

## Threat Models ##
### T5: Message Reorder, Replay, Modification ###
This threat has to do with the constant potential threat of a man in the middle (MiTM) attack, which could come in the form of message reorder, replay, or modification. A MiTM attack could potentially allow the attacker to assume the identity of the user or the server, and could use this position to access information or cause either party to leak information.

We took steps in the previous phase of the project to defend against these threats. Firstly, we authenticate each requested server to the user by signing essential messages in the D-H exchange using the server's private key. Only the server has access to that key, so if a malicious party poses as that server then its messages won't be verified. Even if an attacker intercepts and resends an old response from the server, they won't have access to either party's private D-H number, and thus will not be able to figure out the symmetric key.  

Further, we encrypted all communications (not including public keys) with 128-bit AES keys, operating in Galois-Counter-Mode (GCM). GCM includes built-in authentication tags that are tamper evident. Should any part of the message be modified, the ciphertext will no longer match the tag, and in this way we know that the message has been modified. We will also expand the tag's AAD (Additional Authenticated Data) field to include a timestamp to defend from replay attacks. This field is also validated using the GCM tag, even though it is not encrypted. Looking at the timestamp, we can distinguish between a fresh message and an old one that is being resent from a MiTM and therefore prevent this message from being accepted if it is not legitimate.

^^^ Missing: Reorder attack

### T6: File Leakage ###
This threat has to do with a file server unintentionally (or intentionally) leaking files to a third party, who may be unauthorized to view the file contents. This is obviously quite problematic and not desirable, because we don't want unauthorized person(s) being able to see file contents of a group they do not belong to.

To address this threat, we chose to encrypt every file on the file server using symmetric 128-bit AES keys. Keys will exist on a group-basis, meaning every group has a single key to decrypt its files. This key will be shared among members of the group only, so that only an authorized member of the group can access a file. The file server will not store said key or know about each group's key, since they are largely untrusted. If a file server were to store these keys, all files could be compromised if the file server leaked these keys. Should a member be removed from the group, the symmetric key will be rotated to a fresh one and be available to all current members. This is to ensure that a new member may access files once he/she joins and that no previous member can still access group files.  

Managing and distributing these group keys is a task that can easily be carried out by the GroupServer, which is a trusted entity. Since they are strictly group-dependent and *not* fileserver-dependent, the GroupServer is sure to have all necessary information to deal with them:  
-   The GroupServer authenticates all users who connect to it as part of the SRP handshake that happens at the beginning of a user's session, so there is no risk of the GroupServer sending a group-key to someone not in the group.  
-   Even if an attacker intercepts the message from the GroupServer where this key is being issued, it will be encrypted (just like everything else) using the 128-bit AES session key that was established during the SRP protocol, so there is no chance the attacker will be able to figure out the group-key.  
-   When groups change, that change is recorded and dealt with by the GroupServer already, so it will be straightforward to have the GroupServer simply stop issuing group-keys to removed members, and start issuing them to new members.  

^^^ Needs revised: One of a few things needs to happen  
    1.  The GroupServer needs to find a way to **change** the group-key any time group membership changes, which is not feasible because then all previously encrypted files need to be found and reencrypted with the new key.   
    Do we need to care about removed users being able to decrypt files they already had access to?  
    2.  We need a means of keeping the user *and* the fileserver from ever actually having free access to the group-key.  
    Encrypt the key with user-to-group server session key and store it in the token.  
    Send the user the key encrypted along side of their token.  
    3.  Leslie Lamport OTP style hashing the original.  
    C changes only when a user is removed.  
    Store C along with each file.  
    User never knows original, only gets new keys from group server.  

### T7: Token Theft ###
<!-- - A token currently contains information about its subject
- When verifying a token, need to bind/auth subject of token to user's identity
- "ensuring that any stolen tokens are usable only on the server at which the theft took place" ???? -->

## Summary ##
