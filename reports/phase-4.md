# CS 1653: Applied Cryptography and Network Security -- Phase 4 #
## Overview ##

This phase of the project is the second stage of hardening our Galactic File-Hosting Service (GFHS). We are still operating under the general assumption that the group server is entirely trustworthy--however, the group server is not assumed to share secrets with the file servers in the system. We accounted for this in our previous phase, having assumed no previous sharing between servers and establishing secure lines of communication before proceeding.  

We use a variety of techniques and protocols to address the given threat models and keep our system secure. These are specified herewith, along with reasoning and justification for each. We also implemented a trusted public key infrastructure, called Trent. This server provides public keys for registered file servers. Trent's public key serves as a trust anchor.

*   Protocols:
Leslie Lamport OTP style

*   Tools and Algorithms:
-   AES (128-bit) -- We chose AES because it is the *de facto* standard for quick and secure symmetric key encryption according to NIST. The 128-bit version is projected to be secure for a number of years, and provides for the time being essentially the same security as larger key sizes.<sup id="a3">[3](#f3)</sup>  We use AES with Galois/Counter Mode (GCM), which conveniently allows to both encrypt *and* authenticate in the same go. This allows us to detect errors or tampering with the ciphertext in some more secure way than just getting garbage when we decrypt. We can also add data to the AAD field to protect from additional active attackers. We chose to forgo any message padding for the time being to eliminate confusion and keep things simple.
-   SHA-256 -- We chose SHA-256 because it is recommended for a variety of applications by NIST <sup id="a5">[5](#f5)</sup>. This is used for: validating user passwords on the GroupServer, hashing user Tokens in order to verify their origin, and for establishing group symmetric keys for encrypting files. When using it to hash passwords we include a salt to inhibit brute-force attacks. Details are in sections T1 and T2, respectively.
-   RSA-2048 -- We use RSA signatures to guarantee the validity of a token and to sign public keys issued by Trent. RSA-2048 is approved by NIST for generation/verification of digital signatures and keys,<sup id="a4">[4](#f4)</sup> which is exactly what we are using it for.  
*   Bonus:  

## Threat Models ##
### T5: Message Reorder, Replay, Modification ###
This threat has to do with the constant potential threat of a man in the middle (MiTM) attack, which could come in the form of message reorder, replay, or modification. A MiTM attack could potentially allow the attacker to assume the identity of the user or the server, and could use this position to access information or cause either party to leak information.

We took steps in the previous phase of the project to defend against these threats. Firstly, we authenticate each requested server to the user by signing essential messages in the D-H exchange using the server's private key. Only the server has access to that key, so if a malicious party poses as that server then its messages won't be verified. Even if an attacker intercepts and resends an old response from the server, they won't have access to either party's private D-H number, and thus will not be able to figure out the symmetric key.  

Further, we encrypted all communications (not including public keys) with 128-bit AES keys, operating in Galois-Counter-Mode (GCM). GCM includes built-in authentication tags that are tamper evident. Should any part of the message be modified, the ciphertext will no longer match the tag, and in this way we know that the message has been modified. We will also expand the tag's AAD (Additional Authenticated Data) field to include a timestamp and sequence number to defend from replay and reorder attacks. This field is also validated using the GCM tag, even though it is not encrypted. Looking at the timestamp, we can distinguish between a fresh message and an old one that is being resent from a MiTM and therefore prevent this message from being accepted if it is not legitimate. As an added measure of security, the sequence number can be used to distinguish the order of each message (Message 1 in the process labeled with a "1", Message 2 with a "2", etc.) so that any message sent by a MiTM not in the correct sequence will be disregarded. This also helps to ensure that, for example, Message 1 isn't replayed by the MiTM. Although the timestamp will be in place, differences in the clock of the client and server could leave a window large enough for a malicious MiTM to act. The server will know it has already received Message 1, so it will know not to accept another Message 1 in the protocol.


### T6: File Leakage ###
This threat has to do with a file server unintentionally (or intentionally) leaking files to a third party, who may be unauthorized to view the file contents. This is obviously quite problematic and not desirable, because we don't want unauthorized person(s) being able to see file contents of a group they do not belong to.

When a user joins a group, they should be able to access existing group files which were created before the user joined. We assumed that the user to be added should have this access or else a new group would be created. When a user is removed from the group they should not be able to see any changes from the point that they were removed. We are under the assumption that the user could have downloaded and decrypted all files they had access to right before they were removed. So this means it isn't harmful if they are able to decrypt leaked files that haven't changed, however they should not be able to decrypt new or altered files.  

To address this threat, we encrypt every file on the file server using symmetric 128-bit AES keys. Keys will exist on a group-basis, meaning every group has a single key to decrypt its files. This key will be shared among members of the group only, so that only an authorized member of the group can access a file. The file server will not store said key or know about each group's key, since they are largely untrusted. If a file server were to store these keys, all files could be compromised if the file server leaked these keys. Should a member be removed from the group, the symmetric key will be rotated to a fresh one and be available to all current members. This is to ensure that a new member may access files once he/she joins and that no previous member can still access group files.  

Managing and distributing these group keys is a task that can easily be carried out by the GroupServer, which is a trusted entity. Since they are strictly group-dependent and *not* fileserver-dependent, the GroupServer is sure to have all necessary information to deal with them:  
-   The GroupServer authenticates all users who connect to it as part of the SRP handshake that happens at the beginning of a user's session, so there is no risk of the GroupServer sending a group-key to someone not in the group.  
-   Even if an attacker intercepts the message from the GroupServer where this key is being issued, it will be encrypted (just like everything else) using the 128-bit AES session key that was established during the SRP protocol, so there is no chance the attacker will be able to figure out the group-key.  
-   When groups change, that change is recorded and dealt with by the GroupServer already, so it will be straightforward to have the GroupServer update the group-key while only issuing it to current or new members.  

We chose to base our key update mechanism off of the Leslie Lamport OTP scheme. This will allow us to easily update keys without having to batch re-encrypt all files. When a group is created, the group server will generate a 128-bit AES key and hash that key 1000 times. The server will store the original key, the current hash number, and the current key. When a user is removed from a group, the group server will decrement the hash number and update the current key. All new or updated material will be encrypted with this new key. If a user wishes to decrypt a file they simply take the difference between the hash number associated with the file and the current hash number. They then hash the current key that number of times. This ensures forward secrecy while allowing for backward compatibility.  

Creating a Group

![Creating a Group](./img/T6_Create_Group.png)

Removing a User

![Removing a User](./img/T6_Remove_User.png)  


### T7: Token Theft ###
This threat deals with file servers stealing tokens and attempting to pass them on to another user. This other user may be able to use this token to gain access to a group and its files on another file server. In a given user session, the user can only connect to a single file server, where upon startup the server's address is specified (or defaults to localhost if none is entered). In order to connect to a different file server, the user would have to start a new session and specify the new server he/she wishes to connect to--it is not possible to change this during a session.

Using this setup, our solution to this threat was to make a token valid only for the current session and file server. Binding the token itself to the current session and selected file server will make it non-transferable to another session or server. We will do this by adding fields to the token itself--the address (IP address:port) of the file server being used and a timestamp of when the token is created. The GroupServer will use the specified file server address from the user and the current time to create the token (along with all other required information to create a token) and then sign it.  
This way, when connecting to the file server:
-   We can match the address on the token to the file server's address (IP Address and Port #) to ensure that it is not being used on a different server.
-   We can make sure the timestamp is within a safe window of the current time to ensure its freshness, and that it is not being reused by someone else at a later time.

This process does not interfere with measures put forth to counter threat model T2. Users still cannot modify tokens to enhance their privileges, we are simply expanding information stored in the token. The tokens are still being signed by the GroupServer after its creation, so any modifications to a token will invalidate it. The GroupServer's public key will still available to any third party so that they can verify any token for its validity.

## Summary ##
Interplay between mechanisms
Design process
T1-T4 still valid
