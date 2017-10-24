# CS 1653: Applied Cryptography and Network Security -- Phase 3 #
## Overview ##

This phase of the project is the first stage of hardening our Galactic File-Hosting Service (GFHS). We are still operating under the general assumption that the group server is entirely trustworthy, and that once a user has identified a file server appropriately, that server is also trustworthy and obeys all its rules. However, we will add some measures to enhance security on tokens, the user and file server ends, and to protect against third party monitoring on all communications.

We will use a variety of techniques and protocols to address the given threat models and keep our system secure. Some of these include the Secure Remote Password (SRP) protocol and Diffie-Hellman (D-H) key exchange. To implement these protocols we will use various tools including RSA-2048, SHA-256, and AES.



## Threat Models ##
### T1: Unauthorized Token Issuance ###
This threat has to do with illegitimate or malicious parties requesting (and receiving) another user's token, thereby gaining access to that user's files and groups. This is problematic if that information is intended to be secure in any fashion (i.e. confidential or protected from unauthorized modification). Currently our system only requires a username in order to access that user's account--with all associated privileges--requiring no further form of authentication. An adversary can thus access any account she knows the name of, which is obviously undesirable.  


To address this threat, we chose to implement a Secure Remote Password (SRP) protocol, relying on a shared secret (i.e. password) between the user and the groupserver. This secret is set at user creation, and the groupserver stores <User, Value> pairs, where the Value is a SHA-256 hash (+ salt!) of the user's password. We chose SHA-256 because it is recommended for a variety of applications by NIST, along with salt to inhibit brute-force attacks. We chose SRP because it provides mutual authentication of the user and groupserver and simultaneously allows them to agree on a session key, all securely and over an open channel. At this point that key can be used for the remainder of the session. This protocol is represented diagrammatically below:  

![Image of SRP](./img/T1.png)  

We can see that this process ensures that at the end of the exchange:
-   Bob and the groupserver have authenticated each other.
-   Bob and the groupserver have correctly agreed on the same session key.
-   This session key is known only to Bob and the groupserver.

These are true because the SRP exchange relies on prior knowledge of the secret W, which is never transmitted (and thus not able to be intercepted), and which is used in the (large and unfactorable) calculation of the session key K<sub>GB</sub>. This means that the only parties who will be able to correctly calculate K<sub>GB</sub> are Bob and the groupserver. Thus, at the point of Bob's response to challenge C<sub>1</sub>, he is authenticated to the groupserver, and vice versa with C<sub>2</sub> authenticating the groupserver to Bob.



### T2: Token Modification/Forgery ###
This threat has to do with users--who may or may not have malicious intent, but may want to further their access privileges. They theoretically could do so through modification of a token, which specifies the user's access to groups. If a user could edit a token, he/she could give oneself access to every group in the system- enabling him/her to manage files in the group. Essentially, that user could get into a group and add or delete files without permission (someone adding them to the group). Currently, our system works such that a user obtains a token from the groupserver that authorizes him/her to only operate on groups they want to (selecting from the ones they have access to) for that session, following the principle of least privilege. Although it may be challenging, once a user has that groupsever token, there aren't any measures in place to stop them from editing its contents.

To address this threat, we chose to use RSA signatures to guarantee the validity a token. The groupserver is the only place that makes/grants tokens, so each token that is issued by it will be signed using the groupserver's private key. With that in place, any attempted modifications to a groupserver-signed token will void it, rendering it useless. Additionally, a user cannot forge a new token with the groupserver's signature, because only the groupserver knows its own private key. Only tokens signed by the groupserver will be accepted in the system, and any party can verify token validity with the groupserver's public key- which is publicly available.

![Image of Token Signature](./img/T2.png)  

To address this threat, we chose to use RSA signatures to guarantee the validity a token.

### T3: Unauthorized File Servers ###

### T4: Information Leakage via Passive Monitoring ###
This threat has to do with malicious users attempting to listen in on our communications. If a third party is able to listen in on the communication between two parties, they may be able to perform malicious acts. The third party may be able to know the content of the communication or impersonate the one of the two parties. Our goal is to make sure that no usable information is gleaned from listening in on communications between two parties. Any communication between a user and a server must be kept confidential to ensure the security of our system.

To establish a secure channel that prevents eavesdropping, we create a unique session key that will encrypt all communications between the parties for that session. A new session key is generated for each session, so that even if an old key is compromised, all other communication will be secure. We accomplish this using 256-bit AES symmetric keys: K<sub>GB</sub> and K<sub>BF</sub>. The key K<sub>GB</sub>, explained in T1, is generated using SRP. It is used to encrypt all communication between the GroupServer and the user. The key K<sub>BF</sub>, explained in T3, is generated using Diffie-Hellman key exchange. A unique key is generated when necessary for each file server and user pair required for the session. Each key is used to encrypt all communication between the associated FileServer and the user.

For this to work we have to make a couple of assumptions. We assume that the user has chosen a strong password that has not been compromised. We assume that each user and FileServer has generated a public/private key pair upon creation and that the private key has remained private. We also assume complete trust in Trent. Trent must remain uncompromised and benevolent. Trent will not distribute any private keys to anyone but their intended owner and will not attempt to impersonate the user.

Our mechanism sufficiently addresses this particular threat because we encrypt as much of our communication as possible. If a third party does attempt to listen in, they will be unable to determine what has been said. The data will appear to be random to them and will be useless. Even if one particular session key is compromised, the rest of the sessions will be unaffected. If the user and or server's private key is compromised none of the session keys will be compromised because the of the use of random numbers in the Diffie-Hellman key exchange protocol. Even if the user's password is compromised, no past sessions will be leaked for the same reason. We believe that this will provide sufficient security to prevent a passive listener.
