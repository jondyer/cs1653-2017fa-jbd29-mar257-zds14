# CS 1653: Applied Cryptography and Network Security -- Phase 4 #
## Overview ##
The final phase of the project involves self-directed hardening against self-directed threats to our Galactic File-Hosting Service (GFHS). We will operate under the same trust model as in phase 4 (described below), but will protect against other threats present within the framework of that trust model. Specifically, our trust model supposes the following from phase 4:  

-   **Group Server**: The group server is entirely trustworthy. In this phase of the project, this means that the group server will only issue tokens to properly authenticated clients and will properly enforce the constraints on group creation, deletion, and management specified in previous phases of the project. The group server is not assumed to share secrets with the file servers in the system.  

-   **File Servers**: In this phase of the project, file servers will be assumed to be largely untrusted. In particular, file servers might leak files to unauthorized users or attempt to steal user tokens.  

-   **Clients**: We will assume that clients are not trustworthy. Specifically, clients may attempt to obtain tokens that belong to other users and/or modify the tokens issued to them by the group server to acquire additional permissions. Additionally, clients may attempt to log in as another user or discover another user's password.  

-   **Other Principals**: We assume that *all* communications in the system might be intercepted by an *active attacker* that can insert, reorder, replay, or modify messages. Outside attackers may also seek to establish a connection with any server they wish.  


*   Protocols:  

*   Tools and Algorithms:  


## Threat Models ##
### T8: Weak Passwords ###
The lack of restriction for password creation makes it easy for users to be created with basic or simple passwords, giving a low level of protection should an attacker discover a username and attempt to guess the corresponding password. As our system is currently no rules are being enforced for password creation, even for the administrator account. Thus, common and short passwords such as `password` or `1234` are allowed, leaving those accounts vulnerable to a brute force attack on their passwords.

Our solution to this threat is to require a minimum length on all passwords, in accordance with the latest NIST guidelines<sup id="a1">[1](#f1)</sup>


### T9: Online Password Attack ###
This threat involves the potential for someone to make a brute-force attack on a user's password by attempting to login repeatedly, perhaps with a dictionary of words, as a given user. This is currently possible since our interface simply returns "wrong password" on a mis-entry and allows the user to keep trying.

We address this vulnerability by allowing a user a maximum number of login attempts before suspending the account temporarily. This will prevent a dictionary-type attack on the ... especially combined with the password rule enforcement above.

### T10: Login DOS Attack ###
This threat comes by way of any malicious party who decides to interrupt the availability of the file-hosting service. Specifically, someone can perform a denial-of-service (DOS) attack by attempting to login with garbage user/password pairs from many different clients at once. As per our attack script `attack_T10.sh` it is simple to write a basic script that performs this function, and our server *will* crash if overloaded in this way.  

This problem can be solved on the server side by recording the IP addresses that are used to attempt connections, and disallowing those connections after a certain excessive (but still small) number of attempted SRP handshakes in a short period of time. Thus, such an address will be flagged and ignored in future connection attempts.


## Summary ##


### Nice bonus features: ###
-   Salting our stored password hashes also prevents offline attacks in the event of a leak/hashdump

#### References ####
<b id="f1">1:</b> <https://pages.nist.gov/800-63-3/sp800-63b.html#appA> [↩](#a1)
