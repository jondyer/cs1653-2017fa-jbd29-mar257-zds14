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
The lack of restriction for password creation makes it easy for users to be created with basic or simple passwords, giving a low level of protection should an attacker discover a username and attempt to guess the corresponding password. Our system is currently enforcing no rules for password creation, not even for the administrator account. Thus, common and short passwords such as `password` or `1234` are allowed, leaving those accounts vulnerable to a brute force attack on their passwords.

Our solution to this threat is to require a minimum length on all passwords, in accordance with the latest NIST guidelines.<sup id="a1">[1](#f1)</sup> We will make this minimum length to be no less than 8 characters. While we encourage the user to make lengthy passwords that are harder to brute force and/or guess, we will limit password length at 100 characters maximum, because excessively long passwords can take additional time to hash.  We do not find it necessary to add a complexity requirement, as per NIST guidelines<sup id="a1">[1](#f1)</sup>, because research has shown this to be somewhat ineffective, as it has potential to add negative value to the secret. If a user must add an uppercase letter, number, and a symbol; they will likely change `password` to `Password1!` -  making it very predictable to guess the behavior, and therefore adding no more security to the password. We also intend to check the user's password against a dictionary of common passwords and reject it if there is a match.  

We believe that implementing these changes will make it much more difficult for an atacker to compromise attacks. They will have a harder time running through a dictionary and will be forced to brute force longer passwords.


### T9: Online Password Attack ###
This threat involves the potential for someone to make a brute-force attack on a user's password by attempting to login repeatedly, perhaps with a dictionary of words, as a given user. This is currently possible since our interface simply returns "wrong password" on a mis-entry and allows the user to keep trying.

We address this vulnerability by implementing a timed exponential backoff system for invlid login attempts. The user will be given three chances to enter their password. If all are invalid, there will be a slight delay before the next attempt is accepted. If this is also invalid, the delay time between login attempts will be increased again. The delay time will continue to increase in an exponential fashion for each successive failed login attempt. This will prevent a dictionary-type attack on a user's password especially combined with the password rule enforcement above.  

We believe exponential backoff will prevent an attacker for compromising as many accounts. T8 forces the attacker to brute force a stronger password and the exponential backoff will greatly limit the number of attempts possible.  

### T10: Login DOS Attack ###
This threat comes by way of any malicious party who decides to interrupt the availability of the file-hosting service. Specifically, someone can perform a denial-of-service (DOS) attack by attempting to login with garbage user/password pairs from many different clients at once. As per our attack script `attack_T10.sh` it is simple to write a basic script that performs this function, and our server *will* crash if overloaded in this way.  

This problem can be solved on the server side by requiring a puzzle to be solved, and disallowing those connections with an incorrect solution. The puzzle needs to be something that takes enough work on the client side to prevent the client from performing a DOS attack, but easy enough on the server to check so that it can still accept many incoming connections. An example of a puzzle that comes to mind is brute-forcing a small hash of say 3 or 4 alphanumeric characters. On the client side they will have to perform up to 3^62 hash operations and string comparisons. The size of our result stops the option of simply storing all results. However, the server simply needs one string comparison to verify a connection.  

We believe that this will be effective because it will force the client to do work when submitting a connection so that they will effectiely DOS themselves before harming the server.  


## Summary ##


### Nice bonus features: ###
-   Salting our stored password hashes also prevents offline attacks in the event of a leak/hashdump

#### References ####
<b id="f1">1:</b> <https://pages.nist.gov/800-63-3/sp800-63b.html#appA> [↩](#a1)
