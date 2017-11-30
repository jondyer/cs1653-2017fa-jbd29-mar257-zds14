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


### T9: Online Password Attack ###


### T10: Login DOS Attack ###

## Summary ##


### Nice bonus features: ###


#### References ####
