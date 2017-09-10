## Security Properties
#### Property __: Hierarchical Group Structure
Our group structure is set up so that a group may contain a subgroup and each subgroup has their own set of privileges and their own domain where their privileges apply. For example, you can have a group with a subgroup of administrators. The main group may be able to upload and download files, but only the administrator group is capable of adding and removing users to the group. This is important because it allows for a very flexible system with many possibilities. We must assume that the user implements this in a secure way. (Not giving admin privileges to every user.) We can help by providing a fail-safe default where the least privilege necessary is provided at first.

#### Property __: Administrative Groups
There should be a concept of administrative groups where these users have certain increased privileges within their group compared to its ordinary users. An example of the increased privileges can be the ability to add/remove users to/from a particular group. This is important because it removes the ability for any untrusted user to remove any user that they dislike. However, we have to make the assumption that these administrators can be trusted to not abuse their power.

#### Property __: Authentication
The user's identity will be verified through an account on the group server. Knowing the identity of the user allows the server to provide the user access to the appropriate files and give them the appropriate permissions. This should prevent unauthorized access if we can assume that a user's account has not been compromised.

#### Property __: Correctness
If file f is shared with members of group g, then only members of group g should be able to read, modify, delete, or see the existence of f. Without this requirement, any user could access any file, which is contrary to the notion of group-based file sharing.

3. File Integrity  
  If a file is modified or deleted by one user, it shall be consistent across the system.
4. File Metadata
5. File Accountability  
  Change log or history
7. Authorization  
  Any attempt of access to a resource must be verified.
  How is this different from correctness?
8. Concurrent Access Protocol (CAP)
9. System Timeout
10. Data Encryption  
  Data encrypted in the file server and in transmission to/from client side. Passwords are encrypted
11. User Account Properties  
  Passwords can be changed, etc.
12. Performance
13. Usability  
  Not usable = Not secure
14. Least privilege  
  Both users _and_ processes should operate with minimum permissions necessary
15. It's gon' work (IGW)
16. Memory Protection  
  Separation of address spaces. Processes are running within own memory portion.
17. Redundancy Redundancy
18. Secure Defaults  
  - Password Rule Enforcement (PRE)
  - Admin Login Enforcement (ALE)
  - Port Access Law (PAL)
  

### Threat Models
1. Local Family Media Server  
  - No web access
  - Assume no malicious users
  - Single admin account
  - Players
    - Dad
    - fam
  - **PROPERTIES**
    - IGW
    - 1, 2, 3, 4, 6?, 8, 12, 13
2. Small business
  - Multiple locations, VPN
  - remote access from any internet location
  - Multiple departments/permissions
  - Assume only employees have access to the VPN
  - Players
    - Max
    - Employees
    - IT guys
  - **PROPERTIES**
    - IGW
    - 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 13, 14, 16, 17??, 18
3. Galactic File-hosting service
  - Multiple locations per planet
  - Accessible anywhere in the galaxy (via the GWW)
  - Users are anyone with an account
  - Backups and synchronization
  - Players:
    - Developers
    - Users
    - Space pirates
    - Dawgs
  - **PROPERTIES**
    - IGW
    - 1-18
