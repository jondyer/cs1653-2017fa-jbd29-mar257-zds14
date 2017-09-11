## Security Properties
#### Property __: Hierarchical Group Structure
Our group structure is set up so that a group may contain a subgroup and each subgroup has their own set of privileges and their own domain where their privileges apply. For example, you can have a group with a subgroup of administrators. The main group may be able to upload and download files, but only the administrator group is capable of adding and removing users to the group. This is important because it allows for a very flexible system with many possibilities. We must assume that the user implements this in a secure way. (Not giving admin privileges to every user.) We can help by providing a fail-safe default where the least privilege necessary is provided at first.

#### Property __: Administrative Groups
There should be a concept of administrative groups where these users have certain increased privileges within their group compared to its ordinary users. An example of the increased privileges can be the ability to add/remove users to/from a particular group. This is important because it removes the ability for any untrusted user to remove any user that they dislike. However, we have to make the assumption that these administrators can be trusted to not abuse their power.

#### Property __: Authentication
The user's identity will be verified through an account on the group server. Knowing the identity of the user allows the server to provide the user access to the appropriate files and give them the appropriate permissions. This should prevent unauthorized access if we can assume that a user's account has not been compromised.

#### Property __: Correctness
If file f is shared with members of group g, then only members of group g should be able to read, modify, delete, or see the existence of f. Without this requirement, any user could access any file, which is contrary to the notion of group-based file sharing.

#### Property __: Redundancy Redundancy
The system should have redundancy built in to provide better uptime and to prevent loss of data. Multiple servers in different locations should be used so if one location is temporarily unavailable, user data is still accessible from another location. This would also serve as a backup of that can be used to restore missing data.

#### Property __: File Integrity
If a file is modified or deleted by one user, it shall be consistent across the system. It is important to keep the file servers in sync because inconsistancies can lead to confusion and error.

#### Property __: File Metadata
Every file will have metadata associated with it, such as when it was last modified, and who it was modified by. The timestamps will all be in local server time. This information is important to have as it shows when it was last changed so that users can make sure they have the most up to date version.

#### Property __: Concurrent Access Protocol (CAP)
Multiple users should be able to read a file at the same time, but only one user at a time should be able to write to a file. A write lock can be put in place so that users are not writing over eachothers' work, resulting in lost data.

#### Property __: System Timeout
The proposed write lock should have a timeout. This will prevent a user from requesting write access and holding the file forever, effectively making it unusable for anyone else in the system.

#### Property __: Data Encryption
All data transmissions to/from the server should be encrypted under a well known protocol such as ssh. This is important for both privacy and data and source integrity reasons. It will prevent a malicious user from intercepting and reading, or maybe even editing, the data in transit to the server. Optionally, the user can choose to have the data be encrypted on a per group basis.

1. Handling Passwords
  Passwords should be hashed and salted

5. File Accountability  
  Change log or history
7. Authorization  
  Any attempt of access to a resource must be verified.
  How is this different from correctness?
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
18. Secure Defaults  
  - Password Rule Enforcement (PRE)
  - Admin Login Enforcement (ALE)
  - Port Access Law (PAL)
  

## Threat Models
### Local Family Media Server  
  - No web access
  - Assume no malicious users
  - Single admin account
  - Players
    - Dadmin
    - fam
	
**PROPERTIES**  
  - 1, 2, 3, 4, 6?, 8, 12, 13
### Medium-Sized Business
The system will be deployed in a medium-sized business environment with multiple locations. Access to the file sharing system is only provided through the company VPN or the local intranet. This VPN will allow for remote access from any location, such as the employees that work from home. Within the organization, different teams will require different permissions and access to different files. We are making the assumption that the companies intranet and VPN are not compromised. 

The two groups of players involved are: regular employees who will need to upload and download file, and the IT staff who have the permissions of regular employees as well as permissions necessary to manage the file system. Some examples of these properties are: creating/removing groups, adding/removing users, and the ability to reset a user's password. We are making the assumption that the employee's login credentials are known only to that employee. We are also assuming that employee's VPN access and file sharing accounts are terminated once the employee is no longer with the company. We also assume that we have benevolent IT staff who don't want to destroy everything with their increased permissions.


**PROPERTIES**  
  * Hierarchical Group Structure  
  The Hierarchical Group Structure allows for a flexible model. This will easily allow the IT staff to provide different teams with access to different files and different permissions.
  * Administrative Groups
  The concept of Administrative Groups allows the admins to only give employees the permissions that are necessary. It minimizes the number of people that you are required to trust.
  * Correctness
  The Correctness property ensures that users are not able to access files that they are not supposed to see, such as payroll information.
  * File Integrity
  File Integrity helps to make sure that users at different locations are working on the same version of the file. Data will be kept in sync so that all employees have access to the most recent version.
  * File Metadata
  Storing metadata on files will show important information such as the last person to modify a file. This is useful for employees who want to contact that person to ask a question.
  * File Accountability 
  This property provides a history to files. A files history is important to have in case any changes need to be reversed.
  - 6, 7, 8, 10, 11, 13, 14, 16, 17??, 18

### Galactic File-hosting service
  - Multiple locations per planet
  - Accessible anywhere in the galaxy (via the GWW)
  - Users are anyone with an account
  - Backups and synchronization
  - Players:
    - Developers
    - Users
    - Space pirates

**PROPERTIES**  
  - 1-18
