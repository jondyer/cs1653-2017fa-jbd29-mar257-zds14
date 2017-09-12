# CS 1653: Applied Cryptography and Network Security - Phase 1
## Security Properties  

### Property 1: Hierarchical Group Structure
Our group structure is set up so that a group may contain a subgroup and each subgroup has their own set of privileges and their own domain where their privileges apply. For example, you can have a group with a subgroup of administrators. The main group may be able to upload and download files, but only the administrator group is capable of adding and removing users to the group. This is important because it allows for a very flexible system with many possibilities. We must assume that the user implements this in a secure way. (Not giving admin privileges to every user.) We can help by providing a fail-safe default where the least privilege necessary is provided at first.

### Property 2: Administrative Groups
There should be a concept of administrative groups where these users have certain increased privileges within their group compared to its ordinary users. An example of the increased privileges can be the ability to add/remove users to/from a particular group. This is important because it removes the ability for any untrusted user to remove any user that they dislike. However, we have to make the assumption that these administrators can be trusted to not abuse their power.

### Property 3: Authentication
The user's identity will be verified through an account on the group server. Knowing the identity of the user allows the server to provide the user access to the appropriate files and give them the appropriate permissions. This should prevent unauthorized access if we can assume that a user's account has not been compromised.

### Property 4: Correctness
If file f is shared with members of group g, then only members of group g are authorized to read, modify, delete, or see the existence of f. Without this requirement, any user could access any file, which is contrary to the notion of group-based file sharing.

### Property 5: Redundancy Redundancy
The system should have redundancy built in to provide better uptime and to prevent loss of data. Multiple servers in different locations should be used so if one location is temporarily unavailable, user data is still accessible from another location. This would also serve as a backup which can be used to restore missing data.

### Property 6: File Consistency
If a file is modified or deleted by one user, it shall be consistent across the system. It is important to keep the file servers in sync because inconsistencies can lead to confusion and error.

### Property 7: File Metadata
Every file will have metadata associated with it, such as when it was last modified, and who it was modified by. The timestamps will all be in group server local time. This information is important to have so that users can make sure they have the most up to date version.

### Property 8: Concurrent Access Protocol (CAP)
Multiple users should be able to read a file at the same time, but only one user at a time should be able to write to a file. A write lock can be put in place so that users are not writing over each others' work, resulting in lost data.

### Property 9: File Availability
A file should be accessible to the users most of the time. A user should not be able to request write access and hold it forever, effectively making it unusable for anyone else in the system. A timeout on the write lock is one method to prevent this.

### Property 10: Data Confidentiality During Transfer
All data transmissions to/from the server should be confidential. We can do this over a well known protocol like SSH. This is important for both privacy and data and source integrity reasons. It will prevent a malicious user from intercepting and reading, or maybe even editing, the data in transit to the server. We are assuming that the protocol we use is implemented correctly and the encryption it uses has not been broken.   

### Property 11: Data Confidentiality During Storage
Administrators should be able to choose whether or not to provide data confidentiality on a per group basis. We can provide this functionality through th use of a popular encryption algorithm. This is important when storing sensitive information, such as payroll data. We are making the assumption that the algorithm we chose has not been broken and there are no backdoors.  

### Property 12: User Account Properties
In the event that a user's account becomes compromised or simply needs altered, its properties must be mutable. This includes being able to change login information - i.e. username and password, as well as being able to decommission the account in question.

### Property 13: Performance  
It is important that a system function as intended _reasonably efficiently_ so the criterion of availability can be fulfilled. For example, having a server that becomes prohibitively slow when multiple users are accessing the same file can be as bad as not having the server at all, since availability is compromised. We assume that this type of performance can be achieved without directly infringing on other security criteria.

### Property 14: File Accountability  
Some means of recording changes made to data, such as a change log or file history, should be provided in order to preserve data integrity and source integrity. This enforces a kind of non-repudiation by allowing administrators to determine the source of a change in the event of an attack or unexpected modification.

### Property 15: Usability ("It's Gon' Work")
A system should be usable, meaning that to the best of our knowledge it should be free of bugs and program flaws that may result in vulnerabilities. It should also be navigable and manageable for both users and admins--in particular, security features should be straightforwardly implemented and accessible so that they are more easily enforced. More usable features lead to increased user adoption, leading to greater security overall.

### Property 16: Separation  
The general design principle of separating items, tasks, processes, and privileges that do not necessarily need to be together contributes to overall security of a system. For example, memory protection (preventing a process from accessing the address space/resources of another) helps restrict the potential damage caused by a malicious process. Additionally, separating privileges from one process or task to another allows for support of a _least privilege_ principle, so that processes/users are not operating with unnecessarily high permissions.


## Threat Models
### Local Family Media Server  
This is a basic system which will be used in a home environment on a local network. Access is possible via a device on the local network only, so there should be no direct web connection to the server. The organization (call it the "family") is simple, and consists simply of users of the server, plus one administrative account that has typical permissions (such as adding/removing users and resetting passwords).

We'll assume that no one in the family has malicious intent, meaning that they are not attempting to access files that are not shared with them or perform unauthorized operations on shared files. We assume that each member of the family has a unique login username and password that provides user-level access to the server, and that this information is known only to that user. Additionally, we will suppose that this server is hosted on a network with standard security measures in place.



#### **PROPERTIES**  
  * **Hierarchical Group Structure**   
  This structure allows for the admin to give access to different files to different users. This makes the server more useful and flexible, while preventing unauthorized privilege escalation(?).

  * **Administrative Groups**  
  The concept of Administrative Groups allows the administrator to only give family members the permissions that are necessary. It also restricts the number of accounts with high-level (potentially damaging) permissions.

  * **Correctness**  
  The Correctness property ensures that users are not able to access files that they are not supposed to see, such as media uploaded by another family member and not shared with them.   

  * **Authentication**  
  Verifying the identity of users adds an extra layer of security (beyond whatever the local network provides) by ensuring only members (with an account) have access and that they only have access to the files that they should.  

  * **File Consistency**  
  File Consistency helps to make sure that one user isn't trying to access a file that has been deleted by that file's owner. This information should be synchronized across all file servers in the system.

  * **Concurrent Access Protocol**   
  The server should allow multiple family members to read a file at once, but it should only be modifiable by one person at a time. This helps ensure consistency and usability throughout the system.


  - 8, 12, 13  

### Medium-Sized Business
The system will be deployed in a medium-sized business environment with multiple locations. Access to the file sharing system is only provided through the company VPN or the local intranet. This VPN will allow for remote access from any location, such as the employees that work from home. Within the organization, different teams will require different permissions and access to different files. We are making the assumption that the company's intranet and VPN are not compromised.

The two groups of players involved are: regular employees who will need to upload and download files, and the IT staff who have the permissions of regular employees as well as permissions necessary to manage the file system. Some examples of these properties are: creating/removing groups, adding/removing users, and the ability to reset a user's password. We are making the assumption that the employee's login credentials are known only to that employee. We are also assuming that employee's VPN access and file sharing accounts are terminated once the employee is no longer with the company. We also assume that we have benevolent IT staff who don't want to destroy everything with their increased permissions.


#### **PROPERTIES**  
  * **Hierarchical Group Structure**  
  The Hierarchical Group Structure allows for a flexible model. This will easily allow the IT staff to provide different teams with access to different files and different permissions.  

  * **Administrative Groups**  
  The concept of Administrative Groups allows the admins to only give employees the permissions that are necessary. It minimizes the number of people that you are required to trust.  

  * **Correctness**  
  The Correctness property ensures that users are not able to access files that they are not supposed to see, such as payroll information.  

  * **File Consistency**  
  File Consistency helps to make sure that users at different locations are working on the same version of the file. Data will be kept in sync so that all employees have access to the most recent version.  

  * **File Metadata**  
  Storing metadata on files will show important information such as the last person to modify a file. This is useful for employees who want to contact that person to ask a question.  

  * **File Accountability**  
  This property provides a history to files. A files history is important to have in case any changes need to be reversed.  

  * **Authentication**  
  Verifying the identity of users is done to make sure that only the employees of the company have access and they only have access to the files that they should.  

  * **Concurrent Access Protocol**  
  Preventing multiple users from writing to the same file at the same time will help to ensure that the file remains consistent. Multiple employees trying to edit at the same time would just lead to lost work.  

  * **Data Confidentiality During Transfer**  
  This will prevent a malicious user from intercepting and reading, or maybe even editing, the data in transit to the server. Doing this is necessary for sensitive information like payroll data.  

  * **Data Confidentiality During Storage**  
  Providing data confidentiality to stored files will help to protect privacy and to prevent a disclosure threat. Doing this will help to keep the company secrets actually secret.  

  * **User Account Properties**  
  Timely suspension of user accounts is an important security measure to have in place, to prevent access by former employees.  

  * **Redundancy Redundancy**  
  Having backups are important for businesses which don't want to lose data. Hard drives fail, data gets corrupted; having a backup is important to mitigate any of these issues.  

  * **File Accountability**  
  Having a file history is important for companies that need to ever revert to an old version of file or to monitor changes between two different versions.  

  * **Usability**  
  Usability is an important factor to have to ensure a speedy workflow. The software should be help, never a hinderance, to its users.  
  
  * **Seperation**  
  Seperation of processes and privileges should be done where possible to minimized the risk of privilege escalation and other vulnerabilities.  


### Galactic File-hosting service
This platform allows users to access their own private server space via an online web portal (similar to Dropbox). It will span the galaxy, possibly necessitating multiple server locations per planet, or some kind of large, localized data center (for performance and feasibility reasons). In other words, this service will be accessible anywhere in the galaxy (with internet connection) via the Galaxy Wide Web (GWW).

The two primary groups of concern are the people using the service with user-level permissions and the IT staff/developers who have permission to modify and manage the filesystem and platform itself. We will include in this group any automated processes responsible for function of the service that operate with elevated privileges (e.g. process that creates a new user, resets a password, etc.). We will assume that all of the employees are gruntled, i.e. that none of them have malicious intent towards the company. We suppose that a user's login credentials are private, and that the space pirates that attack such services for fun and profit have no more than user-level credentials (i.e. no insider threat).


#### **PROPERTIES**  
  * **Hierarchical Group Structure**  
  The Hierarchical Group Structure allows for a flexible model. This will easily allow the IT staff/Developers to provide different teams with access to different files and different permissions.

  * **Administrative Groups**  
  The concept of Administrative Groups allows the IT staff/Developers to only give employees the permissions that are necessary. It minimizes the number of people that you are required to trust.  

  * **Authentication**  
  Authentication allows for a particular user in the galaxy to be identified to his/her/its account, i.e. so that space pirates would not be able to log in to a user's account that is not their own.

  * **Correctness**  
  The Correctness property ensures that users are not able to access files that they are not supposed to see. For instance, data from Intra-Galaxy Group A should not be visible/accessible to Intra-Galaxy Group B.

  * **Redundancy Redundancy**  
  Redundancy is important for having maximum up-time for the system and preserving all user data. Storing multiple copies of information in different locations would be suitable for this.

  * **File Consistency**  
  File Consistency helps to make sure that users at different locations within the galaxy are working on the same version of the file. This is especially important with the long distances data may have to travel.

  * **File Metadata**  
  Storing metadata on files will show important information such as the last person to modify a file. This is useful for users who want to contact that person to ask a question.  

  * **File Accountability**  
  This property provides a history to files. A files history is important to have in case any changes need to be reversed.  

  * **Authentication**  
  Verifying the identity of users is done to make sure that only the employees of the company have access and they only have access to the files that they should.  

  * **Concurrent Access Protocol**  
  Preventing multiple users from writing to the same file at the same time will help to ensure that the file remains consistent. Multiple users trying to edit at the same time would just lead to lost work.  

  * **Data Confidentiality During Transfer**  
  This will prevent a malicious user from intercepting and reading, or maybe even editing, the data in transit to the server. Doing this is necessary for sensitive information like financial transactions, personally identifiable information, etc.  

  * **Data Confidentiality During Storage**  
  Providing data confidentiality to stored files will help to protect privacy and to prevent a disclosure threat. Doing this will help to keep the company and user secrets actually secret.
