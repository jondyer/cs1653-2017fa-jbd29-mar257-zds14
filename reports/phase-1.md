### Security Properties
1. Administrative Groups/Users  
  Users cannot arbitrarily add/remove other users to/from other groups.
2. Correctness
  If file f is shared with members of group g, then only members of group g should be able to read, modify, delete, or see the existence of f. Without this requirement, any user could access any file, which is contrary to the notion of group-based file sharing.
3. File Integrity  
  If a file is modified or deleted by one user, it shall be consistent across the system.
4. File Metadata
5. File Accountability  
  Change log or history
6. Authentication
7. Authorization  
  Any attempt of access to a resource must be verified.
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
  
