## Extra Credit additions
### GroupList
  We added a class called 'GroupList' (along with accompanying 'Group' class) which is analogous to the 'UserList' class that was already included. This class facilitates greater efficiency in certain operations, such as listing all members of a given group or determining quickly if a group exists (can simply ask the GroupList or Group object instead of iterating over all Users--especially helpful if there are more users than groups).  

  This class also provides the framework for planned future additions, such as easily allowing Admins to list all groups or find the owner of every group, etc.  

### Principle of least privilege
We attempted to enforce this principle in a couple of ways:  
*   Firstly, we require any accessing user (even administrators for the time being) to designate exactly which group they wish to operate within. Since we are not supporting any cross-group operations, it is never necessary to give a user options regarding more than one group at a time. Our menu makes it easy to switch the 'group context', but the options displayed will only ever apply to at most one group.  
*   In addition to simply limiting the options available to a user, we overloaded the 'getToken' function in the groupClient class (along with associated functions on the server side) to allow us to obtain a token with only a single group in the 'groups' field. This means that anyone operating with this new partial token will only have permission to perform actions on that one group at a time. When a user indicates which group they want to work with (in the above-specified menu restriction), the client then retrieves the partial token associated with that group and moves forward with that. The idea behind this is that if somehow that token escapes into the wild (i.e. someone maliciously/illegitimately/accidentally obtains it), then its potential damage is restricted to a single group.  

### Third one????
