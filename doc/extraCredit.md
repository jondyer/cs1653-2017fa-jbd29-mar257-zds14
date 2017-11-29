# Extra Credit additions #
## Phase 4 ##
### Test Script ###
We felt that it would be useful to have a script that tested all possible operations a user can perform. The result (`betterScript`) automatically starts an instance each of TrentServer, GroupServer, and FileServer, and then runs a ClientApp for your testing convenience. If run with the '-f' flag, it will remove any previous binaries in the `src` folder and start fresh, while the '-t' flag will run every command in the `clientInput` file (each on a separate line, can be modified as desired). Note that this script currently only supports Linux (and Mac OS when run with the '-m' flag). However, it was extremely useful (not to mention educational) and well worth the time.


## Phase 3 and prior ##
### GroupList ###
We added a class called `GroupList` (along with accompanying `Group` class) which is analogous to the `UserList` class that was already included. This class facilitates greater efficiency in certain operations, such as listing all members of a given group or determining quickly if a group exists (can simply ask the GroupList or Group object instead of iterating over all Users--especially helpful if there are more users than groups).  

This class also provides the framework for planned future additions, such as easily allowing Admins to list all groups or find the owner of every group, etc.  

### Principle of least privilege ###
We attempted to enforce this principle in a couple of ways:  
*   Firstly, we require any accessing user (even administrators for the time being) to designate exactly which group they wish to operate within. Since we are not supporting any cross-group operations, it is never necessary to give a user options regarding more than one group at a time. Our menu makes it easy to switch the 'group context', but the options displayed will only ever apply to at most one group.  
*   In addition to simply limiting the options available to a user, we overloaded the `getToken` function in the `groupClient` class (along with associated functions on the server side) to allow us to obtain a token with only a single group in the `groups` field. This means that anyone operating with this new partial token will only have permission to perform actions on that one group at a time. When a user indicates which group they want to work with (in the above-specified menu restriction), the client then retrieves the partial token associated with that group and moves forward with that. The idea behind this is that if somehow that token escapes into the wild (i.e. someone maliciously/illegitimately/accidentally obtains it), then its potential damage is restricted to a single group.  

### ADMIN Group ###
Our system supports the concept of an `ADMIN` group. It has the functionality/behavior of any other group along with administrative privileges, such as Adding/Removing users from the file system, and looking at full lists of existing users and groups. The owner of the `ADMIN` group (The "Super-Admin") is created when the group server first starts. That admin is the one who can manage members of the `ADMIN` group, just as it would be for an owner in any other group. Group `ADMIN` can not be deleted.
