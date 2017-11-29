# Usage Instructions #

## Running the Key Server aka Trent ##

To start the Trent:
-   Enter the `src` directory containing **RunTrentServer.class**
-   Type `java -cp .:bcprov-jdk15on-158.jar RunTrentServer [port number]`

Note that the port number argument to **RunTrentServer** is optional.  This argument specifies the port that the Trent will listen to.  If unspecified, it defaults to port 4444.  Trent must either run on his own machine or all servers must run on the same machine (allowed for testing purposes).

When the Trent is first started, there are no users or groups. Trent should be the first server of the group that is started. If other servers start first, they won't be able to regster their public keys with Trent.

## Running the Group Server ##

To start the Group Server:
-   Enter the `src` directory containing **RunGroupServer.class**
-   Type `java -cp .:bcprov-jdk15on-158.jar RunGroupServer [port number] [Trent_IP] [Trent_Port]`

Note that the arguments to **RunGroupServer** are optional.  The first argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765 and it is assumed that Trent is on the "localhost" at port 4444. You may also enter Trent's actual IP and port if he is not located locally. This allows the server to register its public key with Trent.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.  

## Running the File Server ##

To start the File Server:
-   Enter the `src` directory containing **RunFileServer.class**
-   Type `java -cp .:bcprov-jdk15on-158.jar RunFileServer [port number] [Trent_IP] [Trent_Port]`

Note that the port number argument to **RunFileServer** is optional.  This argument specifies the port that the File Server will listen to. If unspecified, it defaults to port 4321 and it is assumed that Trent is on the "localhost" at port 4444. You may also enter Trent's actual IP and port if he is not located locally. This allows the server to register its public key with Trent.  

The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.  

## Running the Client Application ##

To start the Client Application:
-   Enter the `src` directory containing **RunClientApp.class**  
-   Type `java RunClientApp`
-   or `java -cp .:bcprov-jdk15on-158.jar RunClientApp [file_serv port]`  
-   or `java -cp .:bcprov-jdk15on-158.jar RunClientApp [file_serv port] [group_serv port]`  
-   or `java -cp .:bcprov-jdk15on-158.jar RunClientApp [file_serv port] [group_serv port] [trent_serv port]`  
-   or `java -cp .:bcprov-jdk15on-158.jar RunClientApp [file_serv host] [file_serv port] [group_serv host] [group_serv port]`
-   or `java -cp .:bcprov-jdk15on-158.jar RunClientApp [file_serv host] [file_serv port] [group_serv host] [group_serv port] [trent_serv host] [trent_serv port]`  

Any arguments used are optional. If run with no arguments the client will default to **interactive** mode, guiding the user to fill in the IP and port options or leave them as their default values. Each of the other options allow you to specify the values at the command line. If a port is not specified, it will assume to use that respective server's default port. If an IP address is not specified, it will assume to be located on the "localhost".  

Once started, the client will attempt to connect to the servers specified earlier. If successful, the user will be prompted to enter their username and their password. Our implementation puts the least privilege principal into practice, so users will be asked which group they would like to modify and what types of operations they would like to perform during their session.  

If that user is an administrator, they will be asked if they want to perform administrative operations during this session. Next, the user will either create a new group or select a group they want from the list of groups that they belong to. If they enter `c` to create a group, the group will be created with the user as the owner if the group name is not taken. Once the user selects a group, if they are the owner, they will be asked if they would like to perform owner operations.  

The complete list of options is broken up into several groups. Each only displaying if their current token has the required permissions. The options follow:  
*   Admin Ops:  
    a0) Create user  
    a1) Delete user  
    a2) List all groups  
    a3) List all users  

*   Owner Ops:  
    o0) List members of a group  
    o1) Add user to group  
    o2) Remove user from group  
    o3) Delete group  

*   User Ops:  
    0\) List files  
    1\) Upload files  
    2\) Download files  
    3\) Delete files  
    4\) Create a group  


The user is able to select an option by entering the code preceding the parentheses. For example, if the user belongs to the administrator group they can enter `a0` to begin the process of creating a new user. Each option will display a user-friendly guided approach that anyone can understand. Once the operation has been completed, they will be returned to the main menu shown above where they can make another choice.

If the user would like to switch to operate on a different group they can enter `q` while at the main menu. They can exit the program by entering `q` while at the group select menu. To login as another user you must quit the program and start it again.


## Resetting the Group or File Server ##
To restart everything, simply type `rm *.bin` before restarting all servers and ClientApp.

To reset the Group Server, delete the file **ServerList.bin** and any assosciated KeyPair files.
To reset the Group Server, delete the files **UserList.bin** and **GroupList.bin** and any assosciated KeyPair files.  

To reset a File Server, delete the **FileList.bin** file and the **shared_files/** directory and any associated KeyPair files.  
