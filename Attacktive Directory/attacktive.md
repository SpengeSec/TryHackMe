# TryHackMe - Attacktive Directory

## Windows - Medium Difficulty 
![](../img/thm/attackivedirectory/5ef76a435aebae7f3fc9e6368b6d51b9.png)

### Brought to you by
`https://tryhackme.com`

### Write up by
`Spenge` <br>
`https://spenge.pw`<br>
`twitter.com/@SpengeSec`<br>
***By copy/pasting & cheating you only cheat yourself!***



Lets first create a host record in our ***/etc/hosts*** file.

![](../img/thm/attackivedirectory/adebfb4a12de36002e869fbb8d739b96.png)



### Enumerate the DC
#### The first objective: `How many ports are open < 10000`?

![](../img/thm/attackivedirectory/2e481107fc9da6b111fa3438f6f2fad4.png)

`nmap -sV -sC -p 0-10000 -oA attacktive.nmap <ip>`

I counted 15, but apparently this was incorrect. To double check, I added `| grep open` at the end of my nmap command.

![](../img/thm/attackivedirectory/f3aa59500b5b2ba85f2cdacefda2be3e.png)

I still count 15, but a less detailed nmap scan comes up with only ***11*** open ports.

![](../img/thm/attackivedirectory/d5824d11e4306a81f8fb60330710b32c.png)



#### The second objective: `Which tool do we use to enumerate port 139/445 (SMB)`?

A well known tool to do so is ***enum4linux*** this was also hinted at in the brief.

#### The third objective: `Find out what the NetBIOS-Domain name is of the machine`.

To do so, we run `enum4linux <ip> 2>/dev/null > attacktive.e4l`

- 1) enum4linux <target ip>
- 2) 2>/dev/null -> don't show errors
- 3) > attacktive.e4l -> write output to file

This will return lots of information including the ***NetBIOS Domain Name***

![](../img/thm/attackivedirectory/437ef42416e128395bcda19975350122.png)

#### The fourth objective of the enumeration chapter is: `What invalid TLD do people commonly use for their Active Directory Domain`?

Our ***nmnap*** scan previously revealed the ***Domain Name*** being spookysec.***local***

![](../img/thm/attackivedirectory/5c3341d7357372648678d1e144ade4e0.png)

.local is often miss-used as a .TLD (Top Level Domain)


### Enumerate the DC Pt2 (KERBRUTE)

Lets proceed by downloading the userlist and passwordlist onto our machine.

![](../img/thm/attackivedirectory/f11cea25d554651e4b2c2819eee42ebc.png)

#### The first objective of this chapter is: `How to enumerate valid users with kerbrute`?

Kerbrute has a parameter ***userenum*** to enumerate valid usernames.

To enumerate valid usernames from the ***userlist.txt*** provided to us we run the following command:

`kerbrute_linux_386 userenum --dc spookysec.local -d spookysec.local userlist.txt
`

The output:

![](../img/thm/attackivedirectory/0ce4200031b8327a9b1b95b1d7a763db.png)

***A couple notable accounts are the following:***

- svc-admin@spookysec.local
- backup@spookysec.local
- administrator@spookysec.local

### Exploiting Kerberos
#### First objective: `We have two user accounts that we could potentially query a ticket from. Which user account can you query a ticket from with no password`?

We can use ***Impacket*** ***GetNPUsers.py*** to do some ASREPRoasting to determine if there's an account we can query Kerberos tickets from without password.

![](../img/thm/attackivedirectory/b9690f953f44e6fe6e92fbb044159d81.png)

`python GetNPUsers.py spookysec.local/ -usersfile <file_dir>
`

***svc-admin*** allows us to send a ticket without authentication!

#### Second objective: `Looking at the Hashcat Examples Wiki page, what type of Kerberos hash did we retrieve from the KDC? (Specify the full name)`?

If you visit https://hashcat.net/wiki/doku.php?id=example_hashes

And search for kerberos 5, you'll see the full name is "Kerberos 5 AS-REQ Pre-Auth etype 23" this seemed to be invalid still, so after doing some brute forcing ***Kerberos 5 AS-REQ etype 23*** was valid.


#### Third objective: `What mode is the hash`?
Kerberos 5 AS-REQ etype 23 hashes are mode ***18200*** (defined when using hashcat) this is basic knowledge but can easily be found with a Google search.

#### Fourth objective: `Now crack the hash with the modified password list provided, what is the user accounts password`?

To crack the hash i use ***John*** with the following command:

`john --wordlist=passwordlist.txt AS_REP.txt`

AS_REP.txt is a file containing the hash we previously retrieved.

![](../img/thm/attackivedirectory/b6620d417c3e6f86f9600c4970bb4ea0.png)

The password is ***man-------5***

### Enumerate the DC Pt 3 (SMB with credentials)

In this chapter we'll be using the credentials we previously discovered to gain access to the smb file sharing system.

#### First objective: `Using which utility can we map remote SMB shares`?

Again, this is common knowledge but we'll make use of the ***smbclient*** utility.

#### Second objective: `Which option will list shares`?

The ***-L*** parameter allows us to list shares. This information can be found in the man page.

#### Third objective: `How many remote shares is the server listing`?
To define a username using smbclient we define it by utilising the ***-U*** parameter.

![](../img/thm/attackivedirectory/72afd99aaa64a7ac88702ec57d5bc01e.png)

There are ***6*** shares available!

#### Fourth objective: `There is one particular share that we have access to that contains a text file. Which share is it`?

We can mount each share by using the following command:

`smbclient -U svc-admin //spookysec.local/<share_name>`

I mounted the ***backup*** share and there was a .txt file inside!

![](../img/thm/attackivedirectory/7f90260f72c4c49242c801e10153052d.png)

#### Fifth objective: `What is the content of the file`?

We can retrieve its content by utilising the ***more*** command.

![](../img/thm/attackivedirectory/d71b25bbe23f448edfb38d3c66c22bee.png)

![](../img/thm/attackivedirectory/63de1c0c105be4340e16d0ccb20cd495.png)

***Ym-----------------------------Yw***

#### Sixth objective: `Decoding the contents of the file, what is the full contents`?

To identify the type of hash we're dealing with I used https://www.tunnelsup.com/hash-analyzer/

![](../img/thm/attackivedirectory/81983382cb0a502dec441089e4748b95.png)

Character type ***base64*** I then decrypted base64 in my Kali machine using the following command:

![](../img/thm/attackivedirectory/f0f521edbd83baff6d49c5fc9a1054ea.png)


`base64 -d backup_credentials.txt`

The decrypted hash is ***backup@spookysec.local:ba---------0***

### Elevating Privileges

#### First objective: `What method allowed us to dump NTDS.DIT`?

![](../img/thm/attackivedirectory/2dda33c0700f357bcce99adcff8d00ed.png)

***DRSUAPI***

#### Second objective: `What is the Administrators NTLM hash`?

As you can see in the previous screenshot we use ***secretsdump.py*** to extract the hashes from all users the ***Domain Controller*** has access to.

![](../img/thm/attackivedirectory/c5a055f4fd9dc8999800bd97c8b62fa9.png)

The ***administrator*** NTLM hash is ***e----------------b***

#### Third objective: `What method of attack could allow us to authenticate as the user without the password`?

***Pass the hash*** a hacking technique that allows an attacker to authenticate to a remote server or service by using the underlying ***NTLM or LanMan hash*** of a user's password.

#### Fourth objective: `Using a tool called Evil-WinRM what option will allow us to use a hash`?

***-H*** allows us to input ***NThash***

![](../img/thm/attackivedirectory/329d46d23b75a8c9af3bec0e747bbe4e.png)

### Flags
We can now connect to each of the accounts with their NT:LM hashes.

Evil-winrm supports Pass The Hash, the -H flag allows us to authenticate with the NT hash as explained in the objective above.

![](../img/thm/attackivedirectory/5ed2e2932f4229f08c9158a2b6da0f9e.png)

`evil-winrm -i <ip> -u Administrator -H <NT Hash>`

We are now Administrator, each flag is located in the user ***Desktop*** directory.
