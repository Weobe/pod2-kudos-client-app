# pod2-kudos-client-app

# Installation:

1. Clone this github repo and change directory:

```
git clone https://github.com/Weobe/pod2-kudos-client-app.git
cd pod2-kudos-client-app
```

2. Add an RSA-4096 Key to your GitHub account following the instructions in this link: https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account
3. Create a signature of the text `0xPARC-double-blind` in namespace `double-blind.xyz` with your GitHub private key using this command:
   ```
   ssh-keygen -Y sign -n double-blind.xyz  -f <PATH_TO_YOUR_GITHUB_KEY> > github_rsa.sig
   ```

When prompted, enter your passkey (if any) and then type `0xPARC-double-blind` in the standard input. To finish, press Ctrl+D / Control+D twice without pressing Enter (Pressing Enter adds a new line to the input which would change the text you are signing) 

4. Place `github_rsa.sig` under `pod2-kudos-client-app/main/signature/github_rsa.sig` (Or just paste it in the existing file)

5. Add the 0xPARC server URL to `main/.env` `API_URL=http://192.168.0.225:8080`
   
6. run `init.sh` under `main` directory
```
cd main
bash init.sh
```

# Usage:

You can send kudos from your terminal using `send-pod-kudos`

```
send-pod-kudos
Message: <Your Message>
```

NOTE: For your first usage, please run it with options `send-pod-kudos --generate` to configure your RSA Double Blind Pod.

To change the list of users in your group signature, run with option `--manual` and enter list of users manually. Alternatively, you can edit `main/group_list.json` directly.


