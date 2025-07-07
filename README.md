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
   echo -n "0xPARC-double-blind" | ssh-keygen -Y sign -n double-blind.xyz  -f <PATH_TO_YOUR_GITHUB_KEY> > github_rsa.sig
   ```

When prompted, enter your passkey (if any)

4. Place `github_rsa.sig` under `pod2-kudos-client-app/main/signature/github_rsa.sig` (Or just paste it in the existing file)

  ```
  cp github_rsa.sig main/signature/github_rsa.sig
  ```

5. Add the 0xPARC server URL to `pod2-kudos-client-app/main/.env` `API_URL=http://192.168.0.225:8080`

  ```
  echo "API_URL=http://192.168.0.225:8080" > main/.env
  ```
6. run `init.sh` under `main` directory
```
cd main
bash init.sh
```
This will add a new command in ~/bin and add it to your path.  You may need to restart your terminal or source your RC file, e.g. `source ~/.zshrc` to update the PATH.

# Usage:

You can send kudos from your terminal using `send-pod-kudos`

```
send-pod-kudos
Message: <Your Message>
```

NOTE: For your first usage, please run it with options `send-pod-kudos --generate` to configure your RSA Double Blind Pod.

To change the list of users in your group signature, run with option `--manual` and enter list of users manually. Alternatively, you can edit `main/group_list.json` directly.


