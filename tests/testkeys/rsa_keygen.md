## Why RSA?

Short answer is that I couldn't get our standard EC private keys to work with `frank-jwt` (and it's the only Rust library that implements ES256). RS256 seems to work. I suspect the private key format we generally use isn't being parsed correctly.

## Key generation

For RS256
```
openssl genrsa -out rsa_private.pem 2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

## The admin database

I used the Auth0 service key option to get the basic structure in the database. Then I had to figure out how to extract the right values out of the public key, get them encoded to base64, and in a format ironcore-id would understand.

The following resources were helpful:
* [SO post](https://crypto.stackexchange.com/questions/18031/how-to-find-modulus-from-a-rsa-public-key)
* [Key parser](https://lapo.it/asn1js/) to understand the format better
* [Hex to base64 encoder](http://tomeko.net/online_tools/hex_to_base64.php)

### Steps to get the right base64 string


```
openssl rsa -pubin -in pubkey.txt -text -noout
cat pubkey.txt
```

These are the `n` and `e` values that ironcore-id expects to be in the format `n`.`e` (base64)

Use the [Hex to base64 encoder](http://tomeko.net/online_tools/hex_to_base64.php) to encode the Modulus value (n). Save the value away.

Do the same with the hex value of the exponent. It's probably 0x010001 (65537) which is `AQAB` in base64. Concat that value onto the `n` value, separated by a `.`

Use psql to insert that value into the db

Current key was:

```
update service_key set public_key = 'APC8lcY7EwzvJHvzlsCth0Q98+RwuWTbkh8Wf/Wp2btoBgfgLaQhI7svAR1e/0cb0uROYUfzsgClxBipsAm3B9gHEtUPtKTU0wFvW+xGgRzTlkhCTDCXcpRG2tgyDMQPh0tzGkEc+6sxnF1euBBxuNpm718SN9IlO2k5gBj7v2hSjlnvPoOt9TV93OTX6CCpAFotrrZf1x0gdwEfuu5rSv7GMXH2Bt/tbogv80I6XOMorSjnyH1VXdEVeNTnbAnfR5DyAXIjiBtRLRftiBZJPwZa4ysxrxrL6umnXYVx0DcZC15ta2JAaB65IoWPbpSKNyc1cxTcT60pNW+ElcCJl3k=.AQAB' where id = 551;

```

IMPORTANT!
*Put in the correct `id` for the service key!*