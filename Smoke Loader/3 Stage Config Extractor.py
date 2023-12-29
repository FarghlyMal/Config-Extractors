from Crypto.Cipher import ARC4

ipher = ARC4.new(key)

dump = b'2d0c9bbe0672b7a2519cf8d4899033124f008c6bb854825507baab3d076ae7276985fcd584200e4df89c8467de25243780ac0276ecff1ba4dbcec485330e470a9d18835f855f19a2ab76494ef2323887e7d3840c058bbc1771e4be4cd6f2cbcb092880a91775e4e210c20b1483bf1168e3d20d91ecc206119caf0432bf08058bbc1771e4be4c06119da61b6ee3050b83af4533071386a41e75f9fd06139cf82932bf060081b91771e4071787af1a6dbebf071787a60160fde40a1799a92064fffe1797f807328ab80568e2e3044a8da30204419c8c300441dff80e0a419cef4639d5a84ec0ce0c41efb9765d8da87e9096d4a70841efb976248dfe7e1c16efaf76668dfe7e8e96d5a7c45c4f284ce96bca42f11a6be9ce71691241ef8b76518ddd7ebc96e6a7a35c3c2849e90c41ef9e76448dc07ea89682a7084aefaf76798de87e084aefae766d8de17e084aefa876608df97e205eef90766e8de37e9d9689a7be5c192809e92aca45f1536baace6b696e8a30540834ef8576528dd97e5e27efa5766f8df97e9d96c9a7835c502838e93dca41f15f6bf6ce22696a8a32549895daf6267d419e89aa70b12180ec1110e5b4528b785e1366c5dd547530a8d4f647d1ab1d6d6af25586f5ca7bfb7ddf1250858716b75b46ac95d0bc915b080befba76648de37e102cefa576728df97ec29687a7d25c0e280a34ef9e76308dbd7eb5962655eff376388db47ed59696a7c65c50285fe974ca65f10a6bfcce38693b8a7254d29586f67f7d4222efa376738de87e9e96c8a78f5c5d2828e921ca57f15b6bb9ce6e697f8a6254aa95c4f6207d559e9baa61b13a80a3113fe5fc5296781d1365c58a542730edd4e3474425efa976628de87e8896d3a7cd5c5d2846e96bca1bf1376bc6ce50696e8a24548d95c4f62a7d509ed2aa24b12080f7110ae5eb52c9785c133ec58f545130a0d4e34791ab4625efa976628de87e8896d3a7cd5c5d2846e96bca1bf1376bc6ce50696e8a24548d95c4f62a7d509ed2aa24b12080f7110ae5eb52807849133ec585542730d6d4b547cdab406d084aefa9766e8de07e084aefa576738dea7e084aefa476648df97e1801efb276718de17e9796d5a7925c0f2842e921ca49f15f6b'
dump= binascii.unhexlify(dump)
index = 0
key =0x246FC425
while index < len(dump):
    enc_length = str_data[index]                                                    #inspired from HerraCore @oalabs
    x = rc4crypt(dump[index+1:index+1+enc_length], struct.pack('<I',key))
    print(x.replace(b'\x00',b'')) 
    index = index+1+enc_length


# output
b'https://dns.google/resolve?name=microsoft.com'
b'Software\\Microsoft\\Internet Explorer'
b'advapi32.dll'
b'Location:'
b'plugin_size'
b'user32'
b'advapi32'
b'urlmon'
b'ole32'
b'winhttp'
b'ws2_32'
b'dnsapi'
b'shell32'
b'shlwapi'
b'svcVersion'
b'Version'
b'.bit'
b'%sFF'
b'%02x'
b'%s%08X%08X'
b'%s\\%hs'
b'%s%s'
b'regsvr32 /s %s'
b'%APPDATA%'
b'%TEMP%'
b'.exe'
b'.dll'
b'.bat'
b':Zone.Identifier'
b'POST'
b'Content-Type: application/x-www-form-urlencoded'
b'open'
b'Host: %s'
b'PT10M'
b'1999-11-30T00:00:00'
b'Firefox Default Browser Agent %hs'
b'Accept: */*\r\nReferer: http://%S%s/'
b'Accept: */*\r\nReferer: https://%S%s/'
b'.com'
b'.org'
b'.net'
b'explorer.exe'
