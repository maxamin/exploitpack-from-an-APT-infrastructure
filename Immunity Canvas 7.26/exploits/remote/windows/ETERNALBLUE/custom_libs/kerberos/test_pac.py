#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_pac.py
## Description:
##            :
## Created_On :  Mon Dec  8 22:49:19 PST 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import sys
import logging

if "." not in sys.path:
    sys.path.append(".")

from ccache import CCache
from ticket import Ticket, CCacheTGT, MODE_TICKET, MODE_TGT
from pac import Pac
import helper

'''
mimikatz # lsadump::lsa /name:krbtgt /inject
Domain : IMMU8 / S-1-5-21-1312829957-3779533362-1303910169

RID  : 000001f6 (502)
User : krbtgt

 * Primary
    LM   : 
    NTLM : d15202a5a4e680322fb5b63ccc71c9f9

[...]
 * Kerberos
    Default Salt : IMMU8.COMkrbtgt
    Credentials
      des_cbc_md5       : 0decf4b5431a02ec
    OldCredentials
      des_cbc_md5       : 944a0734e007459d

 * Kerberos-Newer-Keys
    Default Salt : IMMU8.COMkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 8578fcf78a3b3a4bf4a6eb9d1067f83256938a0866e21f484b61611c0b71769d
      aes128_hmac       (4096) : cc1295ff91fa7e69e2fb54f463798bb9
      des_cbc_md5       (4096) : 0decf4b5431a02ec'
'''

# AES-256 ccache file
ccache_aes_256  = '0504000c000100080000000400000000000000010000000100000009494d4d55'
ccache_aes_256 += '382e434f4d0000000d61646d696e6973747261746f7200000001000000010000'
ccache_aes_256 += '0009494d4d55382e434f4d0000000d61646d696e6973747261746f7200000002'
ccache_aes_256 += '0000000200000009494d4d55382e434f4d000000066b72627467740000000949'
ccache_aes_256 += '4d4d55382e434f4d0017000000103dac8431a3d5af0d13ec29319e84627d586c'
ccache_aes_256 += 'f7c0586cf7c0586d8460586e493e0000e0000000000000000000000000041761'
ccache_aes_256 += '8204133082040fa003020105a10b1b09494d4d55382e434f4da21e301ca00302'
ccache_aes_256 += '0102a11530131b066b72627467741b09494d4d55382e434f4da38203d9308203'
ccache_aes_256 += 'd5a003020112a103020105a28203c7048203c333c23be90b2706625fadb22243'
ccache_aes_256 += '1f5060a70a489feb120edf81ccba3539d2a08f5aac41958bdca83290c88a2898'
ccache_aes_256 += '28559d15b24b21324318a0ad6c56f93a0b50f39ee25f8c3d40090d21cfb62209'
ccache_aes_256 += '3fcac02ae3ddc58bdd044b7cb3b5d52028bb04bd47a3d79ca1c2ce1aa491a790'
ccache_aes_256 += 'eb6d52e07b097427165cfd7c2a573b4fab5eef1486ac58aa5fa55807d98a2ed6'
ccache_aes_256 += '677f064ad04a5dc53cf58e22ce6dee31d272ba6bde1d3a7ec64c5b470e9ed516'
ccache_aes_256 += '3262509e93039419663cdabc9be5606c159d34acc7418374cc78688e7270634d'
ccache_aes_256 += '380bc2010c5c612c0ba437c7773723c88764d5af858ff4c73224ff5b75bea72e'
ccache_aes_256 += 'f2ed8f8de1aeeef491cccfc850f9ca4c2aa22004c18c96450507f31b180fdee7'
ccache_aes_256 += '8304c71b9321da5b0bf701b1ddded00242e60101d43d26ab2413dbf6598a83b7'
ccache_aes_256 += '4a4304b31ed0e7949d7ae6f83cf96b331d4321fcefeb6a47525178dcea5df723'
ccache_aes_256 += 'd2f6113669d49e8091c66700180c4b14eff7079cc341f32aa685a3f25680310b'
ccache_aes_256 += 'c20c2e33f9811cd2bc8ba080858414581eec9935b55d268b03a4b30aaf5ce613'
ccache_aes_256 += '9a75fd7407d8c24684e74d8d95e3681c16f877e6abb13737e5386b97fbc4705d'
ccache_aes_256 += '33ae5a36276271a6fe919721943026a024e0087e59a89d6f501c192633c8028d'
ccache_aes_256 += '0e1c8614e1eb54b126614a78e41b78ea5c78c5453778ab2e0a313e8f67532b52'
ccache_aes_256 += '0a4be90c86d602ee5a35a73d2c360fef38832bad446e18c1bb0892b8175b9892'
ccache_aes_256 += '4b1941a0ce863b006b638f0ddf19b22799bdf8fbdcba82cc4bcaf437268d0e62'
ccache_aes_256 += '661448dd02c98b20a0a7c27f620a945ca4a25e7081b88edb836fb967743af097'
ccache_aes_256 += '9610f0a2f05606b92b0784a128cffbccee3f2f759bd2d115653b8dfe8a737421'
ccache_aes_256 += '25def2f1a920c1efca230de30a039bcf6ec56322b067417d5e26e86f0178ff7b'
ccache_aes_256 += '9f3c1997b03d01bc11765d91ad31276eb61ffe41e41ab2493c7f42bcb8bfa489'
ccache_aes_256 += '5675d83a8c9b1e8332d8ecbc273205aa3f8819248c57bbbbaf1efe391ff2e655'
ccache_aes_256 += 'b0af2da1a1c11442bfbe48fa98e99ff565daae5281bc8fdea813016b541bb5d5'
ccache_aes_256 += 'eda0a5d128eb022e76d000a4ef13db71a3f36782359627cac4d45052b8c6937f'
ccache_aes_256 += '6daa3bc6b51e00775db6a5d6c01e0c77c3239521b759d97722fd8a3259f06a15'
ccache_aes_256 += '612a9f1b6b437ba73a0f23e3241b4fbd3a3cbb71b80ad790d84e4713f051e088'
ccache_aes_256 += '4d4d914c05c469685e6a147419deb18d7502760409f2822182038d046e3aa6d9'
ccache_aes_256 += 'e7de5abed8df23e4bbda6cb8139d9a6cba22f9e98a5580557d213b64572fc501'
ccache_aes_256 += '25b9f49bc00d8d6ca491331e85c7d3b670a5791317640b9b8565cb21b65a6041'
ccache_aes_256 += '961c86fd770a5153f3c1f8a23f26093e03a9fba05e5600000000000000010000'
ccache_aes_256 += '000100000009494d4d55382e434f4d0000000d61646d696e6973747261746f72'
ccache_aes_256 += '00000000000000030000000c582d4341434845434f4e463a000000156b726235'
ccache_aes_256 += '5f6363616368655f636f6e665f646174610000000770615f747970650000001a'
ccache_aes_256 += '6b72627467742f494d4d55382e434f4d40494d4d55382e434f4d000000000000'
ccache_aes_256 += '0000000000000000000000000000000000000000000000000000000000000000'
ccache_aes_256 += '013200000000'

# RC4 ccache file
ccache_rc4  = '0504000c000100080000000300000000000000010000000100000009494d4d55'
ccache_rc4 += '392e434f4d0000000d61646d696e6973747261746f7200000001000000010000'
ccache_rc4 += '0009494d4d55392e434f4d0000000d61646d696e6973747261746f7200000002'
ccache_rc4 += '0000000200000009494d4d55392e434f4d000000066b72627467740000000949'
ccache_rc4 += '4d4d55392e434f4d001700000010afb23a71dc2b43fb9b708f538eafc871586c'
ccache_rc4 += 'c92b586cc92b586d55cb586e1aa80000e000000000000000000000000003b361'
ccache_rc4 += '8203af308203aba003020105a10b1b09494d4d55392e434f4da21e301ca00302'
ccache_rc4 += '0102a11530131b066b72627467741b09494d4d55392e434f4da3820375308203'
ccache_rc4 += '71a003020117a10302010aa28203630482035fd1079af8a22c366bc4b23ebec5'
ccache_rc4 += '5f32ac3811619c09ff277f24bafa0b2a2270f1facfba62000bd742a731d1b5d8'
ccache_rc4 += '1d7d328f3749fdf2a150266cbeb99eca401a4dee3d5136048444efce000ce12d'
ccache_rc4 += '89cda9954d056cf4b725e82c2e8701d65d13d698298717d9237be39a1d233779'
ccache_rc4 += 'a92af74e415076976be90f75207648f2954397f4638823501916553c606e5f7a'
ccache_rc4 += 'f8fbdc95ff2c87363d3c4452bbfd5409d717193e247dfa2f1c3b1cb83221737e'
ccache_rc4 += 'e754a8cbc2dc6fbc4965c39ad762d1141efd4670a9a48f229aa8825282a6c26d'
ccache_rc4 += 'ff4691d5d66de164f29be203b4677db60b573dd1fe0d2e46962ee074edd3193a'
ccache_rc4 += '1e2793769c91bf42a5a79b979dc4ebba257f25b5329805eecdc023b8880934c7'
ccache_rc4 += 'cd67798d12178a9ebf2aab304ebad38098db40be1bc374de4e5e8b25268b5d2f'
ccache_rc4 += '49b953414e8624050091b39cb29a7e11f9345c607bbe8ab7c76a5a22ad4cbb85'
ccache_rc4 += 'fb335f8cfd36c0a727db8d7e3dc83114c3f26f65f78a61e378f695241bd561c5'
ccache_rc4 += '6342de862c1dbf31b68723546efe74efd67a7a9da46d0af999c7ef4627f65e2a'
ccache_rc4 += 'ea03e3d3795c2e2c1151a80b2a72c239158f0a56ad1885b8dbb98b7c0246af41'
ccache_rc4 += '80f6a9aece1bf1ed0a8ec514783bc5b32058d206a59282a69a774c0790a82ab6'
ccache_rc4 += '4df7a041d390925af6ba4a0c457114c3a14a2c444c5aee700fbeb6719234b95e'
ccache_rc4 += '220a45dc27284baa3abcfe35c697c8f641f9dcb4dd3a27392a1809a2a7d2f0d3'
ccache_rc4 += 'f8f1e2a93d57291b5b6c0e87b2d4b49e8c0d7c4edaf140b351dea8a1ad120323'
ccache_rc4 += 'f2169885e5cc17a7fc458be477f4cd907152cc05373d37dfc469a20c7b3b73bf'
ccache_rc4 += '37a2ba6072dffaa105870eac164a80b2a0ed07eeb43198ea514d97147a61d268'
ccache_rc4 += '9877a5ee4424a061c80a075c1d9dd4e93b7aa21fdcfc44ed3a9cf19c9f0e9052'
ccache_rc4 += '17a55d913ae73f97343bf0b7b2409109ba174706739ae62e3049614214d59f51'
ccache_rc4 += '261adcdcfebb6f894d6d1e6dfc994ff7396667cda6d5168c4a3c1b63f5bdaed0'
ccache_rc4 += '545851994fa39e270aa93240e02334b8687e0eb4cf406751a3be13622c0e1dd8'
ccache_rc4 += '98b1daab80a645a2c009ad75d314cbb9451b144b28ff3e71ed14e89970b000a2'
ccache_rc4 += 'c3e5567cde89f7f194e9db4782441379a09962e247fa0b8fc40cd4fc15a5a3d4'
ccache_rc4 += '913ac7689c91e92ab09f2ea49fc099364ae52b616c25aa8454855f728f7e249a'
ccache_rc4 += '0309fad35ddf78baa447a0d92ba6f5932b7b0000000000000001000000010000'
ccache_rc4 += '0009494d4d55392e434f4d0000000d61646d696e6973747261746f7200000000'
ccache_rc4 += '000000030000000c582d4341434845434f4e463a000000156b7262355f636361'
ccache_rc4 += '6368655f636f6e665f646174610000000770615f747970650000001a6b726274'
ccache_rc4 += '67742f494d4d55392e434f4d40494d4d55392e434f4d00000000000000000000'
ccache_rc4 += '0000000000000000000000000000000000000000000000000000000001320000'
ccache_rc4 += '0000'

krbtgt_ntlm   = '63fb7d6792655d3167d4bedf2548310b'
krbtgt_aes256 = '8578fcf78a3b3a4bf4a6eb9d1067f83256938a0866e21f484b61611c0b71769d'

test_vectors = [
    ('RC4', ccache_rc4, 'IMMU9.COM', 'Administrator', [helper.ETYPE_ARCFOUR_HMAC_MD5, krbtgt_ntlm.decode('hex')]),
    ('AES256', ccache_aes_256, 'IMMU8.COM', 'Administrator', [helper.ETYPE_AES256_CTS_HMAC_SHA1_96, krbtgt_aes256.decode('hex')]),
]

def test_pac(vec):

    ccache_file = vec[1]
    domain = vec[2]
    username = vec[3]
    passwd = vec[4]

    try:
        cc1 = CCache()
        cc1.set_raw_data(ccache_file.decode('hex'))
        raw_ticket = cc1.get_ticket('krbtgt/%s@%s' % (domain,domain))
        if not raw_ticket:
            return False

        tgtobj = CCacheTGT()
        enc_tgt = Ticket(raw_ticket).get_encrypted_data()
        tgtobj.set_ciphertext(enc_tgt)
        tgtobj.set_key(passwd)
        tgtobj.set_mode(MODE_TGT)
        clear_tgt = tgtobj.decrypt()

        if username.upper() in clear_tgt.upper() or domain.upper() in clear_tgt.upper():
            return True
        else:
            return False

    except Exception as e:
        logging.error(e)
        return False

###
# Main to test the class!
###

def main():

    logging.basicConfig(level=logging.INFO)

    errors=0
    for vec in test_vectors:

        if not test_pac(vec):
            logging.error("Test failed for vector#%s!", vec[0])
            errors += 1

    if not errors:
        logging.info("Success!")

    return

if __name__ == "__main__":
    main()
