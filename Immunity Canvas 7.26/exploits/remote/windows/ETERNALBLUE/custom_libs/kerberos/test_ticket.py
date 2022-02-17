#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_ticket.py
## Description:
##            :
## Created_On :  Mon Dec  8 22:49:19 PST 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import sys
import logging
from ccache import CCache
from ticket import Ticket, CCacheTGT, MODE_TICKET, MODE_TGT

ccache_ms14_068  = '0504000c000100080000000100000000000000010000000100000009494d4d55'
ccache_ms14_068 += '382e434f4d000000056a6f6a6f31000000010000000100000009494d4d55382e'
ccache_ms14_068 += '434f4d000000056a6f6a6f31000000010000000200000009494d4d55382e434f'
ccache_ms14_068 += '4d000000066b726274677400000009494d4d55382e434f4d001700000010c110'
ccache_ms14_068 += '14338deab26f6c2f3121691059ba587564c0587564c05875f160587e9f400050'
ccache_ms14_068 += 'a0000000000000000000000000038b6182038730820383a003020105a10b1b09'
ccache_ms14_068 += '494d4d55382e434f4da21e301ca003020101a11530131b066b72627467741b09'
ccache_ms14_068 += '494d4d55382e434f4da382034d30820349a003020117a103020105a282033b04'
ccache_ms14_068 += '820337a2b47947b3fc5fae8c07ca71428a3f52fac537fb442d57e4b711c84f8e'
ccache_ms14_068 += '313d121710dc5d0d8c598b064c101a414dc893178e80e3bb48b9c536ca781b71'
ccache_ms14_068 += '8d48afc26545f1c4347995630bfbadb7ba57940a78b6d882e2edd2246498dfa7'
ccache_ms14_068 += 'dc68204498adbbc453f893c9143cf5accd67b704001f0828826eefe47a3dd6cb'
ccache_ms14_068 += '71744c0a874b09f640be29b34fcc698e24dc90731313c1a8e5e6f5ddd751625e'
ccache_ms14_068 += '8a084586ce7f27c620939c463f7577760b3d70d6045eac6c9acebbf034c7a507'
ccache_ms14_068 += '1f9bafa25a732f884437f44a786a7c6ab3361dbfb12d96067fea38e36bd3dfa6'
ccache_ms14_068 += 'eb0c96e5e91523d2f73abe906435ed4293d0c728a624e8a41c45c2f4336e5df2'
ccache_ms14_068 += '0e87d926ad6970c53347e7174c60756b4386ddab6ea9d1910d0f4752e8b498dd'
ccache_ms14_068 += '2fffc3c12d95c698aeb12ae33922efa9973a243528ccf7a210e3716e52f602c7'
ccache_ms14_068 += '27117f6335da0d2b6167f8b49d564ac56ef4fa9cf1dce28d8f7eaff18757cebb'
ccache_ms14_068 += '157904a7cf8e1d2e98dd533f9bdd1e2f4152bd73de1891251e6c2cce7167a512'
ccache_ms14_068 += 'a80b486465e804d9171e8aa8e00ab88ed8afcc54649b27ecce680918c8db61cb'
ccache_ms14_068 += '65bee4a1d5467569bc4125763ac05d362a12d2e02ab5ab4096aa8220ece9eee4'
ccache_ms14_068 += 'a7cd93354a00e9e85571f1bb9b53b90f219f4289285bfe58fe5a0d31d4679e8c'
ccache_ms14_068 += '692e005e44f13750f051600b9c24638e7c1df42ebe81306e3128624ed348d092'
ccache_ms14_068 += 'c1fc5b51c8c7c9f64f6d1195c9be43f1e6c62930721a5d48f0d8c144d208eb61'
ccache_ms14_068 += 'c646ad2d9a9c7e36c7aaa4c4f1d199a162ec340f7f8561b1b97e77f45ac9bf56'
ccache_ms14_068 += 'c9879904fb2067f3e128a385f39998de4b830621d01c4b53dacbfb984ee1ddc3'
ccache_ms14_068 += '3a94fc06667518bdd6ece5573fefbaa5545e19c6e14ed052d67aa790290d8f00'
ccache_ms14_068 += 'e9a719d25b08ebb9d3573200fee7f68d6e4d78a245c5cdf10e5c53c3595b0594'
ccache_ms14_068 += '5a65fc32f3eafb2a70882ecae45276b4f1efcb09af7b63f1d23c434400fa4352'
ccache_ms14_068 += 'c94a2d950725736c5c2aa95445eecc7e9f1c4ce7a9bd3e9073957d99cd0735b9'
ccache_ms14_068 += 'ba15c65d9224b66e64990ae3ec4fff96930742c8ca95a782d0ffb29f3f4517d8'
ccache_ms14_068 += '632db2ea4984a27dcf1be25c094e22bce3eba50c1b415a1eb6377774d30c8634'
ccache_ms14_068 += '3b57b413933b7a10b694945a7e7aa5245407e7a5bef4eb919ac600000000'

USER = "jojo1"
DOMAIN = "IMMU8.COM"
KRBTGT_NTLM = 'd15202a5a4e680322fb5b63ccc71c9f9'

def test_ticket_ms14_068():
    try:
        cc1 = CCache()
        cc1.set_raw_data(ccache_ms14_068.decode('hex'))
        raw_ticket = cc1.get_ticket('krbtgt/%s@%s' % (DOMAIN, DOMAIN))
        if not raw_ticket:
            logging.error('No ticket found!')
            return False

        tktobj = Ticket(raw_ticket)
        enc_tgt = tktobj.get_encrypted_data()
        enc_tgt_type = tktobj.get_encryption_type()

        tgtobj = CCacheTGT()
        tgtobj.set_ciphertext(enc_tgt)
        tgtobj.set_key([enc_tgt_type, KRBTGT_NTLM.decode('hex')])
        tgtobj.set_mode(MODE_TGT)
        clear_tgt = tgtobj.decrypt()

        if USER in clear_tgt:
            return True
        else:
            return False

    except Exception as e:
        logging.error(e)
        return False

def main():

    logging.basicConfig(level=logging.INFO)

    if test_ticket_ms14_068():
        logging.info("Success!")
    else:
        logging.error("Failed!")

if __name__ == "__main__":
    main()
