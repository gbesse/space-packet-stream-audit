import unittest,struct
from space_packet_stream_audit import run

def packet(apid,seq,payload=b'x',kind=0):return struct.pack('>HHH',apid|(kind<<12),0xc000|seq,len(payload)-1)+payload
class Tests(unittest.TestCase):
 def test_wrap_gap_and_per_apid(self):
  raw=packet(1,16383)+packet(2,7)+packet(1,0)+packet(1,3)
  r=run({'hex':raw.hex()});self.assertTrue(r['complete_primary_framing']);self.assertEqual(r['packets'][2]['sequence_relation'],'consecutive_modulo');self.assertEqual(r['packets'][3]['conditional_missing_count'],2)
 def test_truncations_keep_offsets(self):
  raw=packet(1,0)
  for n in range(1,len(raw)):
   r=run({'hex':raw[:n].hex()});self.assertFalse(r['complete_primary_framing']);self.assertEqual(r['findings'][0]['offset'],0)
 def test_reset_and_telecommand_are_not_loss_proofs(self):
  r=run({'hex':(packet(3,100)+packet(3,1)+packet(4,9,kind=1)).hex()});self.assertEqual(r['packets'][1]['sequence_relation'],'reorder_reset_or_large_gap_ambiguous');self.assertNotIn('conditional_missing_count',r['packets'][1]);self.assertIn('not_inferred',r['packets'][2]['sequence_relation'])
 def test_full_payload_lengths_native_packer(self):
  for size in [1,2,255,256,65536]:
   r=run({'hex':packet(7,11,b'a'*size).hex()});self.assertTrue(r['complete_primary_framing']);self.assertEqual(r['consumed_bytes'],size+6)
 def test_idle_and_empty(self):
  self.assertEqual(run({'hex':packet(2047,0).hex()})['packets'][0]['sequence_relation'],'idle_not_inferred');self.assertTrue(run({'hex':''})['complete_primary_framing'])
