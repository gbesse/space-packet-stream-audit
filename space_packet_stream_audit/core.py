import hashlib
from .common import integer

def run(data):
 raw=bytes.fromhex(data['hex']);limit=integer(data.get('max_packets',5000),1,5000)
 if len(raw)>4000000:raise ValueError('stream_size')
 packets=[];findings=[];previous={};offset=0
 while offset<len(raw):
  if len(packets)>=limit:raise ValueError('packet_limit')
  if len(raw)-offset<6:findings.append({'offset':offset,'code':'truncated_primary_header','available':len(raw)-offset});break
  first=int.from_bytes(raw[offset:offset+2],'big');control=int.from_bytes(raw[offset+2:offset+4],'big');length=int.from_bytes(raw[offset+4:offset+6],'big')+1
  if first>>13:findings.append({'offset':offset,'code':'unsupported_packet_version'});break
  if offset+6+length>len(raw):findings.append({'offset':offset,'code':'truncated_data_field','required':length,'available':len(raw)-offset-6});break
  apid=first&2047;kind=(first>>12)&1;sequence=control&16383
  row={'offset':offset,'apid':apid,'packet_type':kind,'secondary_header':bool(first&2048),'sequence_flags':control>>14,'sequence_count':sequence,'data_bytes':length,'data_sha256':hashlib.sha256(raw[offset+6:offset+6+length]).hexdigest()}
  if apid==2047:row['sequence_relation']='idle_not_inferred'
  elif kind:row['sequence_relation']='telecommand_counter_or_name_not_inferred'
  else:
   before=previous.get(apid);row['sequence_relation']='first_observation'
   if before is not None:
    delta=(sequence-before)%16384;row['serial_delta']=delta
    if delta==1:row['sequence_relation']='consecutive_modulo'
    elif delta==0:row['sequence_relation']='repeat_or_full_wrap'
    elif delta<8192:row.update(sequence_relation='forward_gap_candidate',conditional_missing_count=delta-1)
    else:row['sequence_relation']='reorder_reset_or_large_gap_ambiguous'
   previous[apid]=sequence
  packets.append(row);offset+=6+length
 return {'packets':packets,'findings':findings,'complete_primary_framing':offset==len(raw),'consumed_bytes':offset,'total_bytes':len(raw),'sequence_scope':'conditional_serial_arithmetic_not_proven_packet_loss'}
