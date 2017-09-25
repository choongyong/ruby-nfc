require '../lib/ruby-nfc.rb'
require 'logger'

$logger = Logger.new(STDOUT)

def p(str)
  $logger.debug str
end

def set_flag(name, value)
  LibNFC.nfc_device_set_property_bool(@ptr, name, value)
end

p "Library version: #{NFC.version}"
readers = NFC::Reader.all
p "Available readers: #{readers}"

reader = readers[0]

reader = reader.connect
@ptr = reader.ptr
LibNFC.nfc_initiator_init(@ptr)
set_flag(:NP_ACTIVATE_FIELD, false)
set_flag(:NP_HANDLE_CRC, true)
set_flag(:NP_HANDLE_PARITY, true)
set_flag(:NP_AUTO_ISO14443_4, true)
set_flag(:NP_ACTIVATE_FIELD, true)

modulation = LibNFC::Modulation.new
modulation[:nmt] = :NMT_ISO14443A
modulation[:nbr] = :NBR_106
targets = FFI::MemoryPointer.new(:uchar, LibNFC::Target.size * 10)
res = LibNFC.nfc_initiator_list_passive_targets(@ptr, modulation, targets, 10)

p res

if res > 0
  target = LibNFC::Target.new(targets)
  tag=Mifare::Desfire::Tag.new(target, reader)

  p tag
  p tag.name

  p Mifare.mifare_desfire_connect(tag.pointer)

  data_ptr = FFI::MemoryPointer.new(:uchar, LibNFC::MIFAREDESFireVersionInfo.size)
  res = Mifare.mifare_desfire_get_version(tag.pointer, data_ptr)
  p res
  p LibNFC::MIFAREDESFireVersionInfo.size
  info = LibNFC::MIFAREDESFireVersionInfo.new(data_ptr)
  p "Software Major Version 0x%02x" % info[:software][:version_major]

  uid = (0..info[:uid].size-1).each.map {|i| info[:uid][i].to_s(16).rjust(2, '0')}.join
  p "UID: #{uid}"
  batch_number = (0..info[:batch_number].size-1).each.map {|i| info[:batch_number][i].to_s(16).rjust(2, '0')}.join
  p "Batch_number: #{batch_number}"
  p info[:production_week].to_s(16)
  p info[:production_year].to_s(16)

  key_data_picc = FFI::MemoryPointer.new(:uint8, 8)
  key_data_picc.put_array_of_uint8 0, [0,0,0,0,0,0,0,0]
  #key_picc = FFI::MemoryPointer.new(:uchar, LibNFC::MifareDESFireKey.size)
  key_picc = Mifare.mifare_desfire_des_key_new_with_version(key_data_picc)
  p key_picc
  res = Mifare.mifare_desfire_authenticate(tag.pointer, 0, key_picc)
  p res

  oo = FFI::MemoryPointer.new(:pointer, 1)
  res = Mifare.mifare_desfire_get_card_uid(tag.pointer, oo)
  p res
  strPtr = oo.read_pointer()

  aa = strPtr.null? ? nil : strPtr.read_string()
#  uid = (0..aa.size-1).each.map {|i| aa[i].to_s.rjust(2, '0')}.join

  p "Actual UID #{aa}"
  Mifare.mifare_desfire_disconnect(tag.pointer)
end