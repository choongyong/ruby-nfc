require_relative './tag'

module Mifare
  # Adding some DESFire related stuff to Mifare module
  
  # tag
  attach_function :mifare_desfire_connect, [:pointer], :int
  # tag
  attach_function :mifare_desfire_disconnect, [:pointer], :int
  
  attach_function :mifare_desfire_authenticate, [:pointer, :uint8, :pointer], :int

  attach_function :mifare_desfire_get_version, [:pointer, :pointer], :int

  attach_function :mifare_desfire_des_key_new_with_version, [:pointer], :pointer

  attach_function :mifare_desfire_key_free, [:pointer], :void

  attach_function :mifare_desfire_get_card_uid, [:pointer, :pointer], :int

  module Desfire
    class Tag < Mifare::Tag
      def initialize(target, reader)
        super(target, reader)

        @auth_block = nil #last authenticated block
      end

      def connect(&block)
        @reader.set_flag(:NP_AUTO_ISO14443_4, false)

        res = Mifare.mifare_desfire_connect(@pointer)
        if 0 == res 
          super
        else
          raise Mifare::Error, "Can't connect to tag: #{res}"
        end
      end

      def disconnect
        Mifare.mifare_desfire_disconnect(@pointer)
        super
      end

      def get_version()
        data_ptr = FFI::MemoryPointer.new(:uchar, 28)
        res = Mifare.mifare_desfire_get_version(@pointer, data_ptr)

        raise Mifare::Error, "Can't read block 0x%02x" % block_num if 0 != res

        data_ptr.get_bytes(0, 28).force_encoding("ASCII-8BIT")
      end

      # returns only value part of value block
      def value(block_num = nil)
        v, _ = value_with_addr(block_num)
        v
      end



      # Check's if our tag class is able to handle this LibNFC::Target
      def self.match?(target)
        keys = [:DESFIRE_EV1]

        Mifare::SAKS.values_at(*keys).include? target.sak
      end
    end
  end
end
