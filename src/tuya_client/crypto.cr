module Tuya
  # :nodoc:
  module Crypto
    private class GCM < OpenSSL::Cipher
      def initialize
        super("aes-128-gcm")
      end

      def associated_data=(data : Bytes) : Nil
        return if data.empty?

        if LibCrypto.evp_cipherupdate(@ctx, nil, out written, data, data.size) != 1
          raise Error.new("Could not set AES-GCM associated data")
        end
      end
    end

    def self.ecb(data : Bytes, key : Bytes, *, encrypt : Bool, padding : Bool = true) : Bytes
      cipher = OpenSSL::Cipher.new("aes-128-ecb")
      encrypt ? cipher.encrypt : cipher.decrypt
      cipher.key = key
      cipher.padding = padding
      cipher.update(data) + cipher.final
    rescue ex : OpenSSL::Cipher::Error
      raise ProtocolError.new("Invalid Tuya AES-ECB payload", cause: ex)
    ensure
      cipher.try &.finalize
    end

    def self.gcm_encrypt(data : Bytes, key : Bytes, iv : Bytes, aad : Bytes = Bytes.empty) : {Bytes, Bytes}
      cipher = GCM.new
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      cipher.associated_data = aad
      ciphertext = cipher.update(data) + cipher.final
      {ciphertext, cipher.gcm_tag}
    ensure
      cipher.try &.finalize
    end

    def self.gcm_decrypt(data : Bytes, key : Bytes, iv : Bytes, aad : Bytes, tag : Bytes) : Bytes
      cipher = GCM.new
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      cipher.associated_data = aad
      cipher.gcm_tag = tag
      cipher.update(data) + cipher.final
    rescue ex : OpenSSL::Cipher::Error
      raise ProtocolError.new("Invalid Tuya AES-GCM authentication tag or payload", cause: ex)
    ensure
      cipher.try &.finalize
    end

    def self.hmac(key : Bytes, data : Bytes) : Bytes
      OpenSSL::HMAC.digest(:sha256, key, data)
    end

    def self.equal?(left : Bytes, right : Bytes) : Bool
      return false unless left.size == right.size

      difference = 0_u8
      left.each_with_index do |byte, index|
        difference |= byte ^ right[index]
      end
      difference.zero?
    end
  end
end
