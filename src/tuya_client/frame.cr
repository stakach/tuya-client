module Tuya
  # :nodoc:
  enum FrameFormat
    CRC
    HMAC
    GCM
  end

  # :nodoc:
  record Frame, sequence : UInt32, command : UInt32, payload : Bytes do
    PREFIX_55AA = 0x000055aa_u32
    PREFIX_6699 = 0x00006699_u32

    private SUFFIX_55AA = 0x0000aa55_u32
    private SUFFIX_6699 = 0x00009966_u32
    private MAX_BODY    = 64 * 1024
    private IV_SIZE     = 12
    private TAG_SIZE    = 16
    private ORDER       = IO::ByteFormat::BigEndian

    def encode(format : FrameFormat, key : Bytes, *, iv : Bytes? = nil) : Bytes
      gcm = format.gcm?
      overhead = self.class.overhead(format)
      length = @payload.size + overhead
      raise ProtocolError.new("Tuya frame payload is too large") if length > MAX_BODY

      io = IO::Memory.new
      io.write_bytes(gcm ? PREFIX_6699 : PREFIX_55AA, ORDER)
      io.write_bytes(0_u16, ORDER) if gcm
      io.write_bytes(@sequence, ORDER)
      io.write_bytes(@command, ORDER)
      io.write_bytes(length.to_u32, ORDER)

      if gcm
        nonce = iv || Random::Secure.random_bytes(IV_SIZE)
        aad = io.to_slice[4..]
        ciphertext, tag = Crypto.gcm_encrypt(@payload, key, nonce, aad)
        io.write(nonce)
        io.write(ciphertext)
        io.write(tag)
        io.write_bytes(SUFFIX_6699, ORDER)
      else
        io.write(@payload)
        if format.hmac?
          io.write(Crypto.hmac(key, io.to_slice))
        else
          io.write_bytes(Digest::CRC32.checksum(io.to_slice), ORDER)
        end
        io.write_bytes(SUFFIX_55AA, ORDER)
      end
      io.to_slice
    end

    def self.read(io : IO, format : FrameFormat, key : Bytes, *, allow_zero_crc : Bool = false) : self
      gcm = format.gcm?
      header_size = gcm ? 18 : 16
      header = Bytes.new(header_size)
      io.read_fully(header)
      expected_prefix = gcm ? PREFIX_6699 : PREFIX_55AA
      raise ProtocolError.new("Invalid Tuya frame prefix") unless uint32(header) == expected_prefix

      sequence = uint32(header, header_size - 12)
      command = uint32(header, header_size - 8)
      length = uint32(header, header_size - 4)
      overhead = overhead(format)
      unless overhead <= length <= MAX_BODY
        raise ProtocolError.new("Invalid Tuya frame length: #{length}")
      end

      body = Bytes.new(length.to_i + (gcm ? 4 : 0))
      io.read_fully(body)
      expected_suffix = gcm ? SUFFIX_6699 : SUFFIX_55AA
      raise ProtocolError.new("Invalid Tuya frame suffix") unless uint32(body, body.size - 4) == expected_suffix

      payload_size = length.to_i - overhead
      payload = if gcm
                  iv = body[0, IV_SIZE]
                  ciphertext = body[IV_SIZE, payload_size]
                  tag = body[IV_SIZE + payload_size, TAG_SIZE]
                  Crypto.gcm_decrypt(ciphertext, key, iv, header[4..], tag)
                else
                  legacy_payload(header, body, payload_size, format, key, allow_zero_crc)
                end

      new(sequence, command, payload)
    end

    private def self.legacy_payload(header : Bytes, body : Bytes, payload_size : Int32, format : FrameFormat,
                                    key : Bytes, allow_zero_crc : Bool) : Bytes
      payload = body[0, payload_size]
      if format.hmac?
        expected = Crypto.hmac(key, header + payload)
        unless Crypto.equal?(expected, body[payload_size, expected.size])
          raise ProtocolError.new("Invalid Tuya frame HMAC")
        end
      else
        checksum = uint32(body, payload_size)
        unless (allow_zero_crc && checksum.zero?) || checksum == Digest::CRC32.checksum(header + payload)
          raise ProtocolError.new("Invalid Tuya frame CRC")
        end
      end
      payload
    end

    def self.uint32(bytes : Bytes, offset : Int32 = 0) : UInt32
      ORDER.decode(UInt32, bytes[offset, 4])
    end

    protected def self.overhead(format : FrameFormat) : Int32
      case format
      when .gcm?  then IV_SIZE + TAG_SIZE
      when .hmac? then 36
      else             8
      end
    end
  end
end
