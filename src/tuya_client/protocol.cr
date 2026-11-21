module Tuya
  # :nodoc:
  class Protocol
    enum Command : UInt32
      SessionStart    = 0x03
      SessionResponse = 0x04
      SessionFinish   = 0x05
      Control         = 0x07
      Status          = 0x08
      Heartbeat       = 0x09
      Query           = 0x0a
      ControlNew      = 0x0d
      QueryNew        = 0x10
      Refresh         = 0x12

      def version_header? : Bool
        control? || control_new? || status?
      end
    end

    record Reply, command : UInt32, code : UInt32, payload : Bytes

    private HEADER_SIZE = 15

    @key : Bytes
    @local_key : Bytes
    @sequence = 0_u32

    def initialize(@version : Version, local_key : Bytes)
      @local_key = @key = local_key
      @format = case @version
                when .v35? then FrameFormat::GCM
                when .v34? then FrameFormat::HMAC
                else            FrameFormat::CRC
                end
      @version_bytes = @version.to_s.to_slice
    end

    def negotiate(io : IO) : Nil
      nonce = Random::Secure.random_bytes(16)
      send(io, Command::SessionStart, nonce)
      response = receive(io)
      unless response.command == Command::SessionResponse.value && response.code.zero? && response.payload.size >= 48
        raise ProtocolError.new("Invalid Tuya session negotiation response")
      end

      remote_nonce = response.payload[0, 16]
      proof = response.payload[16, 32]
      unless Crypto.equal?(Crypto.hmac(@local_key, nonce), proof)
        raise ProtocolError.new("Tuya session negotiation failed nonce verification")
      end

      send(io, Command::SessionFinish, Crypto.hmac(@local_key, remote_nonce))
      mixed = Bytes.new(16) { |i| nonce[i] ^ remote_nonce[i] }
      @key = if @version.v35?
               Crypto.gcm_encrypt(mixed, @local_key, nonce[0, 12])[0]
             else
               Crypto.ecb(mixed, @local_key, encrypt: true, padding: false)
             end
    end

    def send(io : IO, command : Command, data : Bytes = Bytes.empty) : Nil
      @sequence &+= 1_u32
      payload = encode_payload(command, data)
      packet = Frame.new(@sequence, command.value, payload).encode(@format, @key)
      io.write(packet)
      io.flush
    end

    def receive(io : IO) : Reply
      frame = Frame.read(io, @format, @key, allow_zero_crc: @version.v31?)
      body = frame.payload
      # Some firmware omits the return code in empty ACKs or legacy responses.
      if body.empty?
        return Reply.new(frame.command, 0_u32, body)
      end

      code = 0_u32
      if return_code?(body)
        code = Frame.uint32(body)
        body = body[4..]
      end
      body = decode_payload(body, frame.command) unless body.empty?
      Reply.new(frame.command, code, body)
    end

    private def return_code?(body : Bytes) : Bool
      return false if body.size < 4
      return true if body.size == 4 || @version.v35?
      return body.size % 16 == 4 if @version.v34?
      return body[0] == 0 if @version.v31?

      # Legacy ECB replies can omit the return code. A bare ciphertext is
      # block-aligned, even if its first byte happens to be zero.
      return false if body.size % 16 == 0 || version_header?(body)

      body[0] == 0 || (body[0] != '{'.ord && body.size % 16 == 4)
    end

    private def encode_payload(command : Command, data : Bytes) : Bytes
      if @version.v31?
        return data unless command.control?

        encoded = Base64.strict_encode(Crypto.ecb(data, @key, encrypt: true))
        return ("3.1" + legacy_signature(encoded) + encoded).to_slice
      end

      header = command.version_header? ? version_header : Bytes.empty
      if @version.v35?
        header + data
      elsif @version.v34?
        Crypto.ecb(header + data, @key, encrypt: true)
      elsif data.empty?
        data
      else
        header + Crypto.ecb(data, @key, encrypt: true)
      end
    end

    private def decode_payload(data : Bytes, command : UInt32) : Bytes
      if @version.v31?
        return data unless data[0, @version_bytes.size]? == @version_bytes
        raise ProtocolError.new("Truncated Tuya 3.1 signature") if data.size < 19

        encoded = String.new(data[19..])
        unless Crypto.equal?(data[3, 16], legacy_signature(encoded).to_slice)
          raise ProtocolError.new("Invalid Tuya 3.1 payload signature")
        end
        return Crypto.ecb(Base64.decode(encoded), @key, encrypt: false)
      end

      if @version.session?
        data = Crypto.ecb(data, @key, encrypt: false) if @version.v34?
        command == Command::SessionResponse.value ? data : strip_header(data)
      else
        ciphertext = strip_header(data)
        # Some older firmware returns plaintext JSON or this query error.
        if (ciphertext[0]? == '{'.ord && ciphertext.last? == '}'.ord) ||
           ciphertext == "json obj data unvalid".to_slice
          return ciphertext
        end
        Crypto.ecb(ciphertext, @key, encrypt: false)
      end
    rescue ex : Base64::Error
      raise ProtocolError.new("Invalid Tuya 3.1 base64 payload", cause: ex)
    end

    private def strip_header(data : Bytes) : Bytes
      return data unless version_header?(data)
      raise ProtocolError.new("Truncated Tuya version header") if data.size < HEADER_SIZE

      data[HEADER_SIZE..]
    end

    private def version_header?(data : Bytes) : Bool
      prefix = data[0, 3]?
      prefix == @version_bytes ||
        ((@version.v32? || @version.v33?) && (prefix == "3.2".to_slice || prefix == "3.3".to_slice))
    end

    private def version_header : Bytes
      Bytes.new(HEADER_SIZE).tap(&.copy_from(@version_bytes))
    end

    private def legacy_signature(encoded : String) : String
      digest = Digest::MD5.new
      digest.update("data=#{encoded}||lpv=3.1||")
      digest.update(@key)
      digest.hexfinal[8, 16]
    end
  end
end
