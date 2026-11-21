require "./spec_helper"

private LOCAL_KEY    = "0123456789abcdef".to_slice
private REMOTE_NONCE = "3.4abcdefghijklmn"[0, 16].to_slice
private RETCODE      = Bytes.new(4)

private def session_payload(payload : Bytes, format : Tuya::FrameFormat, key : Bytes, *, encrypt : Bool) : Bytes
  format.hmac? ? Tuya::Crypto.ecb(payload, key, encrypt: encrypt) : payload
end

private def device_session(socket : TCPSocket, format : Tuya::FrameFormat, *, correct_proof : Bool = true) : Bytes?
  start = Tuya::Frame.read(socket, format, LOCAL_KEY)
  return unless start.command == 3

  nonce = session_payload(start.payload, format, LOCAL_KEY, encrypt: false)
  proof = correct_proof ? Tuya::Crypto.hmac(LOCAL_KEY, nonce) : Bytes.new(32)
  response = RETCODE + session_payload(REMOTE_NONCE + proof, format, LOCAL_KEY, encrypt: true)
  socket.write(Tuya::Frame.new(101_u32, 4_u32, response).encode(format, LOCAL_KEY))
  return unless correct_proof

  finish = Tuya::Frame.read(socket, format, LOCAL_KEY)
  return unless finish.command == 5

  finish_proof = session_payload(finish.payload, format, LOCAL_KEY, encrypt: false)
  return unless finish_proof == Tuya::Crypto.hmac(LOCAL_KEY, REMOTE_NONCE)

  mixed = Bytes.new(16) { |i| nonce[i] ^ REMOTE_NONCE[i] }
  if format.gcm?
    Tuya::Crypto.gcm_encrypt(mixed, LOCAL_KEY, nonce[0, 12])[0]
  else
    Tuya::Crypto.ecb(mixed, LOCAL_KEY, encrypt: true, padding: false)
  end
end

describe "Tuya session negotiation" do
  {"3.4" => Tuya::FrameFormat::HMAC, "3.5" => Tuya::FrameFormat::GCM}.each do |version, format|
    it "uses a negotiated #{version} key for the next command" do
      server = TCPServer.new("127.0.0.1", 0)
      spawn do
        server.accept do |socket|
          socket.read_timeout = 1.second
          if key = device_session(socket, format)
            request = Tuya::Frame.read(socket, format, key)
            if request.command == 16
              status = %({"data":{"dps":{"1":true}}}).to_slice
              response = RETCODE + session_payload(status, format, key, encrypt: true)
              socket.write(Tuya::Frame.new(102_u32, 16_u32, response).encode(format, key))
            end
          end
        end
      end

      client = Tuya::Client.new("127.0.0.1", "device", String.new(LOCAL_KEY), version: version,
        port: server.local_address.port, timeout: 1.second)
      begin
        client.on?.should be_true
      ensure
        client.close
        server.close
      end
    end
  end

  it "rejects an invalid proof before establishing the session" do
    server = TCPServer.new("127.0.0.1", 0)
    spawn do
      server.accept { |socket| device_session(socket, Tuya::FrameFormat::GCM, correct_proof: false) }
    end

    client = Tuya::Client.new("127.0.0.1", "device", String.new(LOCAL_KEY), version: "3.5",
      port: server.local_address.port, timeout: 1.second)
    begin
      expect_raises(Tuya::ProtocolError, /nonce verification/) { client.connect }
      client.connected?.should be_false
    ensure
      client.close
      server.close
    end
  end
end
