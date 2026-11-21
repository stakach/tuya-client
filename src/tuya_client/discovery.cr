module Tuya
  module Discovery
    private PORTS             = {6666, 6667, 7000}
    private REQUEST_PORT      = 7000
    private BIND_ADDRESS      = "0.0.0.0"
    private BROADCAST_ADDRESS = "255.255.255.255"
    private KEY               = Digest::MD5.digest("yGAdlopoPVldABfn")

    record Device, id : String, ip : String, version : Version, product_key : String? do
      def client(local_key : String, **options) : Client
        Client.new(@ip, @id, local_key, **options, version: @version)
      end
    end

    # Listens for announcements and returns one device per ID.
    # Supply this machine's LAN IPv4 address to solicit 3.5 announcements.
    def self.scan(timeout : Time::Span = 5.seconds, *, local_ip : String? = nil,
                  broadcast_address : String = BROADCAST_ADDRESS) : Array(Device)
      raise ArgumentError.new("Tuya discovery timeout must be positive") unless timeout > Time::Span.zero

      sockets = [] of UDPSocket
      PORTS.each do |port|
        socket = UDPSocket.new
        sockets << socket
        socket.reuse_address = true
        socket.bind(BIND_ADDRESS, port)
        solicit(socket, local_ip, broadcast_address) if port == REQUEST_PORT && local_ip
      end

      results = Channel(Hash(String, Device) | IO::Error | Socket::Error).new(sockets.size)
      deadline = Time.instant + timeout
      sockets.each do |socket|
        spawn do
          results.send(listen(socket, deadline))
        rescue ex : IO::Error | Socket::Error
          results.send(ex)
        end
      end

      devices = {} of String => Device
      sockets.size.times do
        case result = results.receive
        when Exception
          raise result
        else
          devices.merge!(result)
        end
      end
      devices.values.sort_by!(&.id)
    rescue ex : IO::Error | Socket::Error
      raise ConnectionError.new("Tuya discovery failed: #{ex.message}", cause: ex)
    ensure
      sockets.try &.each(&.close)
    end

    # Decodes a single UDP announcement, returning nil for invalid or unsupported packets.
    def self.decode(packet : Bytes) : Device?
      payload = decode_payload(packet)
      return unless payload

      json = JSON.parse(String.new(payload).strip('\0')).as_h?
      return unless json

      id = json["gwId"]?.try(&.as_s?)
      ip = json["ip"]?.try(&.as_s?)
      version = json["version"]?.try(&.as_s?)
      return unless id && ip && version
      return if id.empty? || !Socket::IPAddress.valid?(ip)

      Device.new(id, ip, Version.parse(version), json["productKey"]?.try(&.as_s?))
    rescue ProtocolError | IO::EOFError | JSON::ParseException | ArgumentError
      nil
    end

    private def self.decode_payload(packet : Bytes) : Bytes?
      return if packet.size < 4

      format = case Frame.uint32(packet)
               when Frame::PREFIX_55AA then FrameFormat::CRC
               when Frame::PREFIX_6699 then FrameFormat::GCM
               else                         return Crypto.ecb(packet, KEY, encrypt: false)
               end
      io = IO::Memory.new(packet)
      payload = Frame.read(io, format, KEY, allow_zero_crc: true).payload
      return unless io.pos == packet.size

      # Announcements can be bare payloads or carry a four-byte return code.
      payload = payload[4..] if payload[0, 3]? == Bytes[0, 0, 0] && payload.size >= 4
      if format.crc? && payload[0]? != '{'.ord
        Crypto.ecb(payload, KEY, encrypt: false)
      else
        payload
      end
    end

    private def self.listen(socket : UDPSocket, deadline : Time::Instant) : Hash(String, Device)
      buffer = Bytes.new(65_507)
      found = {} of String => Device
      loop do
        remaining = deadline - Time.instant
        break unless remaining > Time::Span.zero

        socket.read_timeout = remaining
        begin
          size, _ = socket.receive(buffer)
        rescue IO::TimeoutError
          break
        end
        if device = decode(buffer[0, size])
          found[device.id] = device
        end
      end
      found
    end

    private def self.solicit(socket : UDPSocket, local_ip : String, broadcast_address : String) : Nil
      if local_ip.includes?(':') || !Socket::IPAddress.valid?(local_ip)
        raise ArgumentError.new("Tuya discovery local_ip must be an IPv4 address")
      end

      destination = Socket::IPAddress.new(broadcast_address, REQUEST_PORT)
      request = {from: "app", ip: local_ip}.to_json
      packet = Frame.new(1_u32, 0x25_u32, request.to_slice).encode(FrameFormat::GCM, KEY)
      socket.broadcast = true
      socket.send(packet, to: destination)
    end
  end
end
