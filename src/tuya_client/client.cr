module Tuya
  # A synchronous TCP client for a Tuya LAN device.
  class Client
    DEFAULT_PORT = 6668

    getter host : String
    getter device_id : String
    getter version : Version
    getter port : Int32
    getter on_datapoint : String

    @socket : TCPSocket?
    @protocol : Protocol?
    @local_key : Bytes
    @query_datapoints : Array(Int32)?
    @mutex = Mutex.new
    @updates = Datapoints.new

    def initialize(@host : String, @device_id : String, local_key : String,
                   version : Version | String = Version::V33, @port : Int32 = DEFAULT_PORT,
                   @timeout : Time::Span = 5.seconds, on_datapoint : Int32 | String = 1,
                   query_datapoints : Array(Int32)? = nil)
      raise ArgumentError.new("Tuya local key must be 16 bytes") unless local_key.bytesize == 16
      raise ArgumentError.new("Tuya device ID must not be empty") if @device_id.empty?
      raise ArgumentError.new("Tuya timeout must be positive") unless @timeout > Time::Span.zero

      @local_key = local_key.to_slice
      @version = version.is_a?(Version) ? version : Version.parse(version)
      @on_datapoint = on_datapoint.to_s
      @query_datapoints = query_datapoints.try(&.dup) || ([1] if @version.v32?)
    end

    # Opens the TCP connection and negotiates a session key when required.
    # Commands also connect lazily.
    def connect : Nil
      with_connection { }
    end

    def connected? : Bool
      @mutex.synchronize { @socket.try(&.closed?) == false }
    end

    def close : Nil
      @mutex.synchronize { disconnect }
    end

    # Requests the current datapoints. Keys are Tuya datapoint IDs as strings.
    def status : Datapoints
      with_connection do |socket, protocol|
        command, body = status_request
        response = request_status(socket, protocol, command, body)
        if response.payload == "json obj data unvalid".to_slice &&
           @query_datapoints.nil? && (@version.v33? || @version.v34?)
          @query_datapoints = [1]
          command, body = status_request
          response = request_status(socket, protocol, command, body)
        end
        datapoints = extract_datapoints(response.payload)
        # Some legacy firmware returns 1 alongside a successful query payload.
        check_code(response) unless response.code == 1 && datapoints
        datapoints || raise ProtocolError.new("Tuya status response did not contain datapoints")
      end
    end

    def [](datapoint : Int32 | String) : JSON::Any
      status[datapoint.to_s]
    end

    def []=(datapoint : Int32 | String, value) : Nil
      write({datapoint => value})
    end

    # Writes several datapoints in one command.
    def write(datapoints : Hash) : Nil
      return if datapoints.empty?

      values = datapoints.transform_keys(&.to_s)
      time = Time.utc.to_unix
      if @version.session?
        command = Protocol::Command::ControlNew
        body = {protocol: 5, t: time, data: {dps: values}}.to_json
      else
        command = Protocol::Command::Control
        body = {devId: @device_id, uid: "", t: time.to_s, dps: values}.to_json
      end
      with_connection do |socket, protocol|
        protocol.send(socket, command, body.to_slice)
        response = wait_for(socket, protocol, command)
        check_code(response)
      end
    end

    # Reads the configured boolean switch datapoint (ID 1 by default).
    def on? : Bool
      value = self[@on_datapoint].raw
      return value if value.is_a?(Bool)

      raise ProtocolError.new("Tuya datapoint #{@on_datapoint} is not a boolean")
    end

    def on=(value : Bool) : Nil
      self[@on_datapoint] = value
    end

    # Sends a heartbeat and waits for the device to acknowledge it.
    def ping : Nil
      body = {gwId: @device_id, devId: @device_id}.to_json.to_slice
      with_connection do |socket, protocol|
        command = Protocol::Command::Heartbeat
        protocol.send(socket, command, body)
        check_code(wait_for(socket, protocol, command))
      end
    end

    # Asks the device to refresh datapoints such as voltage and current.
    # Devices typically send the values separately as a status update.
    def refresh(datapoints : Enumerable(Int32)) : Nil
      body = {dpId: datapoints.to_a}.to_json.to_slice
      with_connection do |socket, protocol|
        protocol.send(socket, Protocol::Command::Refresh, body)
      end
    end

    # Waits for a device-initiated status update. Updates received during other
    # commands are coalesced by datapoint and returned on the next call.
    def receive_update : Datapoints
      with_connection do |socket, protocol|
        if @updates.empty?
          deadline = Time.instant + @timeout
          while @updates.empty?
            collect_update(receive(socket, protocol, deadline))
          end
        end
        result = @updates
        @updates = Datapoints.new
        result
      end
    end

    private def status_request : {Protocol::Command, String}
      if query_datapoints = @query_datapoints
        requested = query_datapoints.to_h { |id| {id.to_s, nil} }
        body = {devId: @device_id, uid: "", t: Time.utc.to_unix.to_s, dps: requested}
        {Protocol::Command::ControlNew, body.to_json}
      elsif @version.session?
        {Protocol::Command::QueryNew, "{}"}
      else
        {Protocol::Command::Query, {gwId: @device_id, devId: @device_id}.to_json}
      end
    end

    private def request_status(socket : TCPSocket, protocol : Protocol, command : Protocol::Command, body : String) : Protocol::Reply
      protocol.send(socket, command, body.to_slice)
      if command.control_new?
        # device22 queries can acknowledge the control command before reporting DPS.
        wait_for(socket, protocol, command, status_report: true)
      else
        wait_for(socket, protocol, command)
      end
    end

    private def wait_for(socket : TCPSocket, protocol : Protocol, command : Protocol::Command, *, status_report : Bool = false) : Protocol::Reply
      deadline = Time.instant + @timeout
      loop do
        response = receive(socket, protocol, deadline)
        if response.command == command.value
          return response unless status_report && response.code.zero? && response.payload.empty?
        elsif status_report && response.command == Protocol::Command::Status.value && !response.payload.empty?
          return response
        else
          collect_update(response)
        end
      end
    end

    private def receive(socket : TCPSocket, protocol : Protocol, deadline : Time::Instant) : Protocol::Reply
      remaining = deadline - Time.instant
      raise IO::TimeoutError.new("Timed out waiting for Tuya reply") unless remaining > Time::Span.zero

      socket.read_timeout = remaining
      protocol.receive(socket)
    end

    private def collect_update(response : Protocol::Reply) : Nil
      return unless response.command == Protocol::Command::Status.value

      if datapoints = extract_datapoints(response.payload)
        check_code(response) unless response.code == 1
        @updates.merge!(datapoints)
      end
    end

    private def extract_datapoints(data : Bytes) : Datapoints?
      return if data.empty? || data == "json obj data unvalid".to_slice

      json = JSON.parse(String.new(data).strip('\0')).as_h?
      return unless json

      json["dps"]?.try(&.as_h?) || json["data"]?.try(&.as_h?).try(&.["dps"]?).try(&.as_h?)
    rescue ex : JSON::ParseException
      raise ProtocolError.new("Invalid JSON in Tuya response", cause: ex)
    end

    private def check_code(response : Protocol::Reply) : Nil
      raise DeviceError.new(response.code) unless response.code.zero?
    end

    private def with_connection(&)
      @mutex.synchronize do
        socket, protocol = connection
        yield socket, protocol
      rescue ex : IO::Error | Socket::Error
        disconnect
        raise ConnectionError.new("Tuya connection to #{@host}:#{@port} failed: #{ex.message}", cause: ex)
      rescue ex : ProtocolError
        disconnect
        raise ex
      end
    end

    private def connection : {TCPSocket, Protocol}
      if (socket = @socket) && (protocol = @protocol)
        return {socket, protocol}
      end

      @socket = socket = TCPSocket.new(@host, @port, dns_timeout: @timeout, connect_timeout: @timeout)
      socket.read_timeout = @timeout
      socket.write_timeout = @timeout
      socket.tcp_nodelay = true

      protocol = Protocol.new(@version, @local_key)
      protocol.negotiate(socket) if @version.session?
      @protocol = protocol
      {socket, protocol}
    end

    private def disconnect : Nil
      socket, @socket = @socket, nil
      @protocol = nil
      @updates.clear
      socket.try(&.close)
    end
  end
end
