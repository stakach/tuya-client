require "base64"
require "digest/crc32"
require "digest/md5"
require "json"
require "openssl/cipher"
require "openssl/hmac"
require "socket"

module Tuya
  enum Version
    V31 = 1
    V32 = 2
    V33 = 3
    V34 = 4
    V35 = 5

    def self.parse(value : String) : self
      case value
      when "3.1" then V31
      when "3.2" then V32
      when "3.3" then V33
      when "3.4" then V34
      when "3.5" then V35
      else            raise ArgumentError.new("Unsupported Tuya protocol version: #{value}")
      end
    end

    def to_s : String
      "3." + value.to_s
    end

    def to_s(io : IO) : Nil
      io << to_s
    end

    def session? : Bool
      v34? || v35?
    end
  end

  alias Datapoints = Hash(String, JSON::Any)

  class Error < Exception
  end

  class ConnectionError < Error
  end

  class ProtocolError < Error
  end

  class DeviceError < Error
    getter code : UInt32

    def initialize(@code : UInt32)
      super("Tuya device returned code #{@code}")
    end
  end
end

require "./tuya_client/crypto"
require "./tuya_client/frame"
require "./tuya_client/protocol"
require "./tuya_client/client"
require "./tuya_client/discovery"
