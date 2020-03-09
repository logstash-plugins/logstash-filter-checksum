# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/filters/checksum"
require 'openssl'

describe LogStash::Filters::Checksum do

  LogStash::Filters::Checksum::ALGORITHMS.each do |alg|
    describe "#{alg} checksum with single field" do
      config <<-CONFIG
        filter {
          checksum {
            algorithm => "#{alg}"
            keys => ["test"]
          }
        }
        CONFIG

      sample "test" => "foo bar" do
        insist { !subject.get("logstash_checksum").nil? }
        insist { subject.get("logstash_checksum") } == OpenSSL::Digest.hexdigest(alg, "foo bar")
      end
    end

    describe "#{alg} checksum with multiple keys" do
      config <<-CONFIG
        filter {
          checksum {
            algorithm => "#{alg}"
            keys => ["test1", "test2"]
          }
        }
        CONFIG

      sample "test1" => "foo", "test2" => "bar" do
        insist { !subject.get("logstash_checksum").nil? }
        insist { subject.get("logstash_checksum") } == OpenSSL::Digest.hexdigest(alg, "foobar")
      end
    end
  end
end
