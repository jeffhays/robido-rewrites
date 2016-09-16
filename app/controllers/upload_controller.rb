class UploadController < ApplicationController
  @@uploads = Rails.public_path + "/uploads/"
  def create
    file = false
    unless params[:file].nil?
      # initialize
      file = sanitize_filename(params[:file].original_filename)
      @filename = file
      # check if this is a pcap file
      if File.extname(file) == ".pcap"
        # check to see if the uploads directory exist, otherwise create it
        unless File.directory?(@@uploads)
          Dir.mkdir @@uploads
        end
        # upload the file
        path = File.join(@@uploads, file)
        unless File.exists?(path)
          File.open(path, "wb") {|f| f.write(params[:file].read)}
        end
        message = "Uploadeded successful! One moment while we load the PCAP file..."
      else
        file = false
        message = "The file you uploaded was not a PCAP file.\n\nPlease make sure you are uploading a file with the .pcap extension and try again."
      end
    end
    message = message ? message : "There was a problem uploading your file"
    render json: {params: params, file: file, message: message} and return
  end

  def index
    unless params[:file].nil?
      # get packets from file
      @filename = sanitize_filename(params[:file])
      packets = get_packets(@@uploads + @filename)
      packet_data = process_packets(packets)

      # retrieve our packet data
      @host_packets = packet_data[:packets]
      @host_ips = packet_data[:host_ips]
      @host_names = packet_data[:host_names]
      @average_packet_size = packet_data[:average_packet_size]
      @largest_total_packets = packet_data[:largest_total_packets]
      @no_data = @host_packets.nil? && @host_packets.length
    end

    respond_to do |format|
      format.html
      format.json {render json: @host_packets.to_json}
      format.xml {render xml: @host_packets.to_xml}
    end
  end

  private

  def process_packets(packets)
    # initialize
    new_packets = []
    average_packet_size = []
    host_ips = {}
    host_names = {}
    host_packets = {}
    host_averages = {}
    map = {size: 0, src: 1, dest: 2, host: 3}

    # process packets
    unless packets.nil?
      packets.each do |packet|
        # create hashes by host key
        unless packet[map[:host]].nil?
          # aggregate host ips by host
          if host_ips[packet[map[:dest]]].nil?
            host_ips[packet[map[:host]]] = [packet[map[:dest]]]
          else
            host_ips[packet[map[:host]]].push(packet[map[:dest]])
          end

          # aggregate host names by host
          if host_names[packet[map[:dest]]].nil?
            host_names[packet[map[:host]]] = [packet[map[:dest]]]
          else
            host_names[packet[map[:host]]].push(packet[map[:dest]])
          end
        end

        # aggregate packet sizes
        average_packet_size.push(packet[map[:size]].to_i)

        # aggregate packets by source ip
        if host_packets[packet[map[:src]]].nil?
          # packet[map[:src]]
          host_packets[packet[map[:src]]] = [packet]
        else
          host_packets[packet[map[:src]]].push(packet)
        end
      end

      # get average packet size
      average_packet_size = average_packet_size.sum / average_packet_size.length.to_f

      # get largest total packet counts
      largest_total_packets = 0
      host_packets.each do |host,packets|
        largest_total_packets = packets.length > largest_total_packets ? packets.length : largest_total_packets

        # loop through packets for this host to get average packet size by host
        average = []
        packets.each do |packet|
          average.push(packet[map[:size]].to_i)
        end
        average = average.sum / average.length.to_f
        host_averages[host] = average
      end

      # prepare a clean data object of host packets for the view
      index = 0
      new_packets = []
      host_packets.each do |host,packets|
        # loop through packets for this host to get average packet size by host
        average = []
        packets.each do |packet|
          average.push(packet[map[:size]].to_i)
        end

        # calculate data related to this host and setup a hash to deliver a nice data structure to the view
        host = host_ips[host].nil? ? host : host_ips[host]
        total_packet_size = average.sum
        average = average.sum / average.length.to_f

        # aggregate coordinates of outer bounds of bubble by host
        bounds = {min: average - (packets.length / 2), max: average + (packets.length / 2)}

        # push formatted packet hash
        new_packets.push({id: index, host: host, host_ips: host_ips, host_names: host_names, bounds: bounds, total_packet_size: total_packet_size, max: largest_total_packets, average: average, packets: packets})
        index += 1
      end
      host_packets = new_packets.sort_by {|p| p[:packets].length}.reverse
    end

    return {packets: host_packets, largest_total_packets: largest_total_packets, average_packet_size: average_packet_size, host_ips: host_ips, host_names: host_names}
  end

  def get_packets(filename)
    # process file if one is passed
    unless filename.nil?
      # only continue if our sanitized filename exists in the uploads directory
      if File.file?(filename)
        # get the data we need from tshark while preventing tomfoolery
        file = Shellwords.escape(filename)
        packets = `tshark -T fields -eframe.cap_len -eip.src -eip.dst -ehttp.host -r #{filename} -Y "not icmp and (tcp.flags.syn==1 or tcp.flags.ack==1 and tcp.flags.fin==0)"`.split("\n").reject {|e| e.to_s.empty?}
        newpackets = []
        packets.each do |p|
          newpackets.push(p.split("\t"))
        end
        packets = newpackets
      end
    end
    return packets
  end

  def sanitize_filename(filename)
    filename.strip.tap do |name|
      name.sub! /\A.*(\\|\/)/, ''
      name.gsub! /[^\w\.\-]/, '_'
    end
  end
end