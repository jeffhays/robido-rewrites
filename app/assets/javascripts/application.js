// This is a manifest file that'll be compiled into application.js, which will include all the files
// listed below.
//
// Any JavaScript/Coffee file within this directory, lib/assets/javascripts, vendor/assets/javascripts,
// or vendor/assets/javascripts of plugins, if any, can be referenced here using a relative path.
//
// It's not advisable to add code directly here, but if you do, it'll appear at the bottom of the
// the compiled file.
//
// WARNING: THE FIRST BLANK LINE MARKS THE END OF WHAT'S TO BE PROCESSED, ANY BLANK LINE SHOULD
// GO AFTER THE REQUIRES BELOW.
//
//= require jquery
//= require jquery_ujs
//= require foundation
//= require dropzone
//= require d3
//= require_tree .

$(function() {
  $(document).foundation();
  visualize();
});

$(window).scroll(function() {
  animateRows();
});

// display d3js visualization
function visualize(file = false) {
  // initialize
  var chart = '#chart';
  var table = '#chart-data';
  var chartColors = ['#058DC7', '#50B432', '#ED561B', '#DDDF00', '#666666', '#24CBE5', '#64E572', '#FF9655', '#FFF263', '#6AF9C4', '#00AA88', '#434348', '#90ed7d', '#f7a35c', '#8085e9', '#f15c80', '#e4d354', '#8085e8', '#8d4653', '#91e8e1'];
  var file = file ? file : $(chart).data('file');
  var hasData = false;

  // draw chart if filename exists
  if (typeof file != 'undefined' && file.length) {
    d3.json('/upload/index.json?file=' + $(chart).data('file'), function(error, data) {
      hasData = hasData ? hasData : !$.isEmptyObject(data);
      if (hasData) {
        // create bubble chart when data is present
        var margins = { top: 55, right: 500, bottom: 55, left: 0 },
            width = window.innerWidth,
            height = window.innerHeight - 40,
            format = d3.format(',d'),
            color = d3.scale.category20c();

        // scale
        var xScale = d3.scale.linear()
            .domain([0, $(chart).data('packet-average')])
            .range([0, $(chart).data('packet-average')])

        // axes
        var xAxis = d3.svg.axis()
            .scale(xScale);

        // tooltip
        var tooltip = d3.select('body')
            .append('div')
            .attr('id', 'd3tip')
            .text('tooltip');

        // svg
        var svg = d3.select(chart).append('svg')
            .on('mousemove', function() {
              // queue tooltip over host bubble based on current mouse x position
              var y = height / 2 - 200;
              // determine if we're on the x range of a host bubble in the front
              var circle = xCircle(d3.event.pageX, data, width, height, margins);
              // set all the totals, averages, etc.
              var avg = parseFloat($('#node-' + circle + ' average').text());
              var totalSize = parseInt($('#node-' + circle + ' totalsize').text());
              var maxAvg = parseInt($('#node-' + circle + ' maxaverage').text());
              var color = $('#node-' + circle + ' circle').css('fill');
              var packets = $('#node-' + circle + ' packets').text();
              var host = $('#node-' + circle + ' host').text();
              // just in case there are multiple ips that resolve to different hosts, this will be a list of data instead
              host = host.indexOf(',') ? host.split(',')[0] : host;
              host = host.length ? host : 'unknown';

              var packetCount = 0;
              // grab the packets when they're available
              if (packets.length) {
                var packets = JSON.parse(packets);
                if (packets.length) {
                  packetCount = packets.length;
                }
              }

              // when we match a circle to the current mouse x position
              if (circle > -1) {
                // loop through bubbles and queue tooltip based on current mouse x position
                d3.select('.node').each(function(d) {
                  // display and style the tooltip
                  tooltip.html('<table><tbody><tr><td style="text-align:right;padding-right:8px;"><div class="circle"></div>Host:</td><td>' + host + '</td></tr><tr><td style="text-align:right;padding-right:8px;"><nobr>Packet Count:</nobr></td><td>' + packetCount + '</td></tr><tr><td style="text-align:right;padding-right:8px;"><nobr>Average Size:</nobr></td><td>' + avg.toFixed(2) + '</td></tr></tbody></table><div class="button expanded" data-circle="' + circle + '">View Packets</div></div><div id="d3line"></div>');
                  $('#d3tip table .circle').css('background', color);
                  tooltip.style({background: 'rgba(0,0,0,.7)', visibility: 'visible'});
                });

                // show table of packet data on tooltip button click
                tooltip.select('.button').on('click', function() {
                  var circle = $(this).data('circle');
                  showTable(table, data, packets);
                });

                // show table of packet data on tooltip line click to "prevent" the line from getting in the way of the click event
                $('#d3line').on('click', function() {
                  var circle = $(this).data('circle');
                  showTable(table, data, packets);
                });
                return tooltip.style('top', y + 'px').style('left', (d3.event.pageX - 110) + 'px');
              }
              return tooltip.style('visibility', 'hidden');
            })
            .attr('width', width)
            .attr('height', height)
            .attr('class', 'bubble');

        // enter svg and create nodes
        var node = svg.selectAll('.node')
            .data(data)
          .enter().append('g')
            .attr('class', 'node')
            .attr('id', function(d) { return 'node-' + d.id; })
            .attr('transform', function(d) {
              // calculate x position based on data and chart dimensions
              var x = xPosition(d, width, margins);
              return 'translate(' + x  + ',' + (height / 2) + ')';
            });

        // create bubble and append it to svg node
        node.append('circle')
            // animate in
            .transition()
              .duration(750)
              .delay(function(d, i) { return i * 100; })
            .attr('r', function(d) {
              // calculate radius
              var margin = margins.top + margins.bottom;
              var circleDiameter = (d.packets.length * ((height - margin) / parseFloat(d.max)));
              var circleRadius = circleDiameter / 2;
              return circleRadius;
            })
            .style('fill', function(d) {
              // fill color
              var color = 'hsl(' + Math.random() * 360 + ',100%,50%)';
              if (chartColors.length) {
                return chartColors.shift();
              }
              return color;
            })
            .each('end', function() {
              // when the transitions have finished
              $('#loading').fadeOut();
            });

        // add data node to easily build a table of packet data for each host bubble on click
        node.append('packets')
            .text(function(d) { return JSON.stringify(d.packets); });

        // add id node to identify bubbles and connect the tooltip functions to each host node
        node.append('id')
            .text(function(d) { return d.id; });

        // add x node to queue tooltip over bubble x position
        node.append('host')
            .text(function(d) { return d.host });

        // add x node to queue tooltip over bubble x position
        node.append('average')
            .text(function(d) { return d.average });

        // add x node to queue tooltip over bubble x position
        node.append('totalsize')
            .text(function(d) { return d.total_packet_size; });

        // add x node to queue tooltip over bubble x position
        node.append('maxaverage')
            .text(function(d) { return d.max_average; });

        // build table data on click
        node.on('click', function(d) {
          showTable(table, d);
        });

        d3.select(self.frameElement).style('height', width + 'px');
      } else if (error) {
        console.log('ERROR: ', error);
      }
    });
  }

  // upload form
  $('#uploadform').dropzone({
    url: '/upload/create',
    headers: {
      'X-CSRFToken': $('meta[name="csrf-token"]').attr("content")
    },
    params: {
        _token: $('meta[name="csrf-token"]').attr("content")
    },
    init: function() {
      this.on('addedfile', function(file) {
        console.log('adding file ' + file);
        // show loading icon while we wait for the ajax response
        $('.fa-cloud-upload').hide();
        $('#uploadform .loader').show();
      }),
      this.on('success', function(file, response) {
        if (response.file) {
          // reload the page and pass their file in the url
          window.location.href = '/?file=' + response.file;
        } else {
          // animate out loading icon and animate in response message
          alert(response.message);
          $('.loader, .dz-preview').hide();
          $('.fa-cloud-upload').fadeIn('slow');
        }
      })
    },
    drop: function() {
      $('.fa-cloud-upload').hide();
      $('#uploadform .loader').fadeIn('slow');
    }
  });
  // trigger upload form click event on icon click event
  $('#uploadform .fa').on('click', function() {
    $(this).parent().trigger('click');
  });
}

// animate the table rows in to add fanciness :)
function animateRows() {
  // only animate the first few rows so it doesn't get annoying on larger data sets
  var animateRows = Math.floor(window.innerHeight / 36) - 1;
  $('#chart-data tbody tr:not(.animated)').each(function() {
    if (document.body.scrollTop + window.innerHeight >= $(this).offset().top) {
      if ($('#chart-data tbody tr').length) {
        if ($(this).index() > animateRows) {
          $(this).addClass('animated');
        } else {
          $(this).addClass('animated zoomInDown');
        }
      }
    }
  });
}

// dynamically create table of packet data
function showTable(table, data, packets = false) {
  var dataset = $(table).data('host');
  if (typeof dataset == 'undefined' || dataset != data.host) {
    if (packets) {
      data.packets = packets;
    }
    // empty our table
    $(table).empty();
    // build our table structure
    $(table).append(
      $('<thead>').append(
        $('<tr>').append(
          $('<td>').text('Capture Length'),
          $('<td>').text('Source IP'),
          $('<td>').text('Desination IP'),
          $('<td>').text('Host')
        )
      ),
      $('<tbody>')
    );
    // build rows for each packet
    $.each(data.packets, function(index, packet) {
      $(table + ' tbody').append(
        $('<tr>').append(
          $('<td>').html(packet[0]),
          $('<td>').html(packet[1]),
          $('<td>').html(packet[2]),
          $('<td>').html(packet[3])
        )
      );
    });
    // set data attribute to avoid repopulating
    $(table).data('host', data.host);
    // scroll to table data
    $('body,html').animate({ scrollTop: $(table).offset().top }, 1300);
    return true;
  }
  return false;
}

// get bubble data by index
function bubbleData(index) {
  $('.node').each(function(index, value) {
    if (parseInt($(this).children('id').text()) == index) {
      return { id: $(this).children('x') };
    }
  });
}

// get x position of host bubble
function xPosition(data, width, margins) {
  var x = (data.average * (width / parseFloat(data.max)));
  var offset = x > width / 2 ? margins.right * -1 : margins.left;
  return x + offset;
}

// trigger tooltip on host bubble by current mouse x value
function xCircle(x, data, width, height, margins) {
  if (data.length) {
    var xIn = [];
    data.forEach(function(host, index, array) {
      // calculate x position and left and right bounds of bubble
      var circleX = xPosition(host, width, margins);
      // calculate new host bubble diameter based on chart size
      var margin = margins.top + margins.bottom;
      var circleDiameter = (host.packets.length * ((height - margin) / parseFloat(host.max)));
      // set left and right comparison values
      var left = circleX - circleDiameter / 2;
      var right = circleX + circleDiameter / 2;
      // create array of bubbles within bounds of the current x position
      if (x < right && x > left) {
        xIn.push({id: host.id, index: index});
      }
      // sort xIn array by index
      xIn.sort(function(a, b) {
        return a.index - b.index;
      });
    });
    return xIn.length ? xIn.pop().id : -1;
  }
  return false;
}