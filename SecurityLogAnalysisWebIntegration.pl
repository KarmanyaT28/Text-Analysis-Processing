#!/usr/bin/perl

use Dancer2;
use Dancer2::Plugin::Auth::Tiny;
use File::Temp qw(tempfile);
use Text::CSV;
use Geo::IP2;
use LWP::Simple;
use Net::CIDR::Lite;

# Route for the home page
get '/' => sub {
    template 'index';
};

# Route for file upload
post '/upload' => sub {
    my $user = logged_in_user();
    return template 'login' unless $user;

    my $file = request->upload('logfile');
    my ($fh, $filename) = tempfile();
    $file->copy_to($filename);

    my @analysis_results = analyze_log_file($filename);
    template 'results' => { results => \@analysis_results };
};

# Function to analyze log file
sub analyze_log_file {
    my ($file_path) = @_;
    my @analysis_results;

    # Read CSV file
    my $csv = Text::CSV->new({ sep_char => ',' });
    open(my $fh, '<', $file_path) or die "Could not open file '$file_path' $!";
    my @data;
    while (my $row = $csv->getline($fh)) {
        push @data, join(',', @$row);  # Convert array ref to string
    }
    close $fh;

    # Perform cybersecurity analysis
    # Search for security-related patterns
    foreach my $line (@data) {
        my @matches = search_security_patterns($line);
        if (@matches) {
            push @analysis_results, "Security event detected in log: $line\nMatched patterns: @matches";
        }
    }

    # Detect anomalies in log data
    my @anomalies = detect_anomalies(@data);
    if (@anomalies) {
        push @analysis_results, "Anomalies detected:\n" . join("\n", @anomalies);
    }

    # IP Geolocation
    foreach my $line (@data) {
        my ($timestamp, $level, $message) = split /,/, $line;
        if ($message =~ /(\d+\.\d+\.\d+\.\d+)/) {
            my $ip = $1;
            my $country = ip_geolocation($ip);
            push @analysis_results, "IP $ip originated from: $country";
        }
    }

    # Threat Intelligence Integration
    foreach my $line (@data) {
        if ($line =~ /(\d+\.\d+\.\d+\.\d+)/) {
            my $ip = $1;
            my $threat_data = fetch_threat_intelligence($ip);
            push @analysis_results, "Threat intelligence for IP $ip: $threat_data";
        }
    }

    return @analysis_results;
}

# Function to search for security-related patterns in log messages
sub search_security_patterns {
    my ($text) = @_;
    my @matches;
    
    # Add regex patterns for security-related events
    push @matches, $text =~ /\bSQLi\b|\bXSS\b|\bRCE\b|\bLFI\b|\bRFI\b/i;

    return @matches;
}

# Function to perform IP geolocation
sub ip_geolocation {
    my ($ip) = @_;
    my $gi = Geo::IP2->open("GeoLite2-City.mmdb");
    my $record = $gi->city($ip);
    return $record ? $record->country->iso_code : "Unknown";
}

# Function to fetch threat intelligence data
sub fetch_threat_intelligence {
    my ($ip) = @_;
    my $threat_feed_url = "https://api.abuseipdb.com/api/v1/check?ipAddress=$ip";
    my $response = get($threat_feed_url);
    return $response ? $response : "No threat data available";
}

# Function to detect anomalies in log data
sub detect_anomalies {
    my (@data) = @_;
    my @anomalies;

    # Add anomaly detection logic
    # Example: detect unusually high frequency of failed login attempts
    my %count;
    foreach my $line (@data) {
        my @fields = split /,/, $line;
        if ($fields[2] =~ /failed login/i) {
            $count{$fields[0]}++;
        }
    }
    foreach my $timestamp (keys %count) {
        if ($count{$timestamp} > 5) {  # Threshold for anomaly detection
            push @anomalies, "High frequency of failed logins at $timestamp";
        }
    }

    return @anomalies;
}

# Start the web server
start;
