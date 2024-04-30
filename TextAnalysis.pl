#!/usr/bin/perl

use strict;
use warnings;
use Text::CSV;

# Function to search for a specific pattern in text
sub search_text {
    my ($pattern, $text) = @_;
    my @matches = $text =~ /$pattern/g;
    return @matches;
}

# Function to filter data based on a condition
sub filter_data {
    my ($condition, @data) = @_;
    my @filtered_data = grep { $_ =~ /$condition/ } @data;
    return @filtered_data;
}

# Function to generate a report
sub generate_report {
    my ($data_ref) = @_;
    foreach my $line (@$data_ref) {
        print "$line\n";
    }
}

# Main program
sub main {
    my $file_path = "example.csv";

    # Read CSV file
    my $csv = Text::CSV->new({ sep_char => ',' });
    open(my $fh, '<', $file_path) or die "Could not open file '$file_path' $!";
    my @data;
    while (my $row = $csv->getline($fh)) {
        push @data, join(',', @$row);  # Convert array ref to string
    }
    close $fh;

    # Search for a specific pattern
    my $pattern = "error";
    my @matches = search_text($pattern, join("\n", @data));
    print "Matches for pattern '$pattern': @matches\n";

    # Filter data based on a condition
    my $condition = "INFO";
    my @filtered_data = filter_data($condition, @data);

    # Generate report for filtered data
    print "Filtered data report:\n";
    generate_report(\@filtered_data);
}

# Call main function
main();
