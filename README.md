# Misc Tools - Bulk whoIS lookup

This tool allows you to run whois lookups against a list of domains through one script.

It can either output to a csv or stdout.

Visit https://www.achromatic-security.com/blog-bulk-whois for more information on its use case.


## Requirements

Most of the modules used should already be installed by default. However the one you will need to install is:

*pythonwhois


## Usage

usage: bulk_whois.py [-h] -i INPUT_FILE [-o OUTPUT_FILE]

-i Specify the input file containing a list of domains!(one domain per line)

-o Specify the output file to write to. If one is not specified output will be displayed to stdout

*If the -o is not provided then the results will be written to stdout

Also you will need to ensure that the file containing the domains you wish to perform whois lookups against are formatted as one domain per line such as:

achromatic-security.com
google.com
bbc.co.uk

