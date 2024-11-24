#!/bin/bash

# File to save filtered LFI endpoints (unique links)
LFI_OUTPUT_FILE="urls.txt"
TEMP_FILE="temp_urls.txt"
> "$LFI_OUTPUT_FILE"  # Clear the file if it already exists
> "$TEMP_FILE"        # Temporary file for normalization

# Function to filter potential LFI endpoints
filter_lfi() {
    local input=$1
    echo "Scanning $input for URLs and filtering for potential LFI endpoints..."
    echo "$input" | waybackurls | gf lfi | sed 's/=.*/=/' >> "$TEMP_FILE"
}

# Prompt the user for input type
echo "Do you want to scan:"
echo "1) A single site"
echo "2) A file containing a list of sites"
read -p "Enter your choice (1 or 2): " choice

if [[ "$choice" == "1" ]]; then
    # Single site option
    read -p "Enter the site URL to scan (e.g., example.com): " SINGLE_SITE
    if [[ -z "$SINGLE_SITE" ]]; then
        echo "Error: No site URL provided!"
        exit 1
    fi
    filter_lfi "$SINGLE_SITE"

elif [[ "$choice" == "2" ]]; then
    # File containing list of sites option
    read -p "Enter the file path containing the list of sites: " SITES_FILE
    if [[ ! -f "$SITES_FILE" ]]; then
        echo "Error: File '$SITES_FILE' not found!"
        exit 1
    fi
    while IFS= read -r site; do
        filter_lfi "$site"
    done < "$SITES_FILE"

else
    echo "Invalid choice! Please enter 1 or 2."
    exit 1
fi

# Normalize URLs for deduplication
echo "Normalizing and removing duplicate URLs..."
cat "$TEMP_FILE" | \
    sed -E 's/:80\/|\/$//' | \
    sort -u > "$LFI_OUTPUT_FILE"

# Clean up temporary file
rm -f "$TEMP_FILE"

echo "Scanning completed."
echo "Filtered and unique LFI endpoints saved to $LFI_OUTPUT_FILE"
